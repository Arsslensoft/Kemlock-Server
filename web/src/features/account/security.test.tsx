import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { EmergencyApi, EmergencyGrantDto, GrantViewDto } from '@/api/emergency';
import { createTwoStepApi, enabledMethods } from '@/api/twoStep';
import { decodeB64, encodeB64, fromUtf8 } from '@/lib/b64url';
import { renderWithIntl } from '@/test/render';
import { makeBundleB64 } from '@/test/bundles';
import { fakeSharingCrypto } from '@/test/fake-space-crypto';
import type { EmergencyCardProps } from './EmergencyCard';
import { confirmEmergencyContact, daysLeft, groupSecret } from './emergencyModel';
import { SecurityView, type SecurityViewProps } from './SecurityView';

const GRANTOR = '70000000-0000-4000-8000-000000000001';
const CONTACT = '70000000-0000-4000-8000-000000000002';

function grant(over: Partial<EmergencyGrantDto> = {}): EmergencyGrantDto {
  return {
    id: 'g1',
    grantorId: GRANTOR,
    granteeEmail: 'jordan@example.co',
    granteeId: CONTACT,
    kind: 'takeover',
    waitDays: 7,
    state: 'accepted',
    recoveryInitiatedAt: null,
    dueAt: null,
    createdAt: '2026-11-01T00:00:00Z',
    updatedAt: '2026-11-01T00:00:00Z',
    ...over,
  };
}

function viewOf(over: Partial<EmergencyGrantDto> = {}, keys = true): GrantViewDto {
  return {
    grant: grant(over),
    grantorEmail: null,
    contactKeys: keys
      ? { publicBundle: makeBundleB64(CONTACT), bundleSignature: encodeB64(new Uint8Array(3)), keyVersion: 1 }
      : null,
  };
}

function emergencyProps(over: Partial<EmergencyCardProps> = {}): EmergencyCardProps {
  return {
    trustedContacts: [],
    grantors: [],
    confirming: null,
    released: null,
    cryptoAvailable: true,
    busy: false,
    now: new Date('2026-11-22T00:00:00Z'),
    actions: {
      invite: vi.fn(),
      revoke: vi.fn(),
      startConfirm: vi.fn(),
      cancelConfirm: vi.fn(),
      confirm: vi.fn(),
      approve: vi.fn(),
      reject: vi.fn(),
      accept: vi.fn(),
      initiate: vi.fn(),
      getKey: vi.fn(),
    },
    ...over,
  };
}

function security(over: Partial<SecurityViewProps> = {}, emergency: Partial<EmergencyCardProps> = {}) {
  const props: SecurityViewProps = {
    email: 'sam@example.co',
    host: 'vault.example.org',
    methods: [],
    totp: { open: false, enrol: undefined },
    busy: false,
    onStartTotp: vi.fn(),
    onCancelTotp: vi.fn(),
    onConfirmTotp: vi.fn(),
    emergency: emergencyProps(emergency),
    ...over,
  };
  renderWithIntl(<SecurityView {...props} />);
  return props;
}

describe('emergency helpers', () => {
  it('group a secret in fours', () => {
    expect(groupSecret('KQ7M4XZPABCD')).toBe('KQ7M 4XZP ABCD');
  });

  it('count the days of the wait that are left', () => {
    const now = new Date('2026-11-22T00:00:00Z');
    expect(daysLeft('2026-11-25T00:00:00Z', now)).toBe(3);
    expect(daysLeft('2026-11-20T00:00:00Z', now)).toBe(0);
    expect(daysLeft(null, now)).toBeNull();
  });

  it('seal the root key to the contact’s kx1 key only after a consistent fingerprint', async () => {
    const crypto = fakeSharingCrypto();
    const api: Pick<EmergencyApi, 'confirm'> = { confirm: vi.fn(async () => grant({ state: 'confirmed' })) };
    const fp = { text: 'x', bytes: new Uint8Array(64), consistent: true };
    await confirmEmergencyContact({ api, crypto }, viewOf(), fp);
    expect(crypto.calls).toEqual(['sealRootKey:emergency-access']);
    const sealed = vi.mocked(api.confirm).mock.calls[0]?.[1] ?? '';
    expect(fromUtf8(decodeB64(sealed))).toBe('root>emergency-access>1600>16');
    await expect(confirmEmergencyContact({ api, crypto }, viewOf(), { ...fp, consistent: false })).rejects.toThrow();
    await expect(confirmEmergencyContact({ api, crypto }, viewOf({}, false), fp)).rejects.toThrow();
    expect(api.confirm).toHaveBeenCalledTimes(1);
  });
});

describe('the account’s two-step methods', () => {
  it('are read from the server, so they are right after any sign-in', async () => {
    const request = vi.fn(async () => ({
      methods: [
        { method: 'email', enabled: true },
        { method: 'totp', enabled: true },
        { method: 'yubikey', enabled: false },
      ],
      recoveryCodes: true,
    }));
    const list = await createTwoStepApi({ request } as never).list();
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/account/two-step' });
    expect(enabledMethods(list)).toEqual(['email', 'totp']);
  });

  it('leave the authenticator off when it was set up and switched off', () => {
    const methods = enabledMethods({ methods: [{ method: 'totp', enabled: false }], recoveryCodes: false });
    security({ methods });
    expect(screen.getByText('Off')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Set up' })).toBeInTheDocument();
  });
});

describe('SecurityView', () => {
  it('names the account and lists the two-step methods', () => {
    security();
    expect(screen.getByRole('heading', { name: 'Account security', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/sam@example.co/)).toBeInTheDocument();
    expect(screen.getByText('Authenticator app')).toBeInTheDocument();
    expect(screen.getByText('Off')).toBeInTheDocument();
    expect(screen.getByText('YubiKey OTP')).toBeInTheDocument();
  });

  it('shows the authenticator as on, without a way to set it up again', () => {
    security({ methods: ['totp'] });
    expect(screen.getByText('On')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set up' })).not.toBeInTheDocument();
  });

  it('starts enrolment, shows the key to type and confirms a code', async () => {
    const props = security({ totp: { open: true, enrol: { secret: 'KQ7M4XZPABCD', uri: 'otpauth://totp/Kemlock:sam?secret=KQ7M4XZPABCD' } } });
    expect(screen.getByRole('img', { name: 'QR code for sam@example.co on vault.example.org' })).toBeInTheDocument();
    expect(screen.getByText('KQ7M 4XZP ABCD')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123456');
    await user.click(screen.getByRole('button', { name: 'Turn on two-step login' }));
    await vi.waitFor(() => expect(props.onConfirmTotp).toHaveBeenCalledWith('123456'));
  });

  it('asks for a proof before an app is added beside another second step', async () => {
    const enrol = { secret: 'KQ7M4XZPABCD', uri: 'otpauth://totp/Kemlock:sam?secret=KQ7M4XZPABCD' };
    const props = security({ methods: ['email'], totp: { open: true, enrol } });
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('The code from the email'), 'ABCD EFGH');
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123456');
    await user.click(screen.getByRole('button', { name: 'Turn on two-step login' }));
    await vi.waitFor(() => expect(props.onConfirmTotp).toHaveBeenCalledWith('123456', 'ABCD EFGH'));
  });

  it('asks for no proof when no other second step is on', () => {
    security({ methods: [], totp: { open: true, enrol: { secret: 'KQ7M4XZPABCD', uri: 'otpauth://totp/x' } } });
    expect(screen.queryByLabelText('The code from the email')).not.toBeInTheDocument();
  });

  it('opens enrolment from the Set up button', async () => {
    const props = security();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Set up' }));
    expect(props.onStartTotp).toHaveBeenCalled();
  });

  it('says plainly what is not built yet', () => {
    security();
    expect(screen.getByText('API key')).toBeInTheDocument();
    expect(screen.queryByText('Recovery Kit')).not.toBeInTheDocument();
    expect(screen.getByText('Delete account')).toBeInTheDocument();
  });
});

describe('EmergencyCard', () => {
  it('lists contacts with their state and invites a new one', async () => {
    const props = security({}, { trustedContacts: [viewOf({ state: 'confirmed' })] });
    expect(screen.getByText('jordan@example.co')).toBeInTheDocument();
    expect(screen.getByText('Confirmed')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a contact' }));
    await user.type(screen.getByLabelText('Their email'), 'priya@example.co');
    await user.selectOptions(screen.getByLabelText('What they can do'), 'view');
    await user.clear(screen.getByLabelText('Days to wait, 1 to 90'));
    await user.type(screen.getByLabelText('Days to wait, 1 to 90'), '14');
    await user.click(screen.getByRole('button', { name: 'Send the invitation' }));
    expect(props.emergency.actions.invite).toHaveBeenCalledWith({
      email: 'priya@example.co',
      kind: 'view',
      waitDays: 14,
    });
  });

  it('starts the confirmation of an accepted contact', async () => {
    const view = viewOf();
    const props = security({}, { trustedContacts: [view] });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Confirm jordan@example.co' }));
    expect(props.emergency.actions.startConfirm).toHaveBeenCalledWith(view);
  });

  it('shows the contact’s fingerprint and confirms only on "It matches"', async () => {
    const props = security(
      {},
      {
        trustedContacts: [viewOf()],
        confirming: {
          view: viewOf(),
          fingerprint: { text: '11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 11111 22222', bytes: new Uint8Array(64), consistent: true },
        },
      },
    );
    expect(screen.getByLabelText("Fingerprint of jordan@example.co's keys")).toHaveTextContent('11111 22222');
    await userEvent.setup().click(screen.getByRole('button', { name: 'It matches' }));
    expect(props.emergency.actions.confirm).toHaveBeenCalled();
  });

  it('lets the owner refuse or approve a running request, with the days left', async () => {
    const props = security(
      {},
      { trustedContacts: [viewOf({ state: 'recovery-initiated', dueAt: '2026-11-25T00:00:00Z' })] },
    );
    expect(screen.getByText(/3 days left/)).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Refuse the request of jordan@example.co' }));
    expect(props.emergency.actions.reject).toHaveBeenCalledWith('g1');
    await user.click(screen.getByRole('button', { name: 'Approve the request of jordan@example.co' }));
    expect(props.emergency.actions.approve).toHaveBeenCalledWith('g1');
  });

  it('removes a contact', async () => {
    const props = security({}, { trustedContacts: [viewOf()] });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Remove jordan@example.co' }));
    expect(props.emergency.actions.revoke).toHaveBeenCalledWith('g1');
  });

  it('shows the contact’s side: accept, ask, and get the key', async () => {
    const accept = { ...viewOf({ state: 'invited' }), grantorEmail: 'sam@example.co' };
    const ask = { ...viewOf({ id: 'g2', state: 'confirmed' }), grantorEmail: 'ana@example.co' };
    const done = { ...viewOf({ id: 'g3', state: 'approved' }), grantorEmail: 'lee@example.co' };
    const props = security({}, { grantors: [accept, ask, done] });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Accept the invitation of sam@example.co' }));
    expect(props.emergency.actions.accept).toHaveBeenCalledWith('g1');
    await user.click(screen.getByRole('button', { name: 'Ask ana@example.co for access' }));
    expect(props.emergency.actions.initiate).toHaveBeenCalledWith('g2');
    await user.click(screen.getByRole('button', { name: 'Get the key of lee@example.co' }));
    expect(props.emergency.actions.getKey).toHaveBeenCalledWith('g3');
  });

  it('says a released key needs the key worker', () => {
    security({}, { released: { grantor: 'lee@example.co', kind: 'view' } });
    expect(screen.getByText("lee@example.co's key was released")).toBeInTheDocument();
  });
});
