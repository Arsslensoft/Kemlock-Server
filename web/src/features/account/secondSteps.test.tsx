import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { createSecondStepsApi, type TwoStepSetupDto } from '@/api/twoStep';
import { renderWithIntl } from '@/test/render';
import { SecondStepsCard, type SecondStepsProps } from './SecondStepsCard';

const setupOff: TwoStepSetupDto = {
  email: null,
  yubikey: null,
  duo: null,
  emailOffered: true,
  yubikeyOffered: true,
  duoServerKeys: false,
};

function card(over: Partial<SecondStepsProps> = {}) {
  const ok = () => vi.fn(async () => true);
  const props: SecondStepsProps = {
    setup: setupOff,
    securityKeys: [],
    securityKeysAvailable: true,
    hasRecoveryCode: false,
    busy: false,
    actions: {
      addSecurityKey: ok(),
      askProof: ok(),
      removeSecurityKey: ok(),
      emailBegin: ok(),
      emailConfirm: ok(),
      emailOff: ok(),
      yubikeySet: ok(),
      yubikeyOff: ok(),
      duoSet: ok(),
      duoOff: ok(),
      showRecoveryCode: vi.fn(async () => 'ABCDEFGH23456723ABCDEFGH23456723'),
    },
    ...over,
  };
  renderWithIntl(<SecondStepsCard {...props} />);
  return props;
}

describe('the second-steps API', () => {
  it('calls the routes the server serves', async () => {
    type Call = { method: string; path: string; body?: unknown };
    const request = vi.fn(async (_call: Call) => ({ keys: [], enabled: false, code: null }));
    const send = vi.fn(async (_call: Call) => undefined);
    const steps = createSecondStepsApi({ request, send } as never);
    await steps.setup();
    await steps.emailBegin('a@b.co');
    await steps.emailConfirm('a@b.co', '123456');
    await steps.yubikeySet(['ccccccccccccx'], true);
    await steps.duoSet(null);
    await steps.securityKeyRemove(2, '731904');
    await steps.proofRequest();
    await steps.emailOff('731904');
    await steps.recoveryCode();
    expect(request.mock.calls.map(([c]) => `${c.method} ${c.path}`)).toEqual([
      'GET /kem/v1/account/two-step/setup',
      'PUT /kem/v1/account/two-factor/yubikey',
      'PUT /kem/v1/account/two-factor/duo',
      'DELETE /kem/v1/account/two-factor/webauthn/2',
      'GET /kem/v1/account/two-factor/recovery-code',
    ]);
    expect(send.mock.calls.map(([c]) => `${c.method} ${c.path}`)).toEqual([
      'POST /kem/v1/account/two-factor/email',
      'POST /kem/v1/account/two-factor/email/confirm',
      'POST /kem/v1/account/two-factor/proof',
      'DELETE /kem/v1/account/two-factor/email',
    ]);
    expect(request.mock.calls[3]?.[0]).toMatchObject({ body: { proof: '731904' } });
    expect(send.mock.calls[3]?.[0]).toMatchObject({ body: { proof: '731904' } });
    expect(request.mock.calls[2]?.[0]).toMatchObject({ body: {} });
  });
});

describe('SecondStepsCard', () => {
  it('registers a security key under a name and lists it with a way to remove it', async () => {
    const props = card({ securityKeys: [{ id: 3, name: 'Desk key' }] });
    expect(screen.getByText('Desk key')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Remove Desk key' }));
    // Turning a second step off asks for the code that was mailed first.
    expect(props.actions.askProof).toHaveBeenCalled();
    expect(props.actions.removeSecurityKey).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText('The code from the email'), '731904');
    await user.click(screen.getByRole('button', { name: 'Turn it off' }));
    expect(props.actions.removeSecurityKey).toHaveBeenCalledWith(3, '731904');
    await user.click(screen.getByRole('button', { name: 'Add a key' }));
    await user.type(screen.getByLabelText('Name for this key'), 'Spare');
    await user.click(screen.getByRole('button', { name: 'Register the key' }));
    expect(props.actions.addSecurityKey).toHaveBeenCalledWith('Spare');
  });

  it('mails a code to an address, then turns the method on with the code', async () => {
    const props = card();
    const user = userEvent.setup();
    // The Set up buttons are, in order: YubiKey, Duo, email.
    await user.click(screen.getAllByRole('button', { name: 'Set up' })[2] as HTMLElement);
    await user.type(screen.getByLabelText('Address for the codes'), 'sam@example.co');
    await user.click(screen.getByRole('button', { name: 'Send a code' }));
    expect(props.actions.emailBegin).toHaveBeenCalledWith('sam@example.co');
    await user.type(await screen.findByLabelText('The code from the email'), '482913');
    await user.click(screen.getByRole('button', { name: 'Turn on' }));
    expect(props.actions.emailConfirm).toHaveBeenCalledWith('sam@example.co', '482913');
  });

  it('shows where the codes go and turns the method off', async () => {
    const props = card({ setup: { ...setupOff, email: 'sam@example.co' } });
    expect(screen.getByText('Codes go to sam@example.co')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Turn off' }));
    expect(props.actions.emailOff).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText('The code from the email'), '731904');
    await user.click(screen.getByRole('button', { name: 'Turn it off' }));
    expect(props.actions.emailOff).toHaveBeenCalledWith('731904');
  });

  it('says so when the server can not mail or check a YubiKey', () => {
    card({ setup: { ...setupOff, emailOffered: false, yubikeyOffered: false } });
    expect(screen.getByText(/can not send mail/)).toBeInTheDocument();
    expect(screen.getByText(/no Yubico API key/)).toBeInTheDocument();
  });

  it('sends the OTPs of the keys touched, and which keys are read over NFC', async () => {
    const props = card();
    const user = userEvent.setup();
    await user.click(screen.getAllByRole('button', { name: 'Set up' })[0] as HTMLElement);
    await user.type(screen.getByLabelText('Key 1'), 'ccccccccccccdefghijklmnopqrstuvwxyzabcdefghi');
    await user.click(screen.getByLabelText('These keys are read over NFC'));
    await user.click(screen.getByRole('button', { name: 'Save the keys' }));
    expect(props.actions.yubikeySet).toHaveBeenCalledWith(
      ['ccccccccccccdefghijklmnopqrstuvwxyzabcdefghi', '', '', '', ''],
      true,
    );
  });

  it('sets Duo up with the server keys when none are typed, else with the account keys', async () => {
    const props = card({ setup: { ...setupOff, duoServerKeys: true } });
    const user = userEvent.setup();
    await user.click(screen.getAllByRole('button', { name: 'Set up' })[1] as HTMLElement);
    await user.click(screen.getByRole('button', { name: /Use the server/ }));
    expect(props.actions.duoSet).toHaveBeenCalledWith(null);
  });

  it('sends the account’s own Duo keys', async () => {
    const props = card();
    const user = userEvent.setup();
    await user.click(screen.getAllByRole('button', { name: 'Set up' })[1] as HTMLElement);
    await user.type(screen.getByLabelText('API hostname'), 'api-1.duosecurity.com');
    await user.type(screen.getByLabelText('Client id (integration key)'), 'DIXX');
    await user.type(screen.getByLabelText('Client secret'), 'sekret');
    await user.click(screen.getByRole('button', { name: 'Save and turn on' }));
    expect(props.actions.duoSet).toHaveBeenCalledWith({
      host: 'api-1.duosecurity.com',
      clientId: 'DIXX',
      clientSecret: 'sekret',
    });
  });

  it('shows the recovery code only on request, in groups of four, and hides it again', async () => {
    const props = card({ hasRecoveryCode: true });
    expect(screen.queryByTestId('recovery-code')).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Show the code' }));
    expect(props.actions.showRecoveryCode).toHaveBeenCalled();
    expect(await screen.findByText('ABCD EFGH 2345 6723 ABCD EFGH 2345 6723')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Hide the code' }));
    expect(screen.queryByTestId('recovery-code')).not.toBeInTheDocument();
  });
});
