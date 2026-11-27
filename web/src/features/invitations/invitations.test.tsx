import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';

const api = vi.hoisted(() => ({ prelogin: vi.fn(), organization: vi.fn(), emergency: vi.fn() }));
const hash = vi.hoisted(() => vi.fn());

vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  Link: ({ children, to, className }: { children: ReactNode; to: string; className?: string }) => (
    <a href={to} className={className}>
      {children}
    </a>
  ),
}));
vi.mock('@/api/bwInvitations', () => ({
  bwInvitations: { prelogin: api.prelogin, acceptOrganization: api.organization, acceptEmergency: api.emergency },
}));
vi.mock('@/crypto-port', () => ({ vaultCrypto: { bitwardenPasswordHash: hash } }));
vi.mock('@/ui/AuthPage', () => ({ AuthPage: ({ children }: { children: ReactNode }) => <main>{children}</main> }));

import AcceptEmergency from './AcceptEmergency';
import AcceptOrganization from './AcceptOrganization';
import FinishSignup from './FinishSignup';
import { readLinkParams, tokenClaims } from './linkParams';

/** A token shaped like the server's (header.payload.signature); the page never checks the signature. */
function token(claims: Record<string, unknown>): string {
  const payload = btoa(JSON.stringify(claims)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `eyJhbGciOiJSUzI1NiJ9.${payload}.c2ln`;
}

/** Opens the page the way a mailed link does: the values are in the fragment of the address. */
function open(page: ReactNode, path: string, values: Record<string, string>) {
  window.history.replaceState(null, '', `${path}#${new URLSearchParams(values).toString()}`);
  render(
    <StrictMode>
      <I18nProvider>{page}</I18nProvider>
    </StrictMode>,
  );
}

const KDF = { type: 0 as const, iterations: 600000 };

beforeEach(() => {
  for (const fn of [api.prelogin, api.organization, api.emergency, hash]) fn.mockReset();
  api.prelogin.mockResolvedValue(KDF);
  hash.mockResolvedValue('aGFzaA==');
  window.history.replaceState(null, '', '/');
});

const field = () => screen.getByLabelText('Your master password');

describe('the link of an invitation to an organization', () => {
  const link = {
    organizationId: 'org-1',
    organizationUserId: 'user-1',
    organizationName: 'Acme Corp',
    email: 'Bob@Example.org',
    token: token({ invited_by_email: 'alice@acme.example' }),
  };

  it('shows the organization and the inviter and asks for the master password, sending nothing yet', () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByText('alice@acme.example')).toBeInTheDocument();
    expect(field()).toHaveValue('');
    expect(api.prelogin).not.toHaveBeenCalled();
    expect(api.organization).not.toHaveBeenCalled();
    expect(hash).not.toHaveBeenCalled();
  });

  it('on the press asks the KDF of the invited address, makes the hash in the worker and sends the hash, not the password', async () => {
    api.organization.mockResolvedValue({ ok: true });
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'correct horse');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/Invitation accepted/)).toBeInTheDocument();
    expect(api.prelogin).toHaveBeenCalledWith('Bob@Example.org');
    expect(hash).toHaveBeenCalledWith({ password: 'correct horse', email: 'Bob@Example.org', kdf: KDF });
    expect(api.organization).toHaveBeenCalledOnce();
    expect(api.organization).toHaveBeenCalledWith('org-1', 'user-1', link.token, 'aGFzaA==');
    expect(JSON.stringify(api.organization.mock.calls)).not.toContain('correct horse');
  });

  it('ends with a link to sign in, not a signed-in page, and no form left', async () => {
    api.organization.mockResolvedValue({ ok: true });
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/sign-in');
    expect(screen.getByText(/You are not signed in here/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Your master password')).toBeNull();
  });

  it('empties the field as it sends, and keeps the password nowhere on the page', async () => {
    let finish: (value: { ok: true }) => void = () => undefined;
    api.organization.mockReturnValue(new Promise((resolve) => (finish = resolve)));
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'secret-pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(field()).toHaveValue('');
    expect(document.body.innerHTML).not.toContain('secret-pw');
    finish({ ok: true });
    await screen.findByText(/Invitation accepted/);
    expect(document.body.innerHTML).not.toContain('secret-pw');
  });

  it('says a wrong password is not right, and leaves the form for another press without trying again by itself', async () => {
    api.organization.mockResolvedValueOnce({ ok: false, reason: 'password', message: 'Invalid password' });
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/That master password is not right/)).toBeInTheDocument();
    expect(api.organization).toHaveBeenCalledOnce();
    api.organization.mockResolvedValueOnce({ ok: true });
    await user.type(field(), 'right');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/Invitation accepted/)).toBeInTheDocument();
    expect(api.organization).toHaveBeenCalledTimes(2);
  });

  it('shows the wait when the server limits the tries', async () => {
    api.organization.mockResolvedValue({ ok: false, reason: 'limited', message: '', retryAfter: 90 });
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/Wait 90 seconds before you try again/)).toBeInTheDocument();
  });

  it('says so when the key settings can not be read or the hash can not be made, and sends nothing', async () => {
    api.prelogin.mockResolvedValueOnce(undefined);
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/could not work out your master password's check/)).toBeInTheDocument();
    hash.mockRejectedValueOnce(new Error('invalid'));
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    await vi.waitFor(() => expect(hash).toHaveBeenCalledOnce());
    expect(api.organization).not.toHaveBeenCalled();
  });

  it('says why when the server refuses for another reason', async () => {
    api.organization.mockResolvedValue({ ok: false, reason: 'other', message: 'User already accepted the invitation' });
    open(<AcceptOrganization />, '/accept-organization', link);
    const user = userEvent.setup();
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/couldn't be accepted/)).toBeInTheDocument();
    expect(screen.getByText('User already accepted the invitation')).toBeInTheDocument();
  });

  it('asks for nothing when the link has no token or no address', () => {
    open(<AcceptOrganization />, '/accept-organization', { organizationId: 'org-1', organizationUserId: 'u', email: 'a@b.c' });
    expect(screen.getByText(/link is incomplete/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Your master password')).toBeNull();
  });

  it('takes the token out of the address as the page opens, and reads none from the query string', () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(window.location.hash).toBe('');
    expect(window.location.href).not.toContain(link.token);
  });

  it('uses the address in the token when the link carries none', async () => {
    api.organization.mockResolvedValue({ ok: true });
    open(<AcceptOrganization />, '/accept-organization', {
      organizationId: 'org-1',
      organizationUserId: 'user-1',
      token: token({ email: 'claimed@example.org' }),
    });
    const user = userEvent.setup();
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    await screen.findByText(/Invitation accepted/);
    expect(api.prelogin).toHaveBeenCalledWith('claimed@example.org');
  });
});

describe('the link of an emergency-contact invitation', () => {
  it('shows who named the person and accepts with the hash on the press', async () => {
    api.emergency.mockResolvedValue({ ok: true });
    const tok = token({ grantor_name: 'Alice', grantor_email: 'alice@example.org' });
    open(<AcceptEmergency />, '/accept-emergency', { id: 'grant-1', email: 'jo@example.org', token: tok });
    expect(screen.getByText('Alice (alice@example.org)')).toBeInTheDocument();
    expect(api.emergency).not.toHaveBeenCalled();
    const user = userEvent.setup();
    await user.type(field(), 'pw');
    await user.click(screen.getByRole('button', { name: 'Accept and become their emergency contact' }));
    expect(await screen.findByText(/The person who named you now confirms you/)).toBeInTheDocument();
    expect(api.emergency).toHaveBeenCalledWith('grant-1', tok, 'aGFzaA==');
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/sign-in');
  });

  it('is incomplete without an id, a token or an address', () => {
    open(<AcceptEmergency />, '/accept-emergency', { id: 'grant-1', token: 't.k.n' });
    expect(screen.getByText(/link is incomplete/)).toBeInTheDocument();
  });
});

describe('the link that proves a new address', () => {
  it('says the address is verified and offers the code', () => {
    open(<FinishSignup />, '/finish-signup', { email: 'new@example.org', token: 'tok.en' });
    expect(screen.getByText(/new@example.org is verified/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the verification code' })).toBeInTheDocument();
    expect(window.location.hash).toBe('');
  });
});

describe('reading a link', () => {
  it('takes the values from a fragment and ignores any other key', () => {
    expect(readLinkParams('#id=g&token=t&evil=1')).toEqual({ id: 'g', token: 't' });
    expect(readLinkParams('')).toEqual({});
  });

  it('reads the claims of a token, and nothing from one that is not a token', () => {
    expect(tokenClaims(token({ invited_by_email: 'a@b.c' }))).toEqual({ invited_by_email: 'a@b.c' });
    expect(tokenClaims('nonsense')).toEqual({});
    expect(tokenClaims('a.%%%.c')).toEqual({});
    expect(tokenClaims(undefined)).toEqual({});
  });
});
