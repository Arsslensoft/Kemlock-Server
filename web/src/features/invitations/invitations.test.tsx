import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';

const accept = vi.hoisted(() => ({ organization: vi.fn(), emergency: vi.fn() }));

vi.mock('@/api/bwInvitations', () => ({
  bwInvitations: { acceptOrganization: accept.organization, acceptEmergency: accept.emergency },
}));
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

beforeEach(() => {
  accept.organization.mockReset();
  accept.emergency.mockReset();
  window.history.replaceState(null, '', '/');
});

describe('the link of an invitation to an organization', () => {
  const link = {
    organizationId: 'org-1',
    organizationUserId: 'user-1',
    organizationName: 'Acme Corp',
    email: 'bob@example.org',
    token: token({ invited_by_email: 'alice@acme.example', email: 'bob@example.org' }),
  };

  it('shows the organization and the inviter and accepts nothing until the button is pressed', async () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByText('alice@acme.example')).toBeInTheDocument();
    expect(screen.getByText('bob@example.org')).toBeInTheDocument();
    // A page that has only opened (a mail scanner running the script) has accepted nothing.
    await Promise.resolve();
    expect(accept.organization).not.toHaveBeenCalled();
  });

  it('accepts once on the button and says an administrator confirms next', async () => {
    accept.organization.mockResolvedValue({ ok: true });
    open(<AcceptOrganization />, '/accept-organization', link);
    const button = screen.getByRole('button', { name: 'Accept the invitation' });
    await userEvent.click(button);
    expect(await screen.findByText(/An administrator now confirms you/)).toBeInTheDocument();
    expect(accept.organization).toHaveBeenCalledOnce();
    expect(accept.organization).toHaveBeenCalledWith('org-1', 'user-1', link.token);
  });

  it('takes the token out of the address as the page opens', () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('');
    expect(window.location.href).not.toContain(link.token);
  });

  it('says why when the server refuses', async () => {
    accept.organization.mockResolvedValue({ ok: false, message: 'User already accepted the invitation' });
    open(<AcceptOrganization />, '/accept-organization', link);
    await userEvent.click(screen.getByRole('button', { name: 'Accept the invitation' }));
    expect(await screen.findByText(/couldn't be accepted/)).toBeInTheDocument();
    expect(screen.getByText('User already accepted the invitation')).toBeInTheDocument();
  });

  it('asks for nothing when the link has no token', () => {
    open(<AcceptOrganization />, '/accept-organization', { organizationId: 'org-1' });
    expect(screen.getByText(/link is incomplete/)).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
    expect(accept.organization).not.toHaveBeenCalled();
  });

  it('does not read a token from the query string', () => {
    window.history.replaceState(null, '', '/accept-organization?organizationId=o&organizationUserId=u&token=a.b.c');
    render(
      <I18nProvider>
        <AcceptOrganization />
      </I18nProvider>,
    );
    expect(screen.getByText(/link is incomplete/)).toBeInTheDocument();
  });
});

describe('the link of an emergency-contact invitation', () => {
  it('shows who named the person and accepts on the button alone', async () => {
    accept.emergency.mockResolvedValue({ ok: true });
    const tok = token({ grantor_name: 'Alice', grantor_email: 'alice@example.org' });
    open(<AcceptEmergency />, '/accept-emergency', { id: 'grant-1', token: tok });
    expect(screen.getByText('Alice (alice@example.org)')).toBeInTheDocument();
    expect(accept.emergency).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Accept and become their emergency contact' }));
    expect(await screen.findByText(/The person who named you now confirms you/)).toBeInTheDocument();
    expect(accept.emergency).toHaveBeenCalledOnce();
    expect(accept.emergency).toHaveBeenCalledWith('grant-1', tok);
    expect(window.location.hash).toBe('');
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
