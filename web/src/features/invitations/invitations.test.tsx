import { render, screen } from '@testing-library/react';
import { StrictMode, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';

vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  Link: ({
    children,
    to,
    search,
    className,
  }: {
    children: ReactNode;
    to: string;
    search?: Record<string, string>;
    className?: string;
  }) => (
    <a href={`${to}${search ? `?${new URLSearchParams(search).toString()}` : ''}`} className={className}>
      {children}
    </a>
  ),
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

const fetched = vi.fn();

beforeEach(() => {
  fetched.mockReset();
  vi.stubGlobal('fetch', fetched);
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

  it('shows the organization and the inviter, and says the person accepts it themselves once signed in', () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByText('alice@acme.example')).toBeInTheDocument();
    expect(screen.getByText('bob@example.org')).toBeInTheDocument();
    expect(screen.getByText(/Nothing is accepted from this page/)).toBeInTheDocument();
    expect(screen.getByText(/appears under Spaces as an invitation/)).toBeInTheDocument();
  });

  it('leads to the sign-in, which goes on to Spaces, and has no button that accepts', () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/sign-in?next=%2Fspaces');
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('posts nothing, and takes the token out of the address', () => {
    open(<AcceptOrganization />, '/accept-organization', link);
    expect(fetched).not.toHaveBeenCalled();
    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('');
    expect(window.location.href).not.toContain(link.token);
  });

  it('offers no sign-in when the link has no token', () => {
    open(<AcceptOrganization />, '/accept-organization', { organizationId: 'org-1' });
    expect(screen.getByText(/link is incomplete/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Sign in' })).toBeNull();
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
  it('shows who named the person and leads to the sign-in, which goes on to the Security page', () => {
    const tok = token({ grantor_name: 'Alice', grantor_email: 'alice@example.org' });
    open(<AcceptEmergency />, '/accept-emergency', { id: 'grant-1', token: tok });
    expect(screen.getByText('Alice (alice@example.org)')).toBeInTheDocument();
    expect(screen.getByText(/appears under Emergency access/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/sign-in?next=%2Fsecurity');
    expect(fetched).not.toHaveBeenCalled();
    expect(window.location.hash).toBe('');
  });

  it('is incomplete without an id or a token', () => {
    open(<AcceptEmergency />, '/accept-emergency', { id: 'grant-1' });
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
