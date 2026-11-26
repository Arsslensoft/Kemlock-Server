import { render, screen } from '@testing-library/react';
import { StrictMode, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';

const search = vi.hoisted(() => ({ value: {} as Record<string, string | undefined> }));
const accept = vi.hoisted(() => ({ organization: vi.fn(), emergency: vi.fn() }));

vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  getRouteApi: () => ({ useSearch: () => search.value }),
}));
vi.mock('@/api/bwInvitations', () => ({
  bwInvitations: { acceptOrganization: accept.organization, acceptEmergency: accept.emergency },
}));
vi.mock('@/ui/AuthPage', () => ({ AuthPage: ({ children }: { children: ReactNode }) => <main>{children}</main> }));

import AcceptEmergency from './AcceptEmergency';
import AcceptOrganization from './AcceptOrganization';
import FinishSignup from './FinishSignup';

function open(page: ReactNode) {
  render(
    <StrictMode>
      <I18nProvider>{page}</I18nProvider>
    </StrictMode>,
  );
}

beforeEach(() => {
  accept.organization.mockReset();
  accept.emergency.mockReset();
  search.value = {};
});

describe('the link of an invitation to an organization', () => {
  it('accepts once on the token alone and says an administrator confirms next', async () => {
    search.value = { organizationId: 'org-1', organizationUserId: 'user-1', token: 'tok.en' };
    accept.organization.mockResolvedValue({ ok: true });
    open(<AcceptOrganization />);
    expect(await screen.findByText(/An administrator now confirms you/)).toBeInTheDocument();
    // StrictMode ran the effect twice; the server saw one try.
    expect(accept.organization).toHaveBeenCalledOnce();
    expect(accept.organization).toHaveBeenCalledWith('org-1', 'user-1', 'tok.en');
  });

  it('says why when the server refuses, and when the link is incomplete', async () => {
    search.value = { organizationId: 'org-1', organizationUserId: 'user-1', token: 'old' };
    accept.organization.mockResolvedValue({ ok: false, message: 'User already accepted the invitation' });
    open(<AcceptOrganization />);
    expect(await screen.findByText(/couldn't be accepted/)).toBeInTheDocument();
    expect(screen.getByText('User already accepted the invitation')).toBeInTheDocument();
  });

  it('asks for nothing when the link has no token', () => {
    search.value = { organizationId: 'org-1' };
    open(<AcceptOrganization />);
    expect(screen.getByText(/link is incomplete/)).toBeInTheDocument();
    expect(accept.organization).not.toHaveBeenCalled();
  });
});

describe('the link of an emergency-contact invitation', () => {
  it('accepts on the token alone', async () => {
    search.value = { id: 'grant-1', token: 'tok.en' };
    accept.emergency.mockResolvedValue({ ok: true });
    open(<AcceptEmergency />);
    expect(await screen.findByText(/The person who named you now confirms you/)).toBeInTheDocument();
    expect(accept.emergency).toHaveBeenCalledWith('grant-1', 'tok.en');
  });
});

describe('the link that proves a new address', () => {
  it('says the address is verified and offers the code', () => {
    search.value = { email: 'new@example.org', token: 'tok.en' };
    open(<FinishSignup />);
    expect(screen.getByText(/new@example.org is verified/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the verification code' })).toBeInTheDocument();
  });
});
