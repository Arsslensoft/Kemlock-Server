import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createInviteLinkApi } from '@/api/inviteLink';
import { ApiError } from '@/api/errors';
import { copyText } from '@/lib/clipboard';
import { renderWithIntl } from '@/test/render';
import { detail, ME, memberView, spaceView, member } from './fixtures';
import { InviteLinkAction } from './InviteLinkAction';
import { type SpaceActions, SpaceDetailView } from './SpaceDetailView';

vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn(() => Promise.resolve(true)) }));

const LINK = 'https://vault.test/#/accept-organization/?token=secret';
const IVY = '20000000-0000-4000-8000-000000000009';

function problem(status: number, slug: string): ApiError {
  return new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: 'x', status } as never);
}

beforeEach(() => {
  vi.mocked(copyText).mockReset();
  vi.mocked(copyText).mockResolvedValue(true);
});

describe('InviteLinkAction', () => {
  it('copies the link as a secret and warns who it accepts for', async () => {
    const fetchLink = vi.fn(async () => LINK);
    renderWithIntl(<InviteLinkAction name="Ivy" fetchLink={fetchLink} />);
    // Nothing is fetched until it is asked for.
    expect(fetchLink).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole('button', { name: 'Copy the invitation link of Ivy' }));
    await waitFor(() => expect(copyText).toHaveBeenCalledWith(LINK, { secret: true }));
    expect(await screen.findByRole('status')).toHaveTextContent(/accepts the invitation for this account/);
    // A link the clipboard took is not left on the page.
    expect(screen.queryByText(LINK)).not.toBeInTheDocument();
  });

  it('shows the link to copy by hand when the browser refuses the clipboard', async () => {
    vi.mocked(copyText).mockResolvedValue(false);
    renderWithIntl(<InviteLinkAction name="Ivy" fetchLink={async () => LINK} />);
    await userEvent.click(screen.getByRole('button', { name: /Copy the invitation link/ }));
    expect(await screen.findByText(LINK)).toBeInTheDocument();
    expect(screen.getByText(/accepts the invitation for this account/)).toBeInTheDocument();
  });

  it.each([
    [404, 'not-found', /not a Bitwarden organization/],
    [403, 'forbidden', /Only an owner or admin can copy this link/],
    [409, 'not-invited', /already accepted/],
  ])('says so when the server answers %i', async (status, slug, words) => {
    renderWithIntl(
      <InviteLinkAction
        name="Ivy"
        fetchLink={async () => {
          throw problem(status, slug);
        }}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: /Copy the invitation link/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent(words);
    expect(copyText).not.toHaveBeenCalled();
  });
});

describe('the invitation link on the space page', () => {
  function page(
    role: 'owner' | 'admin' | 'member',
    inviteLink: SpaceActions['inviteLink'],
    organization: boolean | 'unsaid' = true,
  ) {
    const actions = {
      invite: vi.fn(),
      accept: vi.fn(),
      startConfirm: vi.fn(),
      cancelConfirm: vi.fn(),
      confirm: vi.fn(),
      changeRole: vi.fn(),
      revoke: vi.fn(),
      restore: vi.fn(),
      remove: vi.fn(),
      createCollection: vi.fn(),
      renameCollection: vi.fn(),
      deleteCollection: vi.fn(),
      createGroup: vi.fn(),
      setGroupMembers: vi.fn(),
      deleteGroup: vi.fn(),
      grant: vi.fn(),
      revokeGrant: vi.fn(),
      ...(inviteLink ? { inviteLink } : {}),
    } as SpaceActions;
    const base = detail();
    renderWithIntl(
      <SpaceDetailView
        detail={{
          ...base,
          view: spaceView({ me: member(ME, { role }), ...(organization === 'unsaid' ? {} : { bitwardenOrganization: organization }) }),
          members: [
            ...base.members,
            memberView(IVY, 'ivy@example.co', { state: 'invited', name: 'Ivy Chen' }),
          ],
        }}
        loading={false}
        confirming={null}
        busy={false}
        offboarded={null}
        cryptoAvailable
        actions={actions}
        onBack={vi.fn()}
      />,
    );
    return actions;
  }

  it('is offered to an owner and an admin, for the invited member only', async () => {
    for (const role of ['owner', 'admin'] as const) {
      const inviteLink = vi.fn(async () => LINK);
      page(role, inviteLink);
      // Theo accepted and Lee is confirmed: they have no link to hand over.
      expect(screen.getAllByRole('button', { name: /Copy the invitation link/ })).toHaveLength(1);
      await userEvent.click(screen.getByRole('button', { name: 'Copy the invitation link of Ivy Chen' }));
      await waitFor(() => expect(inviteLink).toHaveBeenCalledWith(IVY));
      cleanup();
    }
  });

  it('is not offered to a member, or where the page has no such route', () => {
    page('member', vi.fn(async () => LINK));
    expect(screen.queryByRole('button', { name: /Copy the invitation link/ })).not.toBeInTheDocument();
    cleanup();
    page('owner', undefined);
    expect(screen.queryByRole('button', { name: /Copy the invitation link/ })).not.toBeInTheDocument();
  });

  it('is not offered in a space that is not a Bitwarden organization, or one the server does not say of', () => {
    const inviteLink = vi.fn(async () => LINK);
    page('owner', inviteLink, false);
    expect(screen.queryByRole('button', { name: /Copy the invitation link/ })).not.toBeInTheDocument();
    cleanup();
    page('admin', inviteLink, 'unsaid');
    expect(screen.queryByRole('button', { name: /Copy the invitation link/ })).not.toBeInTheDocument();
    cleanup();
    page('admin', inviteLink, true);
    expect(screen.getByRole('button', { name: 'Copy the invitation link of Ivy Chen' })).toBeInTheDocument();
  });
});

describe('createInviteLinkApi', () => {
  it('asks for the link of one member of one space', async () => {
    const request = vi.fn(async () => ({ link: LINK, expiresAt: 1_800_000_000 }));
    const api = createInviteLinkApi({ request: request as never });
    expect(await api.get('space/1', 'user 2')).toEqual({ link: LINK, expiresAt: 1_800_000_000 });
    expect(request).toHaveBeenCalledWith({
      method: 'GET',
      path: '/kem/v1/spaces/space%2F1/members/user%202/invite-link',
    });
  });
});
