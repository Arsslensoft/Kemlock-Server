import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { detail, THEO } from './fixtures';
import { type SpaceActions, type SpaceDetailViewProps, SpaceDetailView } from './SpaceDetailView';
import { SpaceListView } from './SpaceListView';

function actions(): SpaceActions {
  return {
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
  };
}

function view(over: Partial<SpaceDetailViewProps> = {}) {
  const props: SpaceDetailViewProps = {
    detail: detail(),
    loading: false,
    confirming: null,
    busy: false,
    offboarded: null,
    cryptoAvailable: true,
    actions: actions(),
    onBack: vi.fn(),
    ...over,
  };
  renderWithIntl(<SpaceDetailView {...props} />);
  return props;
}

describe('SpaceListView', () => {
  it('lists spaces, naming a closed one plainly, and opens one', async () => {
    const onOpen = vi.fn();
    renderWithIntl(
      <SpaceListView
        rows={[
          { id: 's1', name: 'Example Co', role: 'owner', state: 'confirmed', keysPending: false },
          { id: 's2', name: null, role: 'member', state: 'accepted', keysPending: true },
        ]}
        loading={false}
        creating={false}
        cryptoAvailable
        onOpen={onOpen}
        onCreate={vi.fn()}
      />,
    );
    expect(screen.getByText('Example Co')).toBeInTheDocument();
    expect(screen.getByText('Space (name locked)')).toBeInTheDocument();
    expect(screen.getByText('Keys waiting')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Open Example Co' }));
    expect(onOpen).toHaveBeenCalledWith('s1');
  });

  it('hands over a trimmed name and first collection', async () => {
    const onCreate = vi.fn();
    renderWithIntl(
      <SpaceListView rows={[]} loading={false} creating={false} cryptoAvailable onOpen={vi.fn()} onCreate={onCreate} />,
    );
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Space name'), ' Family ');
    await user.type(screen.getByLabelText('First collection'), 'Home');
    await user.click(screen.getByRole('button', { name: 'Make the space' }));
    expect(onCreate).toHaveBeenCalledWith({ name: 'Family', firstCollection: 'Home' });
  });

  it('says so when the browser can not make space keys yet', () => {
    renderWithIntl(
      <SpaceListView rows={[]} loading={false} creating={false} cryptoAvailable={false} onOpen={vi.fn()} onCreate={vi.fn()} />,
    );
    expect(screen.getByText(/can't seal or sign keys yet/)).toBeInTheDocument();
  });

  it('shows a failure to create', () => {
    renderWithIntl(
      <SpaceListView
        rows={[]}
        loading={false}
        creating={false}
        cryptoAvailable
        createError={{ id: 'error.generic' }}
        onOpen={vi.fn()}
        onCreate={vi.fn()}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
  });
});

describe('SpaceDetailView', () => {
  it('shows the members with their states and the open names', () => {
    view();
    expect(screen.getByRole('heading', { name: 'Example Co', level: 1 })).toBeInTheDocument();
    const row = screen.getByRole('row', { name: /Theo Grant/ });
    expect(within(row).getByText('Needs confirming')).toBeInTheDocument();
    // "Infrastructure" is also an option of the new-collection form inside the Collections card,
    // so ask for the row's own text, not the option.
    const collections = within(screen.getByRole('region', { name: 'Collections' }));
    expect(collections.getByText('Infrastructure', { selector: 'div' })).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Groups' })).getByText('Ops')).toBeInTheDocument();
  });

  it('starts a confirmation from the member row', async () => {
    const props = view();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Confirm Theo Grant' }));
    expect(props.actions.startConfirm).toHaveBeenCalledWith(expect.objectContaining({ user: THEO }));
  });

  it('shows the fingerprint to compare and only confirms on "It matches"', async () => {
    const theo = detail().members.find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    const props = view({
      confirming: {
        member: theo,
        fingerprint: { text: '12345 67890 11111 22222 33333 44444 55555 66666 77777 88888 99999 00000', bytes: new Uint8Array(64), consistent: true },
      },
    });
    expect(screen.getByLabelText("Fingerprint of Theo Grant's keys")).toHaveTextContent('12345 67890');
    await userEvent.setup().click(screen.getByRole('button', { name: 'It matches' }));
    expect(props.actions.confirm).toHaveBeenCalledOnce();
  });

  it('refuses to confirm while the fingerprint is not ready or disagrees', () => {
    const theo = detail().members.find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    view({ confirming: { member: theo, fingerprint: undefined } });
    expect(screen.getByRole('button', { name: 'It matches' })).toBeDisabled();
  });

  it('flags a fingerprint the browser could not check', () => {
    const theo = detail().members.find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    view({
      confirming: { member: theo, fingerprint: { text: '00000', bytes: new Uint8Array(64), consistent: false } },
    });
    expect(screen.getByText(/two ways of working out the fingerprint disagree/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'It matches' })).toBeDisabled();
  });

  it('can not confirm when the worker can not seal keys yet', () => {
    const theo = detail().members.find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    view({
      cryptoAvailable: false,
      confirming: { member: theo, fingerprint: { text: '00000', bytes: new Uint8Array(64), consistent: true } },
    });
    expect(screen.getByRole('button', { name: 'It matches' })).toBeDisabled();
    expect(screen.getAllByText(/can't seal or sign keys yet/).length).toBeGreaterThan(0);
  });

  it('asks before revoking and then revokes', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Revoke Lee Wong' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Revoke Lee Wong?')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    expect(props.actions.revoke).toHaveBeenCalledWith(expect.stringContaining('20000000'));
  });

  it('says what a revoked or removed member could open and that keys wait', () => {
    view({
      offboarded: {
        name: 'Lee Wong',
        outcome: { exposed: [{ collection: 'c1', liveItems: 12 }], keysPending: true },
      },
    });
    expect(screen.getByText('Lee Wong no longer has access')).toBeInTheDocument();
    expect(screen.getByText(/12 items in 1 collection/)).toBeInTheDocument();
    expect(screen.getByText(/waits for its keys to be replaced/)).toBeInTheDocument();
  });

  it('shows the paused-writes banner while keys wait', () => {
    const base = detail();
    view({
      detail: detail({
        view: { ...base.view, space: { ...base.view.space, keysPendingSince: 1_700_000_500 } },
      }),
    });
    expect(screen.getByText('This space waits for its keys to be replaced')).toBeInTheDocument();
  });

  it('shows no member actions to an ordinary member', () => {
    const base = detail();
    view({ detail: detail({ view: { ...base.view, me: { ...base.view.me, role: 'member' } } }) });
    expect(screen.queryByRole('button', { name: /Confirm Theo/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Invite people' })).not.toBeInTheDocument();
  });

  it('invites with a role and the collections they should get', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Invite people' }));
    await user.type(screen.getByLabelText('Email'), 'ana@example.co');
    await user.click(screen.getByLabelText('Infrastructure'));
    await user.click(screen.getByRole('button', { name: 'Send the invitation' }));
    expect(props.actions.invite).toHaveBeenCalledWith({
      email: 'ana@example.co',
      role: 'member',
      custom: [],
      grants: [{ collection: expect.any(String), permission: 'view' }],
    });
  });

  it('grants a collection to a person', async () => {
    const props = view();
    const user = userEvent.setup();
    const form = screen.getByRole('form', { name: 'Grant access' });
    await user.selectOptions(within(form).getByLabelText('Permission'), 'manage');
    await user.click(within(form).getByRole('button', { name: 'Grant' }));
    expect(props.actions.grant).toHaveBeenCalledWith(expect.any(String), expect.stringMatching(/^user:/), 'manage');
  });

  it('adds a collection and a group', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('New collection', { selector: 'input' }), 'Support');
    await user.click(screen.getByRole('button', { name: 'Add the collection' }));
    expect(props.actions.createCollection).toHaveBeenCalledWith('Support', undefined);
    await user.type(screen.getByLabelText('New group', { selector: 'input' }), 'Eng');
    await user.click(screen.getByRole('button', { name: 'Add the group' }));
    expect(props.actions.createGroup).toHaveBeenCalledWith('Eng', []);
  });

  it('shows a plain notice when the space can not be opened here', () => {
    view({ detail: detail({ readable: false, name: null }) });
    expect(screen.getByText(/can't seal or sign keys yet/)).toBeInTheDocument();
  });
});
