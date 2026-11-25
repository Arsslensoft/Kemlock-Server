import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import type { AccountMode, AdminInvite, AdminSpace, AdminUser, InviteIssued } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { relative } from './format';
import { useReauth } from './reauth';
import { ErrorNotice, Loading, PageHead, SelectBox, TextBox } from './ui';

export type UserAction = 'sign-out' | 'disable' | 'enable' | 'reset-two-step' | 'erase' | 'cancel-erasure';
export type InviteAction = 'resend' | 'revoke';

const MODE: Record<AccountMode, MessageId> = {
  'kemlock-only': 'admin.users.mode.kemlock',
  compatible: 'admin.users.mode.compatible',
};

function UserRow({
  user,
  now,
  busy,
  onAction,
}: {
  user: AdminUser;
  now?: number | undefined;
  busy?: boolean | undefined;
  onAction: (action: UserAction, user: AdminUser) => void;
}) {
  const t = useT();
  const who = user.name ?? user.email;
  const disabled = user.disabledAt !== null;
  const button = (action: UserAction, label: MessageId, tone?: 'danger') => (
    <Button
      size="small"
      variant={tone ?? 'default'}
      isDisabled={busy}
      aria-label={t('admin.users.actionFor', { action: t(label), who })}
      onPress={() => onAction(action, user)}
    >
      {t(label)}
    </Button>
  );
  return (
    <tr>
      <td>
        <div>{who}</div>
        <div className="adm-cell-sub">
          {user.name ? user.email : ''}
          {user.role === 'admin' ? ` · ${t('admin.users.admin')}` : ''}
          {disabled ? ` · ${t('admin.users.disabled')}` : ''}
          {user.erasurePending ? ` · ${t('admin.users.erasurePending')}` : ''}
        </div>
      </td>
      <td>{t(MODE[user.mode])}</td>
      <td>
        {user.twoStep ? (
          <span className="tag ok">{t('admin.users.twoStep.on')}</span>
        ) : (
          <span className="tag warn">{t('admin.users.twoStep.none')}</span>
        )}
      </td>
      <td className="adm-num">{user.devices}</td>
      <td>{user.lastSeenAt === null ? t('admin.users.never') : relative(user.lastSeenAt, now)}</td>
      <td>
        <div className="adm-row-actions">
          {user.erasurePending ? (
            // Signing in is refused while the deletion is pending, so only this cancels it.
            button('cancel-erasure', 'admin.users.cancelErasure')
          ) : disabled ? (
            button('enable', 'admin.users.enable')
          ) : (
            <>
              {button('sign-out', 'admin.users.signOut')}
              {button('disable', 'admin.users.disable')}
              {user.twoStep ? button('reset-two-step', 'admin.users.resetTwoStep') : null}
            </>
          )}
          {button('erase', 'admin.users.erase', 'danger')}
        </div>
      </td>
    </tr>
  );
}

function OwnerPanel({
  space,
  candidates,
  onConfirm,
  onCancel,
}: {
  space: AdminSpace;
  candidates: AdminUser[];
  onConfirm: (userId: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [pick, setPick] = useState(candidates[0]?.id ?? '');
  return (
    <div className="adm-pad" role="group" aria-label={t('admin.users.owner.title')}>
      <SelectBox
        label={t('admin.users.owner.new', { space: space.id.slice(0, 8) })}
        value={pick}
        onChange={setPick}
        hint={t('admin.users.owner.hint')}
        options={candidates.map((user) => ({ value: user.id, label: user.name ?? user.email }))}
      />
      <div className="actions">
        <Button size="small" onPress={onCancel}>
          {t('action.cancel')}
        </Button>
        <Button size="small" variant="primary" isDisabled={pick === ''} onPress={() => onConfirm(pick)}>
          {t('admin.users.owner.confirm')}
        </Button>
      </div>
    </div>
  );
}

/** What the server did with a new invitation, and the link it will not show again. */
function Issued({ issued }: { issued: InviteIssued }) {
  const t = useT();
  return (
    <Notice tone={issued.mailed ? 'info' : 'warn'} live>
      <p>
        <b>{t('admin.invites.issued', { email: issued.invite.email })}</b>{' '}
        {issued.mailed ? t('admin.invites.mailed') : t('admin.invites.notMailed')}
      </p>
      <div className="with-action">
        <span className="mono">{issued.link}</span>
        <CopyButton value={issued.link} label={t('admin.invites.copy')} />
      </div>
    </Notice>
  );
}

function inviteState(invite: AdminInvite): MessageId | null {
  if (invite.accepted) return 'admin.invites.accepted';
  return invite.pending ? null : 'admin.invites.expired';
}

export interface UsersViewProps {
  users: AdminUser[];
  total: number;
  invites: AdminInvite[];
  /** The invitation just made or sent again, with its link. */
  issued?: InviteIssued | undefined;
  spaces: AdminSpace[];
  search: string;
  onSearch: (value: string) => void;
  onInvite: (email: string) => void;
  onInviteAction: (action: InviteAction, invite: AdminInvite) => void;
  onAction: (action: UserAction, user: AdminUser) => void;
  onChangeOwner: (space: AdminSpace, userId: string) => void;
  hasMore?: boolean;
  onMore?: () => void;
  busy?: boolean;
  error?: unknown;
  now?: number;
}

/**
 * The server's own rule for an address: one @, text before it, a dot in the domain, no spaces.
 * It takes what a stricter parser would not, such as ada@bücher.de.
 */
export function isEmail(value: string): boolean {
  const parts = value.split('@');
  if (parts.length !== 2 || /\s/.test(value)) return false;
  const [local = '', domain = ''] = parts;
  return local !== '' && domain.includes('.') && !domain.startsWith('.') && !domain.endsWith('.');
}

/** Users, invitations and spaces. Takes data and callbacks, no router and no network. */
export function UsersView(props: UsersViewProps) {
  const { users, spaces, now } = props;
  const t = useT();
  const [email, setEmail] = useState('');
  const [erase, setErase] = useState<AdminUser | null>(null);
  const [ownerOf, setOwnerOf] = useState<AdminSpace | null>(null);
  const candidates = useMemo(() => users.filter((user) => user.disabledAt === null), [users]);

  // Checked as it is typed: an address that is not one shows its error and blocks Invite.
  const address = email.trim();
  const valid = isEmail(address);
  const emailError: MessageId | undefined = address !== '' && !valid ? 'error.email' : undefined;

  function invite(): void {
    if (!valid) return;
    props.onInvite(address);
    setEmail('');
  }

  return (
    <>
      <PageHead
        title={t('admin.users')}
        lede={t('admin.users.lede')}
        actions={
          <form
            className="adm-invite"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              invite();
            }}
          >
            <TextBox
              label={t('admin.users.invite.label')}
              type="email"
              value={email}
              onChange={setEmail}
              placeholder="name@example.co"
              inputMode="email"
              required
              error={emailError}
              autoComplete="off"
            />
            <Button type="submit" variant="primary" isDisabled={props.busy || !valid}>
              {t('admin.users.invite.submit')}
            </Button>
          </form>
        }
      />

      {props.error ? <ErrorNotice error={props.error} /> : null}
      {props.issued ? <Issued issued={props.issued} /> : null}

      <section className="card" aria-labelledby="h-users">
        <div className="adm-head">
          <h2 id="h-users">{t('admin.users.heading')}</h2>
          <span className="hint">{t('admin.users.count', { total: props.total, shown: users.length })}</span>
        </div>
        <div className="adm-pad">
          <TextBox
            label={t('admin.users.search')}
            type="search"
            value={props.search}
            onChange={props.onSearch}
          />
        </div>
        {users.length === 0 ? (
          <p className="empty">{t('admin.users.none')}</p>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th scope="col">{t('admin.users.col.user')}</th>
                  <th scope="col">{t('admin.users.col.signIn')}</th>
                  <th scope="col">{t('admin.users.col.twoStep')}</th>
                  <th scope="col">{t('admin.users.col.devices')}</th>
                  <th scope="col">{t('admin.users.col.active')}</th>
                  <th scope="col">
                    <span className="sr">{t('table.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <UserRow
                    key={user.id}
                    user={user}
                    now={now}
                    busy={props.busy}
                    onAction={(action, target) => {
                      if (action === 'erase') setErase(target);
                      else props.onAction(action, target);
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {props.hasMore ? (
          <div className="adm-pad">
            <Button size="small" onPress={props.onMore}>
              {t('admin.users.more')}
            </Button>
          </div>
        ) : null}
        <p className="hint adm-pad">{t('admin.users.deviceNote')}</p>
      </section>

      <section className="card" aria-labelledby="h-invites">
        <div className="adm-head">
          <h2 id="h-invites">{t('admin.invites.title')}</h2>
        </div>
        {props.invites.length === 0 ? (
          <p className="empty">{t('admin.invites.none')}</p>
        ) : (
          props.invites.map((invite) => {
            const state = inviteState(invite);
            return (
              <div className="row" key={invite.id}>
                <div className="grow">
                  <div>{invite.email}</div>
                  <div className="hint">
                    {state
                      ? t(state)
                      : t('admin.invites.sentOf', {
                          count: invite.sent,
                          when: relative(invite.expiresAt, now),
                        })}
                  </div>
                </div>
                {invite.pending ? (
                  <>
                    <Button
                      size="small"
                      isDisabled={props.busy}
                      aria-label={t('admin.users.actionFor', { action: t('admin.users.resend'), who: invite.email })}
                      onPress={() => props.onInviteAction('resend', invite)}
                    >
                      {t('admin.users.resend')}
                    </Button>
                    <Button
                      size="small"
                      isDisabled={props.busy}
                      aria-label={t('admin.users.actionFor', { action: t('admin.users.revoke'), who: invite.email })}
                      onPress={() => props.onInviteAction('revoke', invite)}
                    >
                      {t('admin.users.revoke')}
                    </Button>
                  </>
                ) : null}
              </div>
            );
          })
        )}
      </section>

      <section className="card" aria-labelledby="h-spaces">
        <div className="adm-head">
          <h2 id="h-spaces">{t('admin.users.spaces')}</h2>
        </div>
        {spaces.length === 0 ? (
          <p className="empty">{t('admin.users.spaces.none')}</p>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th scope="col">{t('admin.users.col.space')}</th>
                  <th scope="col">{t('admin.users.col.owners')}</th>
                  <th scope="col">{t('admin.users.col.members')}</th>
                  <th scope="col">{t('admin.users.col.items')}</th>
                  <th scope="col">{t('admin.users.col.keys')}</th>
                  <th scope="col">
                    <span className="sr">{t('table.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {spaces.map((space) => {
                  const name = space.id.slice(0, 8);
                  return (
                    <tr key={space.id}>
                      <td className="mono">{name}</td>
                      <td>{space.owners.map((owner) => owner.email).join(', ')}</td>
                      <td>{t('admin.users.members.confirmed', { confirmed: space.confirmed, members: space.members })}</td>
                      <td className="adm-num">{space.liveItems}</td>
                      <td>
                        {space.keysPendingSince === null ? (
                          t('admin.users.keys.ok')
                        ) : (
                          <span className="tag warn">{t('admin.users.keys.waiting')}</span>
                        )}
                      </td>
                      <td>
                        <div className="adm-row-actions">
                          <Button
                            size="small"
                            aria-label={t('admin.users.owner.change', { space: name })}
                            onPress={() => setOwnerOf(space)}
                          >
                            {t('admin.users.owner.changeShort')}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="hint adm-pad">{t('admin.users.spaces.nameNote')}</p>
        {ownerOf ? (
          <OwnerPanel
            space={ownerOf}
            candidates={candidates}
            onCancel={() => setOwnerOf(null)}
            onConfirm={(userId) => {
              props.onChangeOwner(ownerOf, userId);
              setOwnerOf(null);
            }}
          />
        ) : null}
      </section>

      <ConfirmDialog
        isOpen={erase !== null}
        onOpenChange={(open) => {
          if (!open) setErase(null);
        }}
        title={t('admin.users.erase.title', { who: erase?.name ?? erase?.email ?? '' })}
        confirmLabel={t('admin.users.erase')}
        onConfirm={() => {
          if (erase) props.onAction('erase', erase);
          setErase(null);
        }}
      >
        <p>{t('admin.users.erase.body')}</p>
      </ConfirmDialog>
    </>
  );
}

const PAGE = 50;

export default function Users() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [issued, setIssued] = useState<InviteIssued | undefined>();
  const { guard, dialog } = useReauth(admin);
  const users = useInfiniteQuery({
    queryKey: ['admin', 'users', search],
    queryFn: ({ pageParam }) =>
      admin.users({ search: search === '' ? undefined : search, limit: PAGE, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => {
      const shown = pages.reduce((sum, page) => sum + page.users.length, 0);
      return shown < last.total && last.users.length > 0 ? shown : undefined;
    },
  });
  const spaces = useQuery({ queryKey: ['admin', 'spaces'], queryFn: () => admin.spaces({ limit: 200 }) });
  const invites = useQuery({ queryKey: ['admin', 'invitations'], queryFn: () => admin.invitations() });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin'] });
  const act = useMutation({
    mutationFn: ({ action, user }: { action: UserAction; user: AdminUser }) =>
      guard((token) => {
        switch (action) {
          case 'sign-out':
            return admin.signOutEverywhere(user.id, token);
          case 'disable':
            return admin.setDisabled(user.id, true, token);
          case 'enable':
            return admin.setDisabled(user.id, false, token);
          case 'reset-two-step':
            return admin.resetTwoStep(user.id, token);
          case 'erase':
            return admin.eraseUser(user.id, token);
          case 'cancel-erasure':
            return admin.cancelErasure(user.id, token);
        }
      }),
    onSuccess: refresh,
  });
  const invite = useMutation({
    mutationFn: (email: string) => guard((token) => admin.invite(email, token)),
    onSuccess: (result) => {
      setIssued(result);
      return refresh();
    },
  });
  const inviteAct = useMutation({
    mutationFn: ({ action, target }: { action: InviteAction; target: AdminInvite }) =>
      guard(async (token) => {
        if (action === 'revoke') {
          await admin.revokeInvitation(target.id, token);
          return undefined;
        }
        return admin.resendInvitation(target.id, token);
      }),
    onSuccess: (result) => {
      setIssued(result);
      return refresh();
    },
  });
  const owner = useMutation({
    mutationFn: ({ space, userId }: { space: AdminSpace; userId: string }) =>
      guard((token) => admin.changeOwner(space.id, { newOwner: userId }, token)),
    onSuccess: refresh,
  });

  const pages = users.data?.pages ?? [];
  const list = pages.flatMap((page) => page.users);
  if (users.isPending) return <Loading />;
  return (
    <>
      <UsersView
        users={list}
        total={pages[0]?.total ?? list.length}
        invites={invites.data ?? []}
        issued={issued}
        spaces={spaces.data?.spaces ?? []}
        search={search}
        onSearch={setSearch}
        onInvite={(email) => invite.mutate(email)}
        onInviteAction={(action, target) => inviteAct.mutate({ action, target })}
        onAction={(action, user) => act.mutate({ action, user })}
        onChangeOwner={(space, userId) => owner.mutate({ space, userId })}
        hasMore={users.hasNextPage}
        onMore={() => void users.fetchNextPage()}
        busy={act.isPending || invite.isPending || inviteAct.isPending || owner.isPending}
        error={users.error ?? spaces.error ?? invites.error ?? act.error ?? invite.error ?? inviteAct.error ?? owner.error}
      />
      {dialog}
    </>
  );
}
