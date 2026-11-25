import { type FormEvent, useState } from 'react';
import type {
  CollectionPermission,
  CustomPermission,
  MemberViewDto,
  OffboardedDto,
  SpaceRole,
} from '@/api/spaces';
import { CUSTOM_PERMISSIONS, COLLECTION_PERMISSIONS, ROLES } from '@/api/spaces';
import { useT } from '@/i18n';
import type { Fingerprint } from '@/sharing/bundle';
import { Button } from '@/ui/Button';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { Notice } from '@/ui/Notice';
import '@/styles/account.css';
import { CheckList, SelectInput, TextInput } from '../account/controls';
import type { Described } from '../account/errors';
import { type SpaceDetail, type InviteInput, canManageUsers, memberLabel } from './model';
import { type Done, succeeded, useAsk } from './outcome';
import { SpaceStructure, type StructureActions } from './SpaceStructure';

export interface ConfirmState {
  member: MemberViewDto;
  /** undefined while it is being worked out, null when the bundle can't be read. */
  fingerprint: Fingerprint | null | undefined;
}

export interface SpaceActions extends StructureActions {
  invite: (input: InviteInput) => Done;
  accept: () => void;
  startConfirm: (member: MemberViewDto) => void;
  cancelConfirm: () => void;
  confirm: () => void;
  changeRole: (user: string, role: SpaceRole, custom: CustomPermission[]) => Done;
  revoke: (user: string) => Done;
  restore: (user: string) => void;
  remove: (user: string) => Done;
}

export interface SpaceDetailViewProps {
  detail: SpaceDetail | undefined;
  loading: boolean;
  loadError?: Described | undefined;
  confirming: ConfirmState | null;
  busy: boolean;
  error?: Described | undefined;
  /** What the last revoke or removal left exposed. */
  offboarded: { name: string; outcome: OffboardedDto } | null;
  cryptoAvailable: boolean;
  actions: SpaceActions;
  onBack: () => void;
}

function InviteForm({
  detail,
  busy,
  onInvite,
}: {
  detail: SpaceDetail;
  busy: boolean;
  /** Resolves true when the invitation went out; the form keeps its input otherwise. */
  onInvite: (input: InviteInput) => Promise<boolean>;
}) {
  const t = useT();
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<SpaceRole>('member');
  const [custom, setCustom] = useState<string[]>([]);
  const [collections, setCollections] = useState<string[]>([]);
  const [permission, setPermission] = useState<CollectionPermission>('view');

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (email.trim() === '') return;
    const sent = await onInvite({
      email,
      role,
      custom: custom as CustomPermission[],
      grants: collections.map((collection) => ({ collection, permission })),
    });
    if (sent) setEmail('');
  }

  return (
    <form className="panel-body" noValidate onSubmit={submit} aria-label={t('space.invite.title')}>
      <h3 className="lbl">{t('space.invite.title')}</h3>
      <TextInput label={t('space.invite.email')} type="email" value={email} onChange={setEmail} required />
      <SelectInput
        label={t('space.invite.role')}
        value={role}
        onChange={(value) => setRole(value as SpaceRole)}
        options={ROLES.map((r) => ({ value: r, label: t(`space.role.${r}`) }))}
      />
      {role === 'custom' ? (
        <CheckList
          legend={t('space.invite.custom')}
          options={CUSTOM_PERMISSIONS.map((p) => ({ value: p, label: t(`space.custom.${p}`) }))}
          selected={custom}
          onChange={setCustom}
        />
      ) : null}
      {detail.collections.length > 0 ? (
        <>
          <CheckList
            legend={t('space.invite.collections')}
            options={detail.collections.map((c) => ({
              value: c.id,
              label: c.title ?? t('space.collection.locked'),
            }))}
            selected={collections}
            onChange={setCollections}
          />
          <SelectInput
            label={t('space.invite.permission')}
            value={permission}
            onChange={(value) => setPermission(value as CollectionPermission)}
            options={COLLECTION_PERMISSIONS.map((p) => ({
              value: p,
              label: t(`space.permission.${p}`),
            }))}
          />
        </>
      ) : null}
      <div className="actions">
        <Button type="submit" variant="primary" isDisabled={busy}>
          {t('space.invite.submit')}
        </Button>
      </div>
    </form>
  );
}

function RoleEditor({
  member,
  busy,
  onSave,
  onCancel,
}: {
  member: MemberViewDto;
  busy: boolean;
  onSave: (role: SpaceRole, custom: CustomPermission[]) => Promise<boolean>;
  onCancel: () => void;
}) {
  const t = useT();
  const name = member.name || member.email;
  const [role, setRole] = useState<SpaceRole>(member.role);
  const [custom, setCustom] = useState<string[]>(member.custom);
  return (
    <div className="panel-body" role="group" aria-label={t('space.role.edit', { name })}>
      <SelectInput
        label={t('space.role.for', { name })}
        value={role}
        onChange={(value) => setRole(value as SpaceRole)}
        options={ROLES.map((r) => ({ value: r, label: t(`space.role.${r}`) }))}
      />
      {role === 'custom' ? (
        <CheckList
          legend={t('space.invite.custom')}
          options={CUSTOM_PERMISSIONS.map((p) => ({ value: p, label: t(`space.custom.${p}`) }))}
          selected={custom}
          onChange={setCustom}
        />
      ) : null}
      <div className="actions">
        <Button onPress={onCancel}>{t('action.cancel')}</Button>
        <Button
          variant="primary"
          isDisabled={busy}
          onPress={() => void onSave(role, role === 'custom' ? (custom as CustomPermission[]) : [])}
        >
          {t('action.save')}
        </Button>
      </div>
    </div>
  );
}

function ConfirmPanel({
  state,
  busy,
  cryptoAvailable,
  onConfirm,
  onCancel,
}: {
  state: ConfirmState;
  busy: boolean;
  cryptoAvailable: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const name = state.member.name || state.member.email;
  const fp = state.fingerprint;
  const ready = fp !== undefined && fp !== null && fp.consistent;
  return (
    <section className="confirm-panel" aria-labelledby="h-confirm">
      <h2 id="h-confirm">{t('space.confirm.title', { name })}</h2>
      <p>{t('space.confirm.body', { name })}</p>
      {fp === undefined ? (
        <p role="status">{t('space.confirm.working')}</p>
      ) : fp === null ? (
        <Notice tone="error" live>
          <p>{t('space.confirm.unreadable', { name })}</p>
        </Notice>
      ) : (
        <>
          <p className="fp" aria-label={t('space.confirm.fingerprintLabel', { name })}>
            {fp.text}
          </p>
          {!fp.consistent ? (
            <Notice tone="error" live>
              <p>{t('space.confirm.inconsistent')}</p>
            </Notice>
          ) : null}
        </>
      )}
      <p>{t('space.confirm.warning')}</p>
      {!cryptoAvailable ? (
        <Notice tone="warn">
          <p>{t('sharing.unavailable')}</p>
        </Notice>
      ) : null}
      <div className="actions">
        <Button onPress={onCancel}>{t('space.confirm.notNow')}</Button>
        <Button
          variant="primary"
          isDisabled={busy || !ready || !cryptoAvailable}
          onPress={onConfirm}
        >
          {t('space.confirm.matches')}
        </Button>
      </div>
    </section>
  );
}

type Offboard = { kind: 'revoke' | 'remove'; member: MemberViewDto } | null;

export function SpaceDetailView({
  detail,
  loading,
  loadError,
  confirming,
  busy,
  error,
  offboarded,
  cryptoAvailable,
  actions,
  onBack,
}: SpaceDetailViewProps) {
  const t = useT();
  const [inviting, setInviting] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const offboarding = useAsk<NonNullable<Offboard>>((target) =>
    target.kind === 'remove' ? actions.remove(target.member.user) : actions.revoke(target.member.user),
  );
  const offboard = offboarding.target;

  if (loading || !detail) {
    return (
      <>
        <div className="actions">
          <Button size="small" onPress={onBack}>
            {t('space.back')}
          </Button>
        </div>
        {loadError ? (
          <Notice tone="error" live>
            <p>{t(loadError.id, loadError.values)}</p>
          </Notice>
        ) : (
          <p role="status" className="muted">
            {t('state.loading')}
          </p>
        )}
      </>
    );
  }

  const { view, members } = detail;
  const me = view.me;
  const manage = canManageUsers(me);
  const pendingKeys =
    view.space.keysPendingSince !== null || view.collections.some((c) => c.staleSince !== null);
  const title = detail.name ?? t('space.detail.locked');

  return (
    <>
      <div className="actions">
        <Button size="small" onPress={onBack}>
          {t('space.back')}
        </Button>
      </div>
      <div className="page-head">
        <div>
          <h1 className="page-title">{title}</h1>
          <p className="lede">
            {t('space.detail.meta', {
              role: t(`space.role.${me.role}`),
              members: members.length,
              collections: view.collections.length,
            })}
          </p>
        </div>
        {manage ? (
          <Button variant="primary" onPress={() => setInviting((open) => !open)}>
            {t('space.invite.open')}
          </Button>
        ) : null}
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      {!detail.readable ? (
        <Notice tone="warn">
          <p>{me.state === 'confirmed' ? t('sharing.unavailable') : t('space.detail.notConfirmed')}</p>
        </Notice>
      ) : null}
      {pendingKeys ? (
        <Notice tone="warn" live>
          <b>{t('space.keysPending.title')}</b>
          <p>{t('space.keysPending.body')}</p>
        </Notice>
      ) : null}
      {offboarded ? (
        <Notice tone="warn" live>
          <b>{t('space.offboarded.title', { name: offboarded.name })}</b>
          <p>
            {offboarded.outcome.exposed.length === 0
              ? t('space.offboarded.none')
              : t('space.offboarded.exposed', {
                  collections: offboarded.outcome.exposed.length,
                  items: offboarded.outcome.exposed.reduce((sum, e) => sum + e.liveItems, 0),
                })}
          </p>
          {offboarded.outcome.keysPending ? <p>{t('space.offboarded.keys')}</p> : null}
        </Notice>
      ) : null}

      {confirming ? (
        <ConfirmPanel
          state={confirming}
          busy={busy}
          cryptoAvailable={cryptoAvailable}
          onConfirm={actions.confirm}
          onCancel={actions.cancelConfirm}
        />
      ) : null}

      <section className="card" aria-labelledby="h-members">
        <div className="card-head">
          <h2 id="h-members">{t('space.members.title')}</h2>
        </div>
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">{t('space.members.member')}</th>
                <th scope="col">{t('space.members.role')}</th>
                <th scope="col">{t('space.members.status')}</th>
                <th scope="col">
                  <span className="sr">{t('table.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {members.map((member) => {
                const name = member.name || member.email;
                const isMe = member.user === me.user;
                return (
                  <tr key={member.user}>
                    <td>
                      <div>{name}</div>
                      <div className="hint">{member.email}</div>
                    </td>
                    <td>
                      {t(`space.role.${member.role}`)}
                      {member.role === 'custom' && member.custom.length > 0 ? (
                        <div className="hint">
                          {member.custom.map((p) => t(`space.custom.${p}`)).join(', ')}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <span className={member.state === 'confirmed' ? 'tag ok' : 'tag warn'}>
                        {t(`space.state.${member.state}`)}
                      </span>
                      {member.needsReconfirmation ? (
                        <span className="tag warn">{t('space.members.reconfirm')}</span>
                      ) : null}
                    </td>
                    <td>
                      <div className="actions">
                        {isMe && member.state === 'invited' ? (
                          <Button size="small" variant="primary" isDisabled={busy} onPress={actions.accept}>
                            {t('space.members.accept')}
                          </Button>
                        ) : null}
                        {!isMe && manage && (member.state === 'accepted' || member.needsReconfirmation) ? (
                          <Button
                            size="small"
                            variant="primary"
                            aria-label={t('space.members.confirmFor', { name })}
                            onPress={() => actions.startConfirm(member)}
                          >
                            {t('space.members.confirm')}
                          </Button>
                        ) : null}
                        {!isMe && manage && member.state !== 'revoked' ? (
                          <>
                            <Button
                              size="small"
                              aria-label={t('space.members.roleFor', { name })}
                              onPress={() => setEditing(member.user)}
                            >
                              {t('space.members.changeRole')}
                            </Button>
                            <Button
                              size="small"
                              aria-label={t('space.members.revokeFor', { name })}
                              onPress={() => offboarding.ask({ kind: 'revoke', member })}
                            >
                              {t('space.members.revoke')}
                            </Button>
                          </>
                        ) : null}
                        {!isMe && manage && member.state === 'revoked' ? (
                          <Button
                            size="small"
                            aria-label={t('space.members.restoreFor', { name })}
                            isDisabled={busy}
                            onPress={() => actions.restore(member.user)}
                          >
                            {t('action.restore')}
                          </Button>
                        ) : null}
                        {!isMe && manage ? (
                          <Button
                            size="small"
                            variant="danger"
                            aria-label={t('space.members.removeFor', { name })}
                            onPress={() => offboarding.ask({ kind: 'remove', member })}
                          >
                            {t('space.members.remove')}
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {editing
          ? (() => {
              const member = members.find((m) => m.user === editing);
              return member ? (
                <RoleEditor
                  key={member.user}
                  member={member}
                  busy={busy}
                  onCancel={() => setEditing(null)}
                  onSave={async (role, custom) => {
                    const saved = await succeeded(actions.changeRole(member.user, role, custom));
                    if (saved) setEditing(null);
                    return saved;
                  }}
                />
              ) : null;
            })()
          : null}
        {inviting && manage ? (
          <InviteForm
            detail={detail}
            busy={busy}
            onInvite={async (input) => {
              const sent = await succeeded(actions.invite(input));
              if (sent) setInviting(false);
              return sent;
            }}
          />
        ) : null}
      </section>

      <SpaceStructure detail={detail} busy={busy} error={error} actions={actions} />

      <ConfirmDialog
        isOpen={offboard !== null}
        onOpenChange={(open) => {
          if (!open) offboarding.close();
        }}
        title={
          offboard?.kind === 'remove'
            ? t('space.remove.title', { name: offboard ? memberLabel(members, offboard.member.user) : '' })
            : t('space.revoke.title', { name: offboard ? memberLabel(members, offboard.member.user) : '' })
        }
        confirmLabel={offboard?.kind === 'remove' ? t('space.members.remove') : t('space.members.revoke')}
        pending={busy}
        error={offboarding.tried && error ? t(error.id, error.values) : undefined}
        onConfirm={() => void offboarding.confirm()}
      >
        <p>{offboard?.kind === 'remove' ? t('space.remove.body') : t('space.revoke.body')}</p>
      </ConfirmDialog>
    </>
  );
}
