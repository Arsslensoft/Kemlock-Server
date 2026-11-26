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
import {
  type InviteInput,
  type ReplaceProgress,
  type Replaced,
  type SpaceDetail,
  canManageUsers,
  keysAwaitReplacement,
  memberLabel,
} from './model';
import { type Done, succeeded, useAsk } from './outcome';
import { SpaceStructure, type StructureActions } from './SpaceStructure';

export interface ConfirmState {
  member: MemberViewDto;
  /** undefined while it is being worked out, null when the bundle can't be read. */
  fingerprint: Fingerprint | null | undefined;
  /** `pin`: only compare, so this browser trusts the confirmations they made; default `confirm`. */
  mode?: 'confirm' | 'pin';
}

export interface SpaceActions extends StructureActions {
  /** The person compared the fingerprint first contact asked for and it matched. */
  acceptFirstContact?: () => void;
  /** Replaces the keys that wait for it, for a space with a verified chain. */
  replaceKeys?: () => void;
  invite: (input: InviteInput) => Done;
  accept: () => void;
  startConfirm: (member: MemberViewDto) => void;
  /** Compares a member's fingerprint without confirming them, so their confirmations are trusted here. */
  startPin?: (member: MemberViewDto) => void;
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
  /** How far a key replacement is, while one runs. */
  replacing?: ReplaceProgress | null;
  /** What the last key replacement did. */
  replaced?: Replaced | null;
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
      <h2 id="h-confirm">{t(state.mode === 'pin' ? 'space.pin.title' : 'space.confirm.title', { name })}</h2>
      <p>{t(state.mode === 'pin' ? 'space.pin.body' : 'space.confirm.body', { name })}</p>
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

/** What a space that isn't checked says: why, and for a chain waiting for first contact, what to compare. */
function ChainNotice({
  detail,
  busy,
  onAccept,
}: {
  detail: SpaceDetail;
  busy: boolean;
  onAccept: (() => void) | undefined;
}) {
  const t = useT();
  const [picked, setPicked] = useState('');
  const trust = detail.trust;
  if (!trust || trust.kind === 'unchained' || trust.kind === 'verified') return null;
  if (trust.kind === 'unverified') {
    return (
      <Notice tone="error" live>
        <b>{t('space.chain.unchecked.title')}</b>
        <p>
          {trust.reason === 'unreachable'
            ? t('space.chain.unreachable.body')
            : t('space.chain.unchecked.body', { reason: trust.reason })}
        </p>
      </Notice>
    );
  }
  const ask = trust.view.firstContact;
  const owners = ask?.owners ?? [];
  const chosen = ask?.kind === 'pick' ? owners.find((o) => o.id === picked) : undefined;
  const person = ask?.kind === 'compare' ? ask.person : chosen?.id;
  const digits = ask?.kind === 'compare' ? ask.fingerprint : chosen?.fingerprint;
  const name = person ? memberLabel(detail.members, person) : '';
  return (
    <section className="confirm-panel" aria-labelledby="h-first-contact">
      <h2 id="h-first-contact">{t('space.chain.contact.title')}</h2>
      {ask?.kind === 'compare' ? (
        <p>{t('space.chain.contact.compare', { name })}</p>
      ) : owners.length > 0 ? (
        <>
          <p>{t('space.chain.contact.pick')}</p>
          <SelectInput
            label={t('space.chain.contact.owner')}
            value={picked}
            onChange={setPicked}
            options={[
              { value: '', label: '' },
              ...owners.map((o) => ({ value: o.id, label: memberLabel(detail.members, o.id) })),
            ]}
          />
        </>
      ) : (
        <Notice tone="warn">
          <p>{t('space.chain.contact.none')}</p>
        </Notice>
      )}
      {digits ? (
        <p className="fp" aria-label={t('space.chain.contact.label', { name })}>
          {digits}
        </p>
      ) : null}
      <p>{t('space.chain.contact.warning')}</p>
      <div className="actions">
        <Button
          variant="primary"
          isDisabled={busy || !digits || !onAccept}
          onPress={() => onAccept?.()}
        >
          {t('space.chain.contact.matches')}
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
  replacing = null,
  replaced = null,
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

  const { view } = detail;
  // While first contact is pending the roster is the server's word, so it isn't shown, and an
  // invitation can't be accepted yet (docs/crypto.md, "First contact", "When").
  const waiting = detail.trust?.kind === 'first-contact';
  const members = waiting ? [] : detail.members;
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
        {manage && !waiting ? (
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
      <ChainNotice detail={detail} busy={busy} onAccept={actions.acceptFirstContact} />
      {!detail.readable && (!detail.trust || detail.trust.kind === 'unchained') ? (
        <Notice tone="warn">
          <p>{me.state === 'confirmed' ? t('sharing.unavailable') : t('space.detail.notConfirmed')}</p>
        </Notice>
      ) : null}
      {keysAwaitReplacement(detail) ? (
        <Notice tone="warn" live>
          <b>{t('space.keysPending.title')}</b>
          <p>{t('space.keysPending.chained')}</p>
          {replacing ? (
            <p role="status">
              {replacing.phase === 'reading'
                ? t('space.keys.reading', { done: replacing.done })
                : replacing.phase === 'sealing'
                  ? t('space.keys.sealing', { total: replacing.total })
                  : t('space.keys.sending', { done: replacing.done, total: replacing.total })}
              {replacing.phase === 'sending' && replacing.total > 0 ? (
                <progress value={replacing.done} max={replacing.total} aria-label={t('space.keys.progress')} />
              ) : null}
            </p>
          ) : null}
          {actions.replaceKeys ? (
            <div className="actions">
              <Button variant="primary" isDisabled={busy || replacing !== null} onPress={actions.replaceKeys}>
                {t('space.keys.replace')}
              </Button>
            </div>
          ) : null}
        </Notice>
      ) : pendingKeys ? (
        <Notice tone="warn" live>
          <b>{t('space.keysPending.title')}</b>
          <p>{t('space.keysPending.body')}</p>
        </Notice>
      ) : null}
      {replaced ? (
        <Notice tone="info" live>
          <b>{t('space.keys.done', { rewritten: replaced.rewritten })}</b>
          {replaced.held > 0 ? <p>{t('space.keys.held', { held: replaced.held })}</p> : null}
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
                const unverified = detail.unverified?.find((u) => u.user === member.user);
                const compareWith = unverified?.compare
                  ? members.find((m) => m.user === unverified.compare)
                  : undefined;
                const compareName = compareWith ? compareWith.name || compareWith.email : '';
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
                      {unverified ? <span className="tag warn">{t('space.members.untraced')}</span> : null}
                    </td>
                    <td>
                      <div className="actions">
                        {isMe && member.state === 'invited' ? (
                          <Button size="small" variant="primary" isDisabled={busy} onPress={actions.accept}>
                            {t('space.members.accept')}
                          </Button>
                        ) : null}
                        {!isMe && manage && unverified ? (
                          <>
                            {compareWith && actions.startPin ? (
                              <Button
                                size="small"
                                aria-label={t('space.members.compareFor', { name: compareName })}
                                onPress={() => actions.startPin?.(compareWith)}
                              >
                                {t('space.members.compare')}
                              </Button>
                            ) : null}
                          </>
                        ) : null}
                        {!isMe &&
                        manage &&
                        (member.state === 'accepted' || member.needsReconfirmation || unverified) ? (
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
        {detail.trust?.kind === 'verified' ? (
          <p className="hint">{t('space.chain.unsupported')}</p>
        ) : null}
        {inviting && manage && !waiting ? (
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
