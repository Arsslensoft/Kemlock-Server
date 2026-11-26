import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
// The manifest keeper plugs into the space deps here: what a key replacement writes is listed in
// the space's signed manifest.
import '@/manifest/instance';
import type { MemberViewDto, OffboardedDto } from '@/api/spaces';
import { decodeB64 } from '@/lib/b64url';
import { type Fingerprint, checkedFingerprint } from '@/sharing/bundle';
import { vaultCrypto } from '@/crypto-port';
import { type Described, describeAccountError } from '../account/errors';
import { useRun } from '../account/useRun';
import { spaceDeps } from './deps';
import { acceptFirstContact } from './chain';
import { refreshSpaces } from './refresh';
import {
  type SpaceDetail as Detail,
  ChainConflict,
  ChainRefused,
  ReplaceBlocked,
  SpaceNotChecked,
  changeRole,
  confirmMember,
  createCollection,
  createGroup,
  deleteCollection,
  deleteGroup,
  grantAccess,
  inviteMember,
  loadSpaceDetail,
  offboardMember,
  pinMember,
  type ReplaceProgress,
  type Replaced,
  type Resealed,
  itemsToReseal,
  renameCollection,
  replaceKeys,
  resealItems,
  revokeGrant,
  sealPending,
  setGroupMembers,
} from './model';
import { type ConfirmState, SpaceDetailView } from './SpaceDetailView';
import { MemberNotVerified } from './verify';

/** A member whose keys weren't sealed to gets words of their own; everything else the account screens'. */
function describeSpaceError(error: unknown): Described {
  if (error instanceof MemberNotVerified) {
    return {
      id: 'space.error.notVerified',
      values: { name: error.member.name || error.member.email },
    };
  }
  if (error instanceof SpaceNotChecked) {
    return { id: error.kind === 'verified' ? 'space.error.chained' : 'space.error.unchecked' };
  }
  if (error instanceof ChainRefused) {
    return { id: 'space.error.chainRefused', values: { reason: error.reason } };
  }
  if (error instanceof ChainConflict) return { id: 'space.error.chainConflict' };
  if (error instanceof ReplaceBlocked) {
    return error.reason === 'too-large'
      ? { id: 'space.error.replaceTooLarge' }
      : error.reason === 'no-manifest'
        ? { id: 'space.error.replaceNoManifest' }
        : { id: 'space.error.replaceUnreadable', values: { count: error.count } };
  }
  return describeAccountError(error);
}

export default function SpaceDetail() {
  const { spaceId = '' } = useParams({ strict: false }) as { spaceId?: string };
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const key = ['spaces', spaceId] as const;
  const query = useQuery({ queryKey: key, queryFn: () => loadSpaceDetail(spaceDeps, spaceId) });
  const { run, pending, error } = useRun(describeSpaceError);
  const [confirming, setConfirming] = useState<ConfirmState | null>(null);
  const [replacing, setReplacing] = useState<ReplaceProgress | null>(null);
  const [replaced, setReplaced] = useState<Replaced | null>(null);
  const [toReseal, setToReseal] = useState(0);
  const [resealed, setResealed] = useState<Resealed | null>(null);
  const [offboarded, setOffboarded] = useState<{ name: string; outcome: OffboardedDto } | null>(null);
  const detail: Detail | undefined = query.data;
  const { api } = spaceDeps;

  // Items left under an old key version (a replacement that stopped halfway, or held items), found
  // from the server's sync, so it is the same after a reload or on another device.
  async function recount(current: Detail | undefined): Promise<void> {
    try {
      setToReseal(current ? (await itemsToReseal(spaceDeps, current)).length : 0);
    } catch {
      // Not read now: the next load tries again.
    }
  }
  useEffect(() => {
    let live = true;
    if (detail?.trust?.kind !== 'verified' || !detail.readable) return undefined;
    void itemsToReseal(spaceDeps, detail)
      .then((items) => (live ? setToReseal(items.length) : undefined))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [detail]);

  // A member who is awaiting a key this account holds is sealed it now ("Using the state",
  // "Sealing"): once for each state of the chain this browser has loaded, and only by a member
  // who holds keys, so a reader of a space is never asked anything.
  const sealedAt = useRef('');
  useEffect(() => {
    if (!detail || detail.trust?.kind !== 'verified' || !detail.readable) return;
    const head = detail.trust.view.head;
    const at = `${spaceId}:${head?.seq ?? ''}:${head?.link ?? ''}`;
    if (sealedAt.current === at) return;
    sealedAt.current = at;
    void sealPending(spaceDeps, detail)
      .then((sealed) => (sealed ? refreshSpaces(queryClient) : undefined))
      .catch(() => undefined);
  }, [detail, spaceId, queryClient]);

  /**
   * Runs a change, then reads the space again. A member the browser wouldn't seal to is asked to
   * be confirmed again, when the server lets them be.
   */
  async function change<T>(action: () => Promise<T>): Promise<T | undefined> {
    const result = await run(async () => {
      try {
        return await action();
      } catch (caught) {
        if (caught instanceof MemberNotVerified) {
          // What would put it right: compare the fingerprint of the member the walk ended at, or
          // confirm this member again when their keys changed.
          if (caught.compare) void startConfirm(caught.compare, 'pin');
          else if (caught.member.needsReconfirmation) void startConfirm(caught.member);
        }
        throw caught;
      }
    });
    if (result !== undefined) {
      await refreshSpaces(queryClient);
    }
    return result;
  }

  /** Runs a change and says whether it worked, so a form can keep its input when it didn't. */
  async function worked(action: () => Promise<unknown>): Promise<boolean> {
    return (await change(action)) !== undefined;
  }

  function nameOf(user: string): string {
    const member = detail?.members.find((m) => m.user === user);
    return member ? member.name || member.email : user;
  }

  async function startConfirm(member: MemberViewDto, mode: 'confirm' | 'pin' = 'confirm') {
    setConfirming({ member, fingerprint: undefined, mode });
    let fingerprint: Fingerprint | null = null;
    try {
      fingerprint = await checkedFingerprint(decodeB64(member.publicBundle), (bundle) =>
        vaultCrypto.fingerprint(bundle),
      );
    } catch {
      fingerprint = null;
    }
    setConfirming({ member, fingerprint, mode });
  }

  return (
    <SpaceDetailView
      detail={detail}
      loading={query.isPending}
      loadError={query.error ? describeAccountError(query.error) : undefined}
      confirming={confirming}
      busy={pending}
      error={error}
      offboarded={offboarded}
      replacing={replacing}
      replaced={replaced}
      toReseal={toReseal}
      resealed={resealed}
      cryptoAvailable={spaceDeps.crypto.available}
      onBack={() => void navigate({ to: '/spaces' })}
      actions={{
        invite: (input) => worked(() => inviteMember(spaceDeps, spaceId, input, detail)),
        acceptFirstContact: () => {
          if (!detail) return;
          void change(() => acceptFirstContact(spaceDeps, spaceId, detail.view.me.user));
        },
        replaceKeys: () => {
          if (!detail) return;
          setReplaced(null);
          setReplacing({ phase: 'reading', done: 0, total: 0 });
          void change(() => replaceKeys(spaceDeps, detail, setReplacing))
            .then((result) => {
              if (result) setReplaced(result);
            })
            .finally(() => {
              setReplacing(null);
              // A failure partway leaves items to seal again: show them.
              void recount(detail);
            });
        },
        resealItems: () => {
          if (!detail) return;
          setResealed(null);
          setReplacing({ phase: 'reading', done: 0, total: 0 });
          void change(() => resealItems(spaceDeps, detail, setReplacing))
            .then((result) => {
              if (result) setResealed(result);
            })
            .finally(() => {
              setReplacing(null);
              void recount(detail);
            });
        },
        accept: () => void change(() => api.accept(spaceId, 'me')),
        startConfirm: (member) => void startConfirm(member),
        startPin: (member) => void startConfirm(member, 'pin'),
        cancelConfirm: () => setConfirming(null),
        confirm: () => {
          const current = confirming;
          if (!detail || !current?.fingerprint) return;
          const member = current.member;
          const fingerprint = current.fingerprint;
          const act = (): Promise<unknown> =>
            current.mode === 'pin'
              ? pinMember(spaceDeps, detail.view.me.user, member, fingerprint).then(() => true)
              : confirmMember(spaceDeps, detail, member, fingerprint);
          void change(act).then((done) => {
            if (done) setConfirming(null);
          });
        },
        changeRole: async (user, role, custom) =>
          !!detail && (await worked(() => changeRole(spaceDeps, detail, user, role, custom))),
        revoke: (user) =>
          detail
            ? change(() => offboardMember(spaceDeps, detail, user, 'revoke')).then((outcome) => {
                if (outcome) setOffboarded({ name: nameOf(user), outcome });
                return outcome !== undefined;
              })
            : Promise.resolve(false),
        restore: (user) => void change(() => api.restore(spaceId, user)),
        remove: (user) =>
          detail
            ? change(() => offboardMember(spaceDeps, detail, user, 'remove')).then((outcome) => {
                if (outcome) setOffboarded({ name: nameOf(user), outcome });
                return outcome !== undefined;
              })
            : Promise.resolve(false),
        createCollection: async (name, parent) =>
          !!detail && (await worked(() => createCollection(spaceDeps, detail, parent ? { name, parent } : { name }))),
        renameCollection: async (id, name) =>
          !!detail && (await worked(() => renameCollection(spaceDeps, detail, id, name))),
        deleteCollection: async (id) =>
          !!detail && (await worked(() => deleteCollection(spaceDeps, detail, id))),
        createGroup: async (name, members) =>
          !!detail && (await worked(() => createGroup(spaceDeps, detail, { name, members }))),
        setGroupMembers: async (id, members) =>
          !!detail && (await worked(() => setGroupMembers(spaceDeps, detail, id, members))),
        deleteGroup: async (id) =>
          !!detail && (await worked(() => deleteGroup(spaceDeps, detail, id))),
        grant: (collection, grantee, permission) => {
          if (!detail) return;
          void change(() => grantAccess(spaceDeps, detail, { collection, grantee, permission }));
        },
        revokeGrant: (collection, grantee) => {
          if (!detail) return;
          void change(() => revokeGrant(spaceDeps, detail, collection, grantee));
        },
      }}
    />
  );
}
