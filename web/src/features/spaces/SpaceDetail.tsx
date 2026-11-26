import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { useState } from 'react';
import type { MemberViewDto, OffboardedDto } from '@/api/spaces';
import { decodeB64 } from '@/lib/b64url';
import { type Fingerprint, checkedFingerprint } from '@/sharing/bundle';
import { vaultCrypto } from '@/crypto-port';
import { type Described, describeAccountError } from '../account/errors';
import { useRun } from '../account/useRun';
import { signedInAccount } from './boxes';
import { spaceDeps } from './deps';
import { acceptFirstContact } from './chain';
import { refreshSpaces } from './refresh';
import {
  type SpaceDetail as Detail,
  confirmMember,
  createCollection,
  createGroup,
  grantAccess,
  inviteMember,
  SpaceNotChecked,
  loadSpaceDetail,
  pinMember,
  renameCollection,
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
  const [offboarded, setOffboarded] = useState<{ name: string; outcome: OffboardedDto } | null>(null);
  const detail: Detail | undefined = query.data;
  const { api } = spaceDeps;

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
      cryptoAvailable={spaceDeps.crypto.available}
      onBack={() => void navigate({ to: '/spaces' })}
      actions={{
        invite: (input) => worked(() => inviteMember(spaceDeps, spaceId, input)),
        acceptFirstContact: () => {
          if (!detail) return;
          void change(() => acceptFirstContact(spaceDeps, spaceId, signedInAccount(spaceDeps, detail.view.me.user)));
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
              ? pinMember(spaceDeps, signedInAccount(spaceDeps, detail.view.me.user), member, fingerprint).then(() => true)
              : confirmMember(spaceDeps, detail, member, fingerprint);
          void change(act).then((done) => {
            if (done) setConfirming(null);
          });
        },
        changeRole: (user, role, custom) => worked(() => api.changeRole(spaceId, user, role, custom)),
        revoke: (user) =>
          change(() => api.revoke(spaceId, user)).then((outcome) => {
            if (outcome) setOffboarded({ name: nameOf(user), outcome });
            return outcome !== undefined;
          }),
        restore: (user) => void change(() => api.restore(spaceId, user)),
        remove: (user) =>
          change(() => api.remove(spaceId, user)).then((outcome) => {
            if (outcome) setOffboarded({ name: nameOf(user), outcome });
            return outcome !== undefined;
          }),
        createCollection: async (name, parent) =>
          !!detail && (await worked(() => createCollection(spaceDeps, detail, parent ? { name, parent } : { name }))),
        renameCollection: async (id, name) =>
          !!detail && (await worked(() => renameCollection(spaceDeps, detail, id, name))),
        deleteCollection: (id) => worked(() => api.deleteCollection(spaceId, id).then(() => true)),
        createGroup: async (name, members) =>
          !!detail && (await worked(() => createGroup(spaceDeps, detail, { name, members }))),
        setGroupMembers: async (id, members) =>
          !!detail && (await worked(() => setGroupMembers(spaceDeps, detail, id, members))),
        deleteGroup: (id) => worked(() => api.deleteGroup(spaceId, id).then(() => true)),
        grant: (collection, grantee, permission) => {
          if (!detail) return;
          void change(() => grantAccess(spaceDeps, detail, { collection, grantee, permission }));
        },
        revokeGrant: (collection, grantee) =>
          void change(() => api.revokeGrant(spaceId, collection, grantee).then(() => true)),
      }}
    />
  );
}
