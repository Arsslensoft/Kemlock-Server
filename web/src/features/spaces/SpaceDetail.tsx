import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { useState } from 'react';
import type { MemberViewDto, OffboardedDto } from '@/api/spaces';
import { decodeB64 } from '@/lib/b64url';
import { type Fingerprint, checkedFingerprint } from '@/sharing/bundle';
import { vaultCrypto } from '@/crypto-port';
import { describeAccountError } from '../account/errors';
import { useRun } from '../account/useRun';
import { spaceDeps, spacesKey } from './deps';
import {
  type SpaceDetail as Detail,
  confirmMember,
  createCollection,
  createGroup,
  grantAccess,
  inviteMember,
  loadSpaceDetail,
  renameCollection,
  setGroupMembers,
} from './model';
import { type ConfirmState, SpaceDetailView } from './SpaceDetailView';

export default function SpaceDetail() {
  const { spaceId = '' } = useParams({ strict: false }) as { spaceId?: string };
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const key = ['spaces', spaceId] as const;
  const query = useQuery({ queryKey: key, queryFn: () => loadSpaceDetail(spaceDeps, spaceId) });
  const { run, pending, error } = useRun();
  const [confirming, setConfirming] = useState<ConfirmState | null>(null);
  const [offboarded, setOffboarded] = useState<{ name: string; outcome: OffboardedDto } | null>(null);
  const detail: Detail | undefined = query.data;
  const { api } = spaceDeps;

  /** Runs a change, then reads the space again. */
  async function change<T>(action: () => Promise<T>): Promise<T | undefined> {
    const result = await run(action);
    if (result !== undefined) {
      await queryClient.invalidateQueries({ queryKey: key });
      await queryClient.invalidateQueries({ queryKey: spacesKey });
    }
    return result;
  }

  function nameOf(user: string): string {
    const member = detail?.members.find((m) => m.user === user);
    return member ? member.name || member.email : user;
  }

  async function startConfirm(member: MemberViewDto) {
    setConfirming({ member, fingerprint: undefined });
    let fingerprint: Fingerprint | null = null;
    try {
      fingerprint = await checkedFingerprint(decodeB64(member.publicBundle), (bundle) =>
        vaultCrypto.fingerprint(bundle),
      );
    } catch {
      fingerprint = null;
    }
    setConfirming({ member, fingerprint });
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
        invite: (input) => void change(() => inviteMember(spaceDeps, spaceId, input)),
        accept: () => void change(() => api.accept(spaceId, 'me')),
        startConfirm: (member) => void startConfirm(member),
        cancelConfirm: () => setConfirming(null),
        confirm: () => {
          const current = confirming;
          if (!detail || !current?.fingerprint) return;
          const member = current.member;
          const fingerprint = current.fingerprint;
          void change(() => confirmMember(spaceDeps, detail, member, fingerprint)).then((done) => {
            if (done) setConfirming(null);
          });
        },
        changeRole: (user, role, custom) => void change(() => api.changeRole(spaceId, user, role, custom)),
        revoke: (user) =>
          void change(() => api.revoke(spaceId, user)).then((outcome) => {
            if (outcome) setOffboarded({ name: nameOf(user), outcome });
          }),
        restore: (user) => void change(() => api.restore(spaceId, user)),
        remove: (user) =>
          void change(() => api.remove(spaceId, user)).then((outcome) => {
            if (outcome) setOffboarded({ name: nameOf(user), outcome });
          }),
        createCollection: (name, parent) => {
          if (!detail) return;
          void change(() => createCollection(spaceDeps, detail, parent ? { name, parent } : { name }));
        },
        renameCollection: (id, name) => {
          if (!detail) return;
          void change(() => renameCollection(spaceDeps, detail, id, name));
        },
        deleteCollection: (id) => void change(() => api.deleteCollection(spaceId, id).then(() => true)),
        createGroup: (name, members) => {
          if (!detail) return;
          void change(() => createGroup(spaceDeps, detail, { name, members }));
        },
        setGroupMembers: (id, members) => {
          if (!detail) return;
          void change(() => setGroupMembers(spaceDeps, detail, id, members));
        },
        deleteGroup: (id) => void change(() => api.deleteGroup(spaceId, id).then(() => true)),
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
