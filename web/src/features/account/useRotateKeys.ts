import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { tokensFromResponse } from '@/api/client';
import { ApiError, isApiError } from '@/api/errors';
import { createPasskeysApi } from '@/api/passkeys';
import { createRotationApi } from '@/api/rotation';
import { createSendsApi } from '@/api/sends';
import { api, session } from '@/app/services';
import { useSessionState } from '@/app/session';
import { vaultCrypto } from '@/crypto-port';
import '@/local/stores';
import { assertWithPasskeyAndPrf } from '@/lib/passkey';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { manifestKeeper } from '@/manifest/instance';
import { describeProfileError } from './profileErrors';
import type { RotateDone, RotateImpact, RotateKeysProps } from './RotateKeysCard';
import {
  type RotationDeps,
  type RotationProgress,
  readdPasskeyUnlock,
  RotationBlockedError,
  RotationPasswordError,
  rotateKeys,
} from './rotationModel';
import { useKeyProof } from './useKeyProof';
import { useRun } from './useRun';
import type { Described } from './errors';

const rotationApi = createRotationApi(api);
const sendsApi = createSendsApi(api);
const passkeysApi = createPasskeysApi(api);
const planKey = ['security', 'rotation-plan'] as const;

/** What the person is told of a failure of the rotation: its own cases first. */
function describeRotation(error: unknown): Described {
  if (error instanceof RotationPasswordError) return { id: 'profile.error.wrong' };
  if (error instanceof RotationBlockedError) {
    if (error.reason === 'spaces') return { id: 'security.rotate.blocked.spaces' };
    if (error.reason === 'compatible') return { id: 'security.rotate.blocked.compatible' };
    return { id: 'security.rotate.error.items' };
  }
  if (isApiError(error, 'rotation-incomplete')) return { id: 'security.rotate.error.incomplete' };
  if (isApiError(error, 'spaces-need-rekey')) return { id: 'security.rotate.blocked.spaces' };
  return describeProfileError(error);
}

/** "Rotate account keys" on Account security: the plan the server gives, and the rotation itself. */
export function useRotateKeys(email: string, twoStep: boolean) {
  const queryClient = useQueryClient();
  const state = useSessionState(session);
  const plan = useQuery({
    queryKey: planKey,
    queryFn: () => rotationApi.plan(),
    retry: false,
    enabled: email !== '',
  });
  // Each emergency contact's fingerprint, worked out here from the bundle the server serves now.
  const contacts = useQuery({
    queryKey: ['security', 'rotation-contacts', plan.dataUpdatedAt],
    enabled: plan.data !== undefined,
    queryFn: async () =>
      Promise.all(
        (plan.data?.emergency ?? []).flatMap((grant) =>
          grant.granteeBundle
            ? [
                (async () => ({
                  id: grant.id,
                  email: grant.granteeEmail ?? '',
                  bundle: grant.granteeBundle as string,
                  fingerprint: await vaultCrypto.fingerprint(decodeB64(grant.granteeBundle as string)),
                }))(),
              ]
            : [],
        ),
      ),
  });
  const { run, pending, error } = useRun(describeRotation);
  const keyProof = useKeyProof(run);
  const [progress, setProgress] = useState<RotationProgress | null>(null);
  const [done, setDone] = useState<RotateDone | null>(null);
  /** The passkeys whose unlock the last rotation removed, with the credential to touch for each. */
  const [removed, setRemoved] = useState<Array<{ id: string; credentialId: string }>>([]);

  const planError = plan.error instanceof ApiError ? plan.error : undefined;
  const blocked: RotateKeysProps['blocked'] =
    planError?.slug === 'compatible-account' ? 'compatible' : (plan.data?.spaces ?? 0) > 0 ? 'spaces' : null;
  const impact: RotateImpact | undefined = plan.data
    ? {
        contacts: contacts.data ?? [],
        passkeys: plan.data.passkeys.length,
        emergency: plan.data.emergency.length,
        recovery: plan.data.recovery.length,
        hasKit: plan.data.kit !== null,
        hasPassword: plan.data.hasPassword,
      }
    : undefined;

  const props: RotateKeysProps = {
    impact,
    blocked,
    twoStep,
    keyProof,
    busy: pending,
    progress,
    done,
    actions: {
      askProof: () =>
        api
          .send({ method: 'POST', path: '/kem/v1/account/two-factor/proof' })
          .then(() => true)
          .catch(() => false),
      dismiss: () => setDone(null),
      readdPasskey: async (id) => {
        const target = removed.find((passkey) => passkey.id === id);
        if (!target) return false;
        const kept = await run(() =>
          readdPasskeyUnlock({ api: passkeysApi, crypto: vaultCrypto, assert: assertWithPasskeyAndPrf }, target).then(
            () => true,
          ),
        );
        if (kept) await queryClient.invalidateQueries({ queryKey: ['security', 'passkeys'] });
        return kept === true;
      },
      start: async ({ password, makeKit, emergencyKeep, proof }) => {
        const { userId, deviceId } = state;
        if (!userId || !deviceId) return false;
        const deps: RotationDeps = {
          api: {
            ...rotationApi,
            prelogin: api.prelogin,
            opaqueStart: api.opaqueStart,
            sync: api.sync,
          },
          sends: sendsApi,
          crypto: vaultCrypto,
          userId,
          deviceId,
        };
        setProgress({ phase: 'plan', done: 0, total: 1 });
        const result = await run(() =>
          rotateKeys(
            deps,
            { email, password, makeKit, emergencyKeep, ...(proof !== undefined ? { proof } : {}) },
            setProgress,
          ),
        );
        setProgress(null);
        if (!result) return false;
        // The new security stamp ended this device's tokens: carry on with the ones it was given.
        if (result.tokens) session.tokenStore.set(tokensFromResponse(result.tokens, Date.now()));
        // This tab's reload copy is for the old key version: make it again, or the next reload asks.
        try {
          const sealed = await vaultCrypto.deviceCopySeal(userId, deviceId, result.keyVersion, session.tabId());
          session.sealedRoot.set({ sealed: encodeB64(sealed), keyVersion: result.keyVersion });
        } catch {
          session.sealedRoot.clear();
        }
        // The old manifest was signed by the old key: sign the next with the new one, listing the
        // re-encrypted items, so the next sync does not flag them.
        try {
          await manifestKeeper.wrote(result.rewritten);
          await manifestKeeper.flush();
        } catch {
          // The keeper shows a failed publish itself, and tries again after the next write.
        }
        setRemoved(result.removed.passkeys);
        const names = new Map<string, string>();
        try {
          for (const passkey of await passkeysApi.list()) names.set(passkey.id, passkey.name);
        } catch {
          // Without the names the list says "Passkey".
        }
        setDone({
          fingerprint: result.fingerprint,
          kit: result.kit,
          removed: result.removed,
          passkeys: result.removed.passkeys.map((passkey) => ({
            id: passkey.id,
            name: names.get(passkey.id) ?? 'Passkey',
          })),
        });
        await queryClient.invalidateQueries();
        return true;
      },
    },
  };
  return { props, error };
}
