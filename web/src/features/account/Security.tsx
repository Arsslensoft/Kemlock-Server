import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useRef, useState } from 'react';
import { createEmergencyApi, type GrantViewDto } from '@/api/emergency';
import { createPasskeysApi } from '@/api/passkeys';
import { createTwoStepApi, enabledMethods } from '@/api/twoStep';
import { api, hostOf, session, configQuery } from '@/app/services';
import { useSessionState } from '@/app/session';
import { useT } from '@/i18n';
import { vaultCrypto } from '@/crypto-port';
import { decodeB64 } from '@/lib/b64url';
import { passkeysAvailable } from '@/lib/passkey';
import { type PreparedPasskey, preparePasskey } from '@/lib/webauthn';
import { type Fingerprint, checkedFingerprint } from '@/sharing/bundle';
import { sharingCrypto } from '@/sharing/crypto';
import type { EmergencyConfirmState } from './EmergencyCard';
import { confirmEmergencyContact } from './emergencyModel';
import { useApiKey } from './useApiKey';
import { useDeleteAccount } from './useDeleteAccount';
import { useRecoveryKit } from './useRecoveryKit';
import { useRotateKeys } from './useRotateKeys';
import { useRun } from './useRun';
import { useSecondSteps } from './useSecondSteps';
import { useSignedWrites } from './useSignedWrites';
import { SecurityView, type TotpState } from './SecurityView';

const emergencyApi = createEmergencyApi(api);
const passkeysApi = createPasskeysApi(api);
const twoStepApi = createTwoStepApi(api);

/** How long a made passkey is kept for another try: the server's registration lasts five minutes. */
const PREPARED_PASSKEY_MS = 4 * 60 * 1000;

export default function Security() {
  const t = useT();
  const queryClient = useQueryClient();
  const state = useSessionState(session);
  const config = useQuery(configQuery);
  const email = state.email ?? '';
  const twoStepList = useQuery({
    queryKey: ['security', 'methods', email],
    queryFn: () => twoStepApi.list(),
    enabled: email !== '',
  });
  const methods = twoStepList.data ? enabledMethods(twoStepList.data) : undefined;
  const passkeys = useQuery({ queryKey: ['security', 'passkeys'], queryFn: () => passkeysApi.list() });
  const passkeyRun = useRun();
  // The passkey made for the proof being asked for, so a wrong code is retried without the
  // authenticator being touched again.
  const preparedPasskey = useRef<{ made: PreparedPasskey; at: number } | null>(null);
  const overview = useQuery({ queryKey: ['security', 'emergency'], queryFn: () => emergencyApi.overview() });
  const [totp, setTotp] = useState<TotpState>({ open: false, enrol: undefined });
  const totpRun = useRun();
  const { run, pending, error } = useRun();
  const secondSteps = useSecondSteps(twoStepList.data?.recoveryCodes, methods?.includes('totp') ?? false);
  const recoveryKit = useRecoveryKit();
  const rotation = useRotateKeys(email, (methods?.length ?? 0) > 0);
  const apiKey = useApiKey();
  const signedWrites = useSignedWrites(email, (methods?.length ?? 0) > 0);
  const navigate = useNavigate();
  const deleteAccount = useDeleteAccount(email, (methods?.length ?? 0) > 0, () => void navigate({ to: '/sign-in' }));
  const [confirming, setConfirming] = useState<EmergencyConfirmState | null>(null);
  const [released, setReleased] = useState<{ grantor: string; kind: 'view' | 'takeover' } | null>(null);

  async function change<T>(action: () => Promise<T>): Promise<T | undefined> {
    const result = await run(action);
    await queryClient.invalidateQueries({ queryKey: ['security', 'emergency'] });
    return result;
  }

  async function changePasskeys<T>(action: () => Promise<T>): Promise<T | undefined> {
    const result = await passkeyRun.run(action);
    await queryClient.invalidateQueries({ queryKey: ['security', 'passkeys'] });
    return result;
  }

  async function startConfirm(view: GrantViewDto) {
    setConfirming({ view, fingerprint: undefined });
    let fingerprint: Fingerprint | null = null;
    try {
      fingerprint = view.contactKeys
        ? await checkedFingerprint(decodeB64(view.contactKeys.publicBundle), (bundle) =>
            vaultCrypto.fingerprint(bundle),
          )
        : null;
    } catch {
      fingerprint = null;
    }
    setConfirming({ view, fingerprint });
  }

  return (
    <SecurityView
      email={email}
      host={hostOf(config.data?.domain)}
      methods={methods}
      totp={totp}
      busy={
        pending ||
        totpRun.pending ||
        passkeyRun.pending ||
        secondSteps.props.busy ||
        recoveryKit.props.busy ||
        rotation.props.busy ||
        apiKey.props.busy ||
        deleteAccount.props.busy ||
        signedWrites.props.busy
      }
      error={
        error ??
        passkeyRun.error ??
        secondSteps.error ??
        recoveryKit.error ??
        rotation.error ??
        apiKey.error ??
        signedWrites.error ??
        deleteAccount.error
      }
      secondSteps={secondSteps.props}
      recoveryKit={recoveryKit.props}
      rotateKeys={rotation.props}
      apiKey={apiKey.props}
      signedWrites={signedWrites.props}
      deleteAccount={deleteAccount.props}
      totpError={totpRun.error}
      onStartTotp={() => {
        setTotp({ open: true, enrol: undefined });
        // Beside another second step that is on, adding the app asks for a mailed code too.
        if (methods?.some((m) => m !== 'totp')) void secondSteps.props.actions.askProof();
        void totpRun.run(() => api.totpEnrol()).then((enrol) => {
          if (enrol) setTotp({ open: true, enrol });
        });
      }}
      onCancelTotp={() => setTotp({ open: false, enrol: undefined })}
      onConfirmTotp={(code, proof) => {
        void totpRun.run(() => api.totpConfirm(code, proof).then(() => true)).then(async (done) => {
          if (!done) return;
          setTotp({ open: false, enrol: undefined });
          await queryClient.invalidateQueries({ queryKey: ['security', 'methods'] });
        });
      }}
      passkeys={
        passkeysAvailable()
          ? {
              passkeys: passkeys.data,
              busy: passkeyRun.pending,
              // A passkey signs in without the second step, so with one on it is added on a fresh proof.
              proofNeeded: (methods?.length ?? 0) > 0,
              keyProof: secondSteps.props.keyProof,
              // A code is mailed only beside a second step other than the app, as for the app itself.
              mailsCode: methods?.some((m) => m !== 'totp') ?? false,
              onAskProof: () => void secondSteps.props.actions.askProof(),
              onCancel: () => {
                preparedPasskey.current = null;
              },
              onAdd: (proof) =>
                changePasskeys(async () => {
                  // The proof is asked for first; the passkey is made once and stored again with a new
                  // proof if the server refuses the one given.
                  let held = preparedPasskey.current;
                  if (!held || Date.now() - held.at > PREPARED_PASSKEY_MS) {
                    held = {
                      made: await preparePasskey({ passkeys: passkeysApi, crypto: vaultCrypto }),
                      at: Date.now(),
                    };
                    preparedPasskey.current = held;
                  }
                  try {
                    const added = await held.made.register(t('security.passkeys.defaultName'), proof);
                    preparedPasskey.current = null;
                    return added;
                  } catch (error) {
                    // Without a proof there is nothing to retry: the server used the registration up.
                    if (proof === undefined) preparedPasskey.current = null;
                    throw error;
                  }
                }).then((added) => added !== undefined),
              onRemove: (id) => void changePasskeys(() => passkeysApi.remove(id).then(() => true)),
            }
          : undefined
      }
      emergency={{
        trustedContacts: overview.data?.trustedContacts,
        grantors: overview.data?.grantors,
        confirming,
        released,
        cryptoAvailable: sharingCrypto.available,
        busy: pending,
        actions: {
          invite: (input) => change(() => emergencyApi.invite(input)).then((made) => made !== undefined),
          revoke: (id) => void change(() => emergencyApi.revoke(id).then(() => true)),
          startConfirm: (view) => void startConfirm(view),
          cancelConfirm: () => setConfirming(null),
          confirm: () => {
            const current = confirming;
            if (!current?.fingerprint) return;
            const view = current.view;
            const fingerprint = current.fingerprint;
            void change(() =>
              confirmEmergencyContact({ api: emergencyApi, crypto: sharingCrypto }, view, fingerprint),
            ).then((done) => {
              if (done) setConfirming(null);
            });
          },
          approve: (id) => void change(() => emergencyApi.approve(id)),
          reject: (id) => void change(() => emergencyApi.reject(id)),
          accept: (id) => void change(() => emergencyApi.accept(id)),
          initiate: (id) => void change(() => emergencyApi.initiate(id)),
          getKey: (id) =>
            void change(() => emergencyApi.key(id)).then((release) => {
              if (!release) return;
              const view = overview.data?.grantors.find((g) => g.grant.id === id);
              setReleased({ grantor: view?.grantorEmail ?? release.grantorId, kind: release.kind });
            }),
        },
      }}
    />
  );
}
