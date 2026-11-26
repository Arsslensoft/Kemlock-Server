import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { tokensFromResponse } from '@/api/client';
import { createProfileApi } from '@/api/profile';
import { createSecondStepsApi } from '@/api/twoStep';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { describeError } from '@/lib/errors';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { type IdentityNotice, type PasswordNotice, ProfileView } from './ProfileView';
import { describeProfileError } from './profileErrors';
import { type ProfileDeps, changePassword, requestEmailChange } from './profileModel';
import { useKeyProof } from './useKeyProof';
import { useRun } from './useRun';

const profileApi = createProfileApi(api);
const stepsApi = createSecondStepsApi(api);
const profileKey = ['profile'] as const;

const deps: ProfileDeps = {
  api: {
    credentialsStart: profileApi.credentialsStart,
    changePassword: profileApi.changePassword,
    requestEmailChange: profileApi.requestEmailChange,
    prelogin: api.prelogin,
    opaqueStart: api.opaqueStart,
  },
  crypto: vaultCrypto,
};

/** Profile (`/profile`): the name, the address and the master password of the signed-in account. */
export default function Profile() {
  const t = useT();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: profileKey, queryFn: () => profileApi.get() });
  const identity = useRun(describeProfileError);
  const password = useRun(describeProfileError);
  // With a second step on, each card can answer its proof with a security key or passkey.
  const identityKeyProof = useKeyProof(identity.run);
  const passwordKeyProof = useKeyProof(password.run);
  const [identityNotice, setIdentityNotice] = useState<IdentityNotice | undefined>();
  const [passwordNotice, setPasswordNotice] = useState<PasswordNotice | undefined>();
  const profile = query.data;

  if (query.isPending) {
    return (
      <p className="empty" role="status">
        {t('profile.loading')}
      </p>
    );
  }
  if (!profile) {
    return (
      <Notice tone="error" live>
        <p>{t(describeError(query.error).id)}</p>
        <div>
          <Button size="small" onPress={() => void query.refetch()}>
            {t('action.retry')}
          </Button>
        </div>
      </Notice>
    );
  }
  const current = profile;

  return (
    <ProfileView
      profile={current}
      busy={identity.pending || password.pending}
      identityNotice={identityNotice}
      identityError={identity.error}
      passwordNotice={passwordNotice}
      passwordError={password.error}
      identityKeyProof={identityKeyProof}
      passwordKeyProof={passwordKeyProof}
      actions={{
        // Mail may be off or out of reach: then an authenticator code or the recovery code is the
        // proof, so a failed request is not an error on the screen.
        askProof: () =>
          stepsApi
            .proofRequest()
            .then(() => true)
            .catch(() => false),
        async saveIdentity(input) {
          setIdentityNotice(undefined);
          const notice = await identity.run(async (): Promise<IdentityNotice> => {
            let result: IdentityNotice = { kind: 'saved' };
            if (input.name !== undefined) {
              const renamed = await profileApi.rename(input.name);
              queryClient.setQueryData(profileKey, renamed);
              // The avatar and its menu read the name from the session.
              session.renamed(renamed.name);
            }
            if (input.email !== undefined) {
              const asked = await requestEmailChange(deps, {
                email: current.email,
                newEmail: input.email,
                current: input.password,
                ...(input.proof !== undefined ? { proof: input.proof } : {}),
              });
              await queryClient.invalidateQueries({ queryKey: profileKey });
              result = { kind: 'sent', email: asked.pendingEmail };
            }
            return result;
          });
          setIdentityNotice(notice);
          return notice !== undefined;
        },
        async cancelEmailChange() {
          setIdentityNotice(undefined);
          const done = await identity.run(async () => {
            await profileApi.cancelEmailChange();
            await queryClient.invalidateQueries({ queryKey: profileKey });
            return true;
          });
          if (done) setIdentityNotice({ kind: 'cancelled' });
          return done === true;
        },
        async changePassword(input) {
          setPasswordNotice(undefined);
          const done = await password.run(async () => {
            const changed = await changePassword(deps, { email: current.email, ...input });
            // Signing the other devices out changed the account's security stamp, which ended this
            // device's tokens with theirs: the answer holds the ones to go on with.
            if (changed.tokens) session.tokenStore.set(tokensFromResponse(changed.tokens, Date.now()));
            // A change of address asked for before is dropped with the old password.
            await queryClient.invalidateQueries({ queryKey: profileKey });
            return true;
          });
          if (done) setPasswordNotice(input.signOutOthers ? 'changedOthers' : 'changed');
          return done === true;
        },
      }}
    />
  );
}
