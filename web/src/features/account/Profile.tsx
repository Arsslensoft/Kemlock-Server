import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { createProfileApi } from '@/api/profile';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { describeError } from '@/lib/errors';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { type IdentityNotice, type PasswordNotice, ProfileView } from './ProfileView';
import { type ProfileDeps, changePassword, requestEmailChange } from './profileModel';
import { useRun } from './useRun';

const profileApi = createProfileApi(api);
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
  const identity = useRun();
  const password = useRun();
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
      actions={{
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
            await changePassword(deps, { email: current.email, ...input });
            return true;
          });
          if (done) setPasswordNotice(input.signOutOthers ? 'changedOthers' : 'changed');
          return done === true;
        },
      }}
    />
  );
}
