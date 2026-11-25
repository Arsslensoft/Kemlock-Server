import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { createDevicesApi } from '@/api/devices';
import { signOut } from '@/app/actions';
import { api, configQuery, session } from '@/app/services';
import { useSessionState } from '@/app/session';
import { encodeB64 } from '@/lib/b64url';
import { uuidBytes } from '@/sharing/bundle';
import { sharingCrypto } from '@/sharing/crypto';
import { DevicesView } from './DevicesView';
import { approveRequest, leaveThisBrowser, loadApprovals, otherDevices } from './devicesModel';
import { describeAccountError } from './errors';
import { useRun } from './useRun';

const devicesApi = createDevicesApi(api);

export default function Devices() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const state = useSessionState(session);
  const config = useQuery(configQuery);
  const approvals = useQuery({
    queryKey: ['devices', 'approvals'],
    queryFn: () => loadApprovals(devicesApi),
    refetchInterval: 10_000,
  });
  const devices = useQuery({ queryKey: ['devices', 'list'], queryFn: () => devicesApi.devices() });
  const keyCopy = useQuery({ queryKey: ['devices', 'key-copy'], queryFn: () => devicesApi.keyCopy() });
  const { run, pending, error } = useRun();
  // Set while this browser signs itself out, so nothing else is pressed meanwhile.
  const [leaving, setLeaving] = useState(false);

  async function change<T>(action: () => Promise<T>): Promise<void> {
    await run(action);
    await queryClient.invalidateQueries({ queryKey: ['devices'] });
  }

  // The address the server is set up with, which is what an app needs. The page's own address is
  // not a stand-in: behind a proxy it may be another one, so Connect waits for the answer.
  const address = config.data?.domain;

  return (
    <DevicesView
      address={address}
      addressFailed={config.isError}
      approvals={approvals.data}
      approvalsError={approvals.error ? describeAccountError(approvals.error) : undefined}
      others={
        devices.data === undefined
          ? devices.isError
            ? null
            : undefined
          : devices.data === null
            ? null
            : otherDevices(devices.data, state.deviceId)
      }
      keyCopy={keyCopy.data}
      cryptoAvailable={sharingCrypto.available}
      trustAvailable={sharingCrypto.available && sharingCrypto.canWrapForThisDevice !== false}
      busy={pending || leaving}
      error={error}
      onApprove={(row) => {
        const account = state.userId;
        if (!account) return;
        void change(() => approveRequest({ api: devicesApi, crypto: sharingCrypto }, row, account));
      }}
      onDeny={(id) => void change(() => devicesApi.deny(id))}
      onSignOut={(device) => void change(() => devicesApi.signOut(device.id))}
      onSignOutThisBrowser={() => {
        if (leaving) return;
        const device = state.deviceId;
        setLeaving(true);
        void (async () => {
          try {
            await leaveThisBrowser(
              {
                signOutDevice: (id) => devicesApi.signOut(id),
                endSession: signOut,
                goToSignIn: () => navigate({ to: '/sign-in' }),
              },
              device,
            );
          } finally {
            setLeaving(false);
          }
        })();
      }}
      onSignOutOthers={() => {
        const list = devices.data ? otherDevices(devices.data, state.deviceId) : [];
        void change(async () => {
          for (const device of list) await devicesApi.signOut(device.id);
        });
      }}
      onTrust={() => {
        const account = state.userId;
        const device = state.deviceId;
        if (!account || !device) return;
        void change(async () => {
          const wrapped = await sharingCrypto.wrapForThisDevice({
            accountId: uuidBytes(account),
            deviceId: uuidBytes(device),
            keyVersion: (await api.accountKeys()).keyVersion,
          });
          await devicesApi.putKeyCopy({ wrappedKey: encodeB64(wrapped), protection: 'web-crypto' });
        });
      }}
      onUntrust={() => void change(() => devicesApi.deleteKeyCopy())}
      onUntrustDevice={(device) => void change(() => devicesApi.untrustDevice(device.id))}
    />
  );
}
