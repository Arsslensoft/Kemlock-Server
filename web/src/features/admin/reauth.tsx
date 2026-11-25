// A fresh check before every admin write (crates/kemlock-api-admin: each write needs a step-up
// token). The server answers a write 403 `step-up-required` unless it carries a token from `POST
// /admin/v1/step-up/totp` or `step-up/passkey/*` (src/api/admin.ts). `useReauth().guard` runs the
// action with the token it holds; on that answer it asks once, then runs the action again.
//
// It asks only for what the account has (stepUpMethods.ts): the code field when the authenticator
// app is on, a passkey or security key when there is one and the browser has WebAuthn (the server
// takes both on the passkey route). With no app, the browser's prompt opens at once. The password
// route (`step-up/password/*`, two OPAQUE messages) is in the client but not offered here.
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import type { AdminApi } from '@/api/admin';
import { isApiError } from '@/api/errors';
import { useT } from '@/i18n';
import { type Described, describeError } from '@/lib/errors';
import { PasskeyError, assertWithPasskey, passkeysAvailable } from '@/lib/passkey';
import { normaliseCode } from '@/lib/schemas';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import type { StepUpMethods } from './stepUpMethods';
import { TextBox } from './ui';

let held: { grant: string; until: number } | undefined;

/** The grant to send, if one is still good (a minute is kept in hand). */
export function currentGrant(now = Date.now()): string | undefined {
  return held && held.until - 60_000 > now ? held.grant : undefined;
}

/** Keeps a token until `expiresAtSeconds`, the Unix time the server says it stops working. */
export function rememberGrant(grant: string, expiresAtSeconds: number): void {
  held = { grant, until: expiresAtSeconds * 1000 };
}

export function forgetGrant(): void {
  held = undefined;
}

/**
 * The dialog: a code from the authenticator app, a passkey, or both, as the account has them.
 * `code` false hides the code field (no authenticator app is on); `onPasskey` absent hides the
 * passkey. `loading` shows while the ways are looked up. No network of its own.
 */
export function ReauthDialogView({
  isOpen,
  pending,
  loading,
  error,
  code: codeOffered = true,
  keyLabel = 'admin.reauth.passkey',
  onSubmit,
  onPasskey,
  onCancel,
}: {
  isOpen: boolean;
  pending?: boolean;
  loading?: boolean;
  error?: Described | undefined;
  /** Whether the authenticator app is on, so a code can be typed. */
  code?: boolean;
  /** The words on the WebAuthn button: a passkey, a security key, or either. */
  keyLabel?: 'admin.reauth.passkey' | 'admin.reauth.securityKey' | 'admin.reauth.passkeyOrKey';
  onSubmit: (code: string) => void;
  /** Present when a passkey can be asked for. */
  onPasskey?: (() => void) | undefined;
  onCancel: () => void;
}) {
  const t = useT();
  const [code, setCode] = useState('');
  // The view stays mounted while closed, so each opening starts empty rather than with the last code.
  useEffect(() => {
    if (isOpen) setCode('');
  }, [isOpen]);
  const valid = /^\d{6}$/.test(normaliseCode(code));
  const body = loading
    ? 'admin.reauth.loading'
    : codeOffered && onPasskey
      ? 'admin.reauth.body'
      : codeOffered
        ? 'admin.reauth.bodyCode'
        : onPasskey
          ? 'admin.reauth.bodyPasskey'
          : undefined;
  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={(open) => {
        if (!open) onCancel();
      }}
      isDismissable
      className="overlay"
    >
      <Modal>
        <Dialog className="dialog">
          <Heading slot="title">{t('admin.reauth.title')}</Heading>
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              if (codeOffered && valid) onSubmit(normaliseCode(code));
            }}
          >
            {body ? (
              <p className="muted" role={loading ? 'status' : undefined}>
                {t(body)}
              </p>
            ) : (
              <Notice tone="error">
                <p>{t('admin.reauth.none')}</p>
              </Notice>
            )}
            {codeOffered && !loading ? (
              <TextBox
                label={t('admin.reauth.code')}
                value={code}
                onChange={setCode}
                mono
                autoComplete="one-time-code"
              />
            ) : null}
            {error ? (
              <Notice tone="error" live>
                <p>{t(error.id, error.values)}</p>
              </Notice>
            ) : null}
            <div className="actions">
              <Button onPress={onCancel}>{t('action.cancel')}</Button>
              {onPasskey && !loading ? (
                <Button isDisabled={pending} variant={codeOffered ? 'default' : 'primary'} onPress={onPasskey}>
                  {t(keyLabel)}
                </Button>
              ) : null}
              {codeOffered && !loading ? (
                <Button type="submit" variant="primary" isDisabled={!valid || pending}>
                  {t('admin.reauth.confirm')}
                </Button>
              ) : null}
            </div>
          </form>
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}

/**
 * The words for a passkey that did not answer; anything else is described as everywhere else.
 * With no code to fall back on, the words do not point at one.
 */
function describePasskeyError(error: unknown, codeOffered: boolean): Described {
  if (error instanceof PasskeyError) {
    const cancelled = error.reason === 'cancelled';
    if (codeOffered) return { id: cancelled ? 'admin.reauth.passkeyCancelled' : 'admin.reauth.passkeyUnavailable' };
    return { id: cancelled ? 'admin.reauth.passkeyCancelledOnly' : 'admin.reauth.passkeyUnavailableOnly' };
  }
  return describeError(error);
}

export class ReauthCancelled extends Error {
  constructor() {
    super('The check was cancelled');
    this.name = 'ReauthCancelled';
  }
}

interface Waiter {
  resolve: (grant: string) => void;
  reject: (error: unknown) => void;
}

/** Looked up only when a check is needed, so the hook's tests can hand in their own. */
const loadMethods = (): Promise<StepUpMethods> => import('./stepUpMethods').then((m) => m.loadStepUpMethods());

/** `guard(fn)` runs `fn(grant)`, asking first only if the server says it must. */
export function useReauth(
  api: Pick<AdminApi, 'stepUpTotp'> & Partial<Pick<AdminApi, 'stepUpPasskeyOptions' | 'stepUpPasskeyFinish'>>,
  passkey: { available: () => boolean; assert: typeof assertWithPasskey } = {
    available: passkeysAvailable,
    assert: assertWithPasskey,
  },
  methods: () => Promise<StepUpMethods> = loadMethods,
): {
  guard: <T>(action: (grant: string | undefined) => Promise<T>) => Promise<T>;
  dialog: ReactNode;
} {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Described>();
  const [ways, setWays] = useState<StepUpMethods>();
  const waiter = useRef<Waiter | undefined>(undefined);

  const granted = useCallback((result: { token: string; expiresAt: number }) => {
    rememberGrant(result.token, result.expiresAt);
    setOpen(false);
    waiter.current?.resolve(result.token);
    waiter.current = undefined;
  }, []);

  const canPasskey = Boolean(api.stepUpPasskeyOptions && api.stepUpPasskeyFinish && passkey.available());

  const askPasskey = useCallback(
    (codeOffered: boolean) => {
      const { stepUpPasskeyOptions, stepUpPasskeyFinish } = api;
      if (!stepUpPasskeyOptions || !stepUpPasskeyFinish) return;
      setPending(true);
      setError(undefined);
      stepUpPasskeyOptions()
        .then(async ({ options, challenge }) => stepUpPasskeyFinish(challenge, await passkey.assert(options)))
        .then(granted)
        .catch((caught: unknown) => setError(describePasskeyError(caught, codeOffered)))
        .finally(() => setPending(false));
    },
    [api, passkey, granted],
  );

  const ask = useCallback(
    () =>
      new Promise<string>((resolve, reject) => {
        waiter.current = { resolve, reject };
        setError(undefined);
        setWays(undefined);
        setOpen(true);
        methods()
          // If the lookup fails, offer both rather than nothing; the server still decides.
          .catch((): StepUpMethods => ({ totp: true, passkey: true, securityKey: false }))
          .then((found) => {
            if (!waiter.current) return;
            setWays(found);
            // A passkey is the only way: open the browser's prompt instead of making them press for it.
            if ((found.passkey || found.securityKey) && !found.totp && canPasskey) askPasskey(false);
          });
      }),
    [methods, canPasskey, askPasskey],
  );

  const guard = useCallback(
    async <T,>(action: (grant: string | undefined) => Promise<T>): Promise<T> => {
      try {
        return await action(currentGrant());
      } catch (caught) {
        if (!isApiError(caught, 'step-up-required')) throw caught;
        const grant = await ask();
        return action(grant);
      }
    },
    [ask],
  );

  const codeOffered = ways?.totp ?? false;
  const dialog = (
    <ReauthDialogView
      isOpen={open}
      pending={pending}
      loading={!ways}
      error={error}
      code={codeOffered}
      onCancel={() => {
        setOpen(false);
        waiter.current?.reject(new ReauthCancelled());
        waiter.current = undefined;
      }}
      onSubmit={(code) => {
        setPending(true);
        api
          .stepUpTotp(code)
          .then(granted)
          .catch((caught: unknown) => setError(describeError(caught)))
          .finally(() => setPending(false));
      }}
      keyLabel={
        ways?.securityKey
          ? ways.passkey
            ? 'admin.reauth.passkeyOrKey'
            : 'admin.reauth.securityKey'
          : 'admin.reauth.passkey'
      }
      onPasskey={(ways?.passkey || ways?.securityKey) && canPasskey ? () => askPasskey(codeOffered) : undefined}
    />
  );

  return { guard, dialog };
}
