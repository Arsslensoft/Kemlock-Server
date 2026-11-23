// A fresh check before every admin write (crates/kemlock-api-admin: each write needs a step-up
// token). The server answers a write 403 `step-up-required` unless it carries a token from `POST
// /admin/v1/step-up/totp` (src/api/admin.ts). `useReauth().guard` runs the action with the token it
// holds; on that answer it asks for an authenticator code once, then runs the action again. The
// passkey route (`step-up/passkey/options` and `/finish`) is offered beside the code when the browser
// has WebAuthn; the password route (`step-up/password/*`, two OPAQUE messages) is in the client but
// not offered here.
import { type ReactNode, useCallback, useRef, useState } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import type { AdminApi } from '@/api/admin';
import { isApiError } from '@/api/errors';
import { useT } from '@/i18n';
import { type Described, describeError } from '@/lib/errors';
import { PasskeyError, assertWithPasskey, passkeysAvailable } from '@/lib/passkey';
import { normaliseCode } from '@/lib/schemas';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
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

/** The dialog: a code from the authenticator app, or a passkey. No network of its own. */
export function ReauthDialogView({
  isOpen,
  pending,
  error,
  onSubmit,
  onPasskey,
  onCancel,
}: {
  isOpen: boolean;
  pending?: boolean;
  error?: Described | undefined;
  onSubmit: (code: string) => void;
  /** Present when a passkey can be asked for: the step-up dialog offers it beside the code. */
  onPasskey?: (() => void) | undefined;
  onCancel: () => void;
}) {
  const t = useT();
  const [code, setCode] = useState('');
  const valid = /^\d{6}$/.test(normaliseCode(code));
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
              if (valid) onSubmit(normaliseCode(code));
            }}
          >
            <p className="muted">{t('admin.reauth.body')}</p>
            <TextBox
              label={t('admin.reauth.code')}
              value={code}
              onChange={setCode}
              mono
              autoComplete="one-time-code"
            />
            {error ? (
              <Notice tone="error" live>
                <p>{t(error.id, error.values)}</p>
              </Notice>
            ) : null}
            <div className="actions">
              <Button onPress={onCancel}>{t('action.cancel')}</Button>
              {onPasskey ? (
                <Button isDisabled={pending} onPress={onPasskey}>
                  {t('admin.reauth.passkey')}
                </Button>
              ) : null}
              <Button type="submit" variant="primary" isDisabled={!valid || pending}>
                {t('admin.reauth.confirm')}
              </Button>
            </div>
          </form>
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}

/** The words for a passkey that did not answer; anything else is described as everywhere else. */
function describePasskeyError(error: unknown): Described {
  if (error instanceof PasskeyError) {
    return { id: error.reason === 'cancelled' ? 'admin.reauth.passkeyCancelled' : 'admin.reauth.passkeyUnavailable' };
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

/** `guard(fn)` runs `fn(grant)`, asking for a code first only if the server says it must. */
export function useReauth(
  api: Pick<AdminApi, 'stepUpTotp'> & Partial<Pick<AdminApi, 'stepUpPasskeyOptions' | 'stepUpPasskeyFinish'>>,
  passkey: { available: () => boolean; assert: typeof assertWithPasskey } = {
    available: passkeysAvailable,
    assert: assertWithPasskey,
  },
): {
  guard: <T>(action: (grant: string | undefined) => Promise<T>) => Promise<T>;
  dialog: ReactNode;
} {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Described>();
  const waiter = useRef<Waiter | undefined>(undefined);

  const ask = useCallback(
    () =>
      new Promise<string>((resolve, reject) => {
        waiter.current = { resolve, reject };
        setError(undefined);
        setOpen(true);
      }),
    [],
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

  const granted = (result: { token: string; expiresAt: number }) => {
    rememberGrant(result.token, result.expiresAt);
    setOpen(false);
    waiter.current?.resolve(result.token);
    waiter.current = undefined;
  };

  const dialog = (
    <ReauthDialogView
      isOpen={open}
      pending={pending}
      error={error}
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
      onPasskey={
        api.stepUpPasskeyOptions && api.stepUpPasskeyFinish && passkey.available()
          ? () => {
              const { stepUpPasskeyOptions, stepUpPasskeyFinish } = api;
              if (!stepUpPasskeyOptions || !stepUpPasskeyFinish) return;
              setPending(true);
              setError(undefined);
              stepUpPasskeyOptions()
                .then(async ({ options, challenge }) =>
                  stepUpPasskeyFinish(challenge, await passkey.assert(options)),
                )
                .then(granted)
                .catch((caught: unknown) => setError(describePasskeyError(caught)))
                .finally(() => setPending(false));
            }
          : undefined
      }
    />
  );

  return { guard, dialog };
}
