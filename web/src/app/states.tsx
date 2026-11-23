import { Link, type ErrorComponentProps, useRouter } from '@tanstack/react-router';
import { NetworkError } from '@/api/errors';
import { useT } from '@/i18n';
import { AuthPage } from '@/ui/AuthPage';
import { Button, buttonClass } from '@/ui/Button';
import { Notice } from '@/ui/Notice';

export function PendingScreen() {
  const t = useT();
  return (
    <div className="auth-page" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span className="sr">{t('state.loading')}</span>
    </div>
  );
}

/** A route failed to load or a guard failed: usually the server isn't reachable. */
export function RouteError({ error, reset }: ErrorComponentProps) {
  const t = useT();
  const router = useRouter();
  const offline = error instanceof NetworkError;
  return (
    <AuthPage>
      <div>
        <h1>{t(offline ? 'state.offline.title' : 'state.error.title')}</h1>
        <p className="lede">{t(offline ? 'state.offline.body' : 'state.error.body')}</p>
      </div>
      <Notice tone="error" live>
        <span className="mono">{error instanceof Error ? error.message : String(error)}</span>
      </Notice>
      <Button
        variant="primary"
        size="large"
        block
        onPress={() => {
          reset();
          void router.invalidate();
        }}
      >
        {t('action.retry')}
      </Button>
    </AuthPage>
  );
}

export function NotFound() {
  const t = useT();
  return (
    <AuthPage>
      <div>
        <h1>{t('state.notFound.title')}</h1>
        <p className="lede">{t('state.notFound.body')}</p>
      </div>
      <Link to="/" className={buttonClass({ variant: 'primary', size: 'large', block: true })}>
        {t('state.notFound.home')}
      </Link>
    </AuthPage>
  );
}
