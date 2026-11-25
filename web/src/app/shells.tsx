// The page frames: the vault's header and sidebar, and the admin console's. They are layout
// routes, so they stay mounted while the screens inside them change.
import { Link, Outlet, useNavigate, useSearch } from '@tanstack/react-router';
import { useVault } from '@/features/vault/hooks';
import { FailoverBanner } from '@/features/failover/Banner';
import { useT } from '@/i18n';
import { Icon, type IconName, Wordmark } from '@/ui/Icon';
import { buttonClass } from '@/ui/Button';
import { lockVault, signOut } from './actions';
import { session } from './services';
import { useSessionState } from './session';

function initials(name: string | null, email: string | null): string {
  const source = (name ?? email ?? '?').trim();
  const words = source.split(/[\s@.]+/).filter(Boolean);
  const letters = words.length > 1 ? `${words[0]?.[0] ?? ''}${words[1]?.[0] ?? ''}` : source.slice(0, 2);
  return letters.toUpperCase();
}

/** The icon, label and optional count inside a nav link. */
function Item({ icon, count, children }: { icon: IconName; count?: number; children: string }) {
  return (
    <>
      <Icon name={icon} />
      {children}
      {count !== undefined ? <span className="n">{count}</span> : null}
    </>
  );
}

export function VaultShell() {
  const t = useT();
  const navigate = useNavigate();
  const state = useSessionState(session);
  const search = useSearch({ strict: false }) as { q?: string };
  const { active, trashed } = useVault();
  const count = (kind: string) => active.filter((item) => item.kind === kind).length;
  return (
    <div className="shell">
      <a className="sr" href="#main">
        {t('shell.skip')}
      </a>
      <header className="shell-header">
        <Link to="/vault" className="logo">
          <Wordmark />
          <span className="tag-chip">{t('brand.server')}</span>
        </Link>
        <div className="search" role="search">
          <label className="sr" htmlFor="vault-search">
            {t('shell.search')}
          </label>
          <Icon name="search" />
          <input
            id="vault-search"
            type="search"
            placeholder={t('shell.searchPlaceholder')}
            value={search.q ?? ''}
            onChange={(event) => {
              const q = event.target.value;
              void navigate({ to: '/vault', search: { q: q === '' ? undefined : q }, replace: true });
            }}
          />
        </div>
        <div className="right">
          <Link to="/vault/new" className={buttonClass({ variant: 'primary' })}>
            <Icon name="plus" />
            {t('action.newItem')}
          </Link>
          <Link
            to="/security"
            className="avatar"
            aria-label={t('shell.account', {
              initials: initials(state.name, state.email),
              name: state.name ?? state.email ?? '',
            })}
          >
            {initials(state.name, state.email)}
          </Link>
        </div>
      </header>
      <div className="shell-body">
        <nav className="nav" aria-label={t('shell.nav.vault')}>
          <h2>{t('shell.nav.vault')}</h2>
          <Link to="/vault" activeOptions={{ exact: true }}>
            <Item icon="items" count={active.length}>{t('nav.all')}</Item>
          </Link>
          <Link to="/vault" search={{ kind: 'login' }} activeOptions={{ exact: true }}>
            <Item icon="login" count={count('login')}>{t('nav.logins')}</Item>
          </Link>
          <Link to="/vault" search={{ kind: 'note' }} activeOptions={{ exact: true }}>
            <Item icon="note" count={count('note')}>{t('nav.notes')}</Item>
          </Link>
          <h2>{t('shell.nav.spaces')}</h2>
          <Link to="/spaces">
            <Item icon="building">{t('nav.spaces')}</Item>
          </Link>
          <h2>{t('shell.nav.tools')}</h2>
          <Link to="/send" activeOptions={{ exact: true }}>
            <Item icon="send">{t('nav.send')}</Item>
          </Link>
          <Link to="/health" activeOptions={{ exact: true }}>
            <Item icon="pulse">{t('nav.health')}</Item>
          </Link>
          <Link to="/duplicates">
            <Item icon="copy">{t('nav.duplicates')}</Item>
          </Link>
          <Link to="/import-export" activeOptions={{ exact: true }}>
            <Item icon="transfer">{t('nav.importExport')}</Item>
          </Link>
          <Link to="/storage" activeOptions={{ exact: true }}>
            <Item icon="server">{t('nav.storage')}</Item>
          </Link>
          <Link to="/trash" activeOptions={{ exact: true }}>
            <Item icon="trash" count={trashed.length}>{t('nav.trash')}</Item>
          </Link>
          <h2>{t('shell.nav.account')}</h2>
          <Link to="/security" activeOptions={{ exact: true }}>
            <Item icon="shield">{t('nav.security')}</Item>
          </Link>
          <Link to="/devices" activeOptions={{ exact: true }}>
            <Item icon="device">{t('nav.devices')}</Item>
          </Link>
          <Link to="/about" activeOptions={{ exact: true }}>
            <Item icon="info">{t('about.link')}</Item>
          </Link>
          {state.admin ? (
            <Link to="/admin" activeOptions={{ exact: true }}>
            <Item icon="server">{t('nav.admin')}</Item>
          </Link>
          ) : null}
          <button
            type="button"
            onClick={() => {
              void lockVault().then(() => navigate({ to: '/unlock' }));
            }}
          >
            <Icon name="lock" />
            {t('action.lock')}
          </button>
          <button
            type="button"
            onClick={() => {
              void signOut().then(() => navigate({ to: '/sign-in' }));
            }}
          >
            <Icon name="logout" />
            {t('action.signOut')}
          </button>
        </nav>
        <main id="main" className="page" tabIndex={-1}>
          <FailoverBanner />
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function AdminShell() {
  const t = useT();
  const navigate = useNavigate();
  return (
    <div className="shell">
      <a className="sr" href="#main">
        {t('shell.skip')}
      </a>
      <header className="shell-header">
        <Link to="/admin" className="logo">
          <Wordmark />
          <span className="tag-chip amber">{t('brand.admin')}</span>
        </Link>
        <div className="right">
          <Link to="/vault">{t('admin.openVault')}</Link>
          <button
            type="button"
            className="btn s"
            onClick={() => {
              void signOut().then(() => navigate({ to: '/sign-in' }));
            }}
          >
            {t('admin.signOut')}
          </button>
        </div>
      </header>
      <div className="shell-body">
        <nav className="nav" aria-label={t('admin.nav')}>
          <h2>{t('admin.nav.server')}</h2>
          <Link to="/admin" activeOptions={{ exact: true }}>
            <Item icon="grid">{t('admin.overview')}</Item>
          </Link>
          <Link to="/admin/users" activeOptions={{ exact: true }}>
            <Item icon="users">{t('admin.users')}</Item>
          </Link>
          <Link to="/admin/events" activeOptions={{ exact: true }}>
            <Item icon="list">{t('admin.events')}</Item>
          </Link>
          <h2>{t('admin.nav.settings')}</h2>
          <Link to="/admin/sso" activeOptions={{ exact: true }}>
            <Item icon="signin">{t('admin.sso')}</Item>
          </Link>
          <Link to="/admin/settings" activeOptions={{ exact: true }}>
            <Item icon="settings">{t('admin.settings')}</Item>
          </Link>
          <h2>{t('admin.nav.federation')}</h2>
          <Link to="/admin/federation">
            <Item icon="globe">{t('admin.federation')}</Item>
          </Link>
          <h2>{t('admin.nav.data')}</h2>
          <Link to="/admin/migrate" activeOptions={{ exact: true }}>
            <Item icon="move">{t('admin.migrate')}</Item>
          </Link>
          <h2>{t('about.nav')}</h2>
          <Link to="/about" activeOptions={{ exact: true }}>
            <Item icon="info">{t('about.link')}</Item>
          </Link>
        </nav>
        <main id="main" className="page" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
