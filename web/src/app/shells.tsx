// The page frames: the vault's header and sidebar, and the admin console's. They are layout
// routes, so they stay mounted while the screens inside them change.
import {
  Link,
  Outlet,
  useLinkProps,
  useNavigate,
  useRouter,
  useRouterState,
  useSearch,
} from '@tanstack/react-router';
import { useKindCounts } from '@/features/vault/hooks';
import { KIND_ORDER, kindIcon, kindPluralLabel } from '@/features/vault/kinds';
import { FailoverBanner } from '@/features/failover/Banner';
import { useT } from '@/i18n';
import { Icon, type IconName, Wordmark } from '@/ui/Icon';
import { AccountMenu } from './AccountMenu';
import { NewItemMenu } from './NewItemMenu';
import { lockVault, signOut } from './actions';
import { session } from './services';
import { initials, isKindActive, withQuery } from './shellNav';
import { useSessionState } from './session';
import { useAccountName } from './useAccountName';

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

/**
 * "All items" and one link per type: the vault list filtered by kind. Which one is current depends
 * on the path and the kind only; the search box, the page and the favourites filter must not turn
 * the highlight off, so it is not the router's own match (which compares the whole search).
 */
function KindLink({ kind, icon, count, children }: { kind?: string; icon: IconName; count: number; children: string }) {
  const props = useLinkProps({ to: '/vault', search: kind ? { kind } : {} });
  const active = useRouterState({
    select: (s) =>
      isKindActive(s.location.pathname, (s.location.search as { kind?: unknown }).kind, kind),
  });
  return (
    <a
      {...props}
      aria-current={active ? 'page' : undefined}
      data-status={active ? 'active' : undefined}
    >
      <Item icon={icon} count={count}>
        {children}
      </Item>
    </a>
  );
}

export function VaultShell() {
  const t = useT();
  const navigate = useNavigate();
  const router = useRouter();
  const state = useSessionState(session);
  useAccountName(state);
  const search = useSearch({ strict: false }) as { q?: string };
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { total, byKind, trashed } = useKindCounts();
  const name = state.name?.trim() || state.email || '';
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
              // On the list, typing refines it in place: the filters stay and one history entry is
              // reused. From any other page the first letter leaves it, as a step Back can undo.
              if (pathname === '/vault') {
                void navigate({ to: '/vault', search: (previous) => withQuery(previous, q), replace: true });
              } else {
                void navigate({ to: '/vault', search: q === '' ? {} : { q } });
              }
            }}
          />
        </div>
        <div className="right">
          <NewItemMenu />
          <AccountMenu
            initials={initials(state.name, state.email)}
            name={name}
            subtitle={state.name?.trim() ? (state.email ?? '') : ''}
          >
            {(close) => (
              <>
                <Link to="/profile" activeOptions={{ exact: true }} onClick={close}>
                  <Icon name="user" />
                  {t('shell.menu.profile')}
                </Link>
                <Link to="/security" activeOptions={{ exact: true }} onClick={close}>
                  <Icon name="shield" />
                  {t('nav.security')}
                </Link>
                <Link to="/devices" activeOptions={{ exact: true }} onClick={close}>
                  <Icon name="device" />
                  {t('nav.devices')}
                </Link>
                {state.admin ? (
                  <Link to="/admin" activeOptions={{ exact: true }} onClick={close}>
                    <Icon name="server" />
                    {t('nav.admin')}
                    <span className="popup-tag">{t('shell.menu.adminTag')}</span>
                  </Link>
                ) : null}
                <Link to="/about" activeOptions={{ exact: true }} onClick={close}>
                  <Icon name="info" />
                  {t('about.link')}
                </Link>
                <div className="popup-sep" role="separator" />
                <button
                  type="button"
                  onClick={() => {
                    close();
                    // The unlock screen brings the person back to the page they locked from.
                    const next = router.state.location.href;
                    void lockVault().then(() => navigate({ to: '/unlock', search: { next } }));
                  }}
                >
                  <Icon name="lock" />
                  {t('action.lock')}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    close();
                    void signOut().then(() => navigate({ to: '/sign-in' }));
                  }}
                >
                  <Icon name="logout" />
                  {t('action.signOut')}
                </button>
              </>
            )}
          </AccountMenu>
        </div>
      </header>
      <div className="shell-body">
        <nav className="nav" aria-label={t('shell.nav.vault')}>
          <h2>{t('shell.nav.vault')}</h2>
          <KindLink icon="items" count={total}>
            {t('nav.all')}
          </KindLink>
          {KIND_ORDER.map((kind) => (
            <KindLink key={kind} kind={kind} icon={kindIcon(kind)} count={byKind[kind] ?? 0}>
              {t(kindPluralLabel(kind))}
            </KindLink>
          ))}
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
            <Item icon="trash" count={trashed}>{t('nav.trash')}</Item>
          </Link>
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
  const state = useSessionState(session);
  useAccountName(state);
  const name = state.name?.trim() || state.email || '';
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
          <AccountMenu
            tone="amber"
            initials={initials(state.name, state.email)}
            name={name}
            subtitle={t('shell.menu.adminSub', { email: state.email ?? '' })}
          >
            {(close) => (
              <>
                <Link to="/vault" onClick={close}>
                  <Icon name="lock" />
                  {t('admin.openVault')}
                </Link>
                <Link to="/about" activeOptions={{ exact: true }} onClick={close}>
                  <Icon name="info" />
                  {t('about.link')}
                </Link>
                <div className="popup-sep" role="separator" />
                <button
                  type="button"
                  onClick={() => {
                    close();
                    void signOut().then(() => navigate({ to: '/sign-in' }));
                  }}
                >
                  <Icon name="logout" />
                  {t('action.signOut')}
                </button>
              </>
            )}
          </AccountMenu>
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
          <Link to="/admin/fields" activeOptions={{ exact: true }}>
            <Item icon="fields">{t('admin.fields')}</Item>
          </Link>
          <h2>{t('admin.nav.federation')}</h2>
          <Link to="/admin/federation">
            <Item icon="globe">{t('admin.federation')}</Item>
          </Link>
          <h2>{t('admin.nav.data')}</h2>
          <Link to="/admin/migrate" activeOptions={{ exact: true }}>
            <Item icon="move">{t('admin.migrate')}</Item>
          </Link>
        </nav>
        <main id="main" className="page" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
