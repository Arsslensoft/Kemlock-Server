// The route list is the design canvas's flow map. Every screen is its own chunk, loaded when
// its route is: the sign-in screen carries no vault code, and members never download the admin
// console. Guards live in `beforeLoad`, before any chunk is fetched.
import type { QueryClient } from '@tanstack/react-query';
import {
  type RouterHistory,
  Outlet,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  lazyRouteComponent,
  redirect,
} from '@tanstack/react-router';
import { z } from 'zod';
import type { ConfigResponse } from '@/api/types';
import { safeNext } from '@/lib/safe-next';
import { configQuery } from './services';
import type { Session } from './session';
import { NotFound, PendingScreen, RouteError } from './states';

export interface RouterContext {
  queryClient: QueryClient;
  session: Session;
}

const optionalString = z
  .union([z.string(), z.number()])
  .transform(String)
  .optional()
  .catch(undefined);

// Search parameters are typed by hand, so every key is optional and a link needs no `search`.
interface NextSearch {
  next?: string;
}
interface PasswordSearch {
  email?: string;
  next?: string;
}
interface VaultSearch {
  kind?: string;
  q?: string;
  page?: number;
  fav?: boolean;
}
interface SsoSearch {
  code?: string;
  state?: string;
  error?: string;
}
interface NewItemSearch {
  kind?: 'login' | 'note';
}

const nextSearch = z.object({ next: optionalString });
const passwordSearch = z.object({ email: optionalString, next: optionalString });
const ssoSearch = z.object({ code: optionalString, state: optionalString, error: optionalString });
const vaultSearch = z.object({
  kind: optionalString,
  q: optionalString,
  page: z.number().int().min(1).optional().catch(undefined),
  fav: z.boolean().optional().catch(undefined),
});
const newItemSearch = z.object({ kind: z.enum(['login', 'note']).optional().catch(undefined) });

const rootRoute = createRootRouteWithContext<RouterContext>()({
  beforeLoad: async ({ context, location }) => {
    const config: ConfigResponse = await context.queryClient.fetchQuery(configQuery);
    const path = location.pathname;
    // Anyone can read about the server, whatever state setup is in.
    if (path === '/about') return { config };
    const inSetup = path.startsWith('/setup');
    switch (config.setup) {
      case 'needs-admin':
        // Nobody can sign in yet: everything leads to the setup code.
        if (path !== '/setup' && path !== '/setup/admin') throw redirect({ to: '/setup' });
        break;
      case 'pending':
        // The admin exists and still owes a two-step method.
        if (path === '/setup' || path === '/setup/admin') throw redirect({ to: '/setup/two-step' });
        break;
      case 'complete':
        if (inSetup && path !== '/setup/done') throw redirect({ to: '/sign-in' });
        break;
    }
    return { config };
  },
  component: Outlet,
  pendingComponent: PendingScreen,
  errorComponent: RouteError,
  notFoundComponent: NotFound,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: ({ context }) => {
    if (context.config.setup === 'needs-admin') throw redirect({ to: '/setup' });
    const status = context.session.getState().status;
    throw redirect({ to: status === 'unlocked' ? '/vault' : status === 'locked' ? '/unlock' : '/sign-in' });
  },
});

// ---- About ---------------------------------------------------------------------------------

/** The licence, the source and the notices: public, so it needs no sign-in and no vault. */
const about = createRoute({
  getParentRoute: () => rootRoute,
  path: '/about',
  component: lazyRouteComponent(() => import('@/features/about/About')),
});

// ---- First-run setup ----------------------------------------------------------------------

/** Steps after the admin account exists need that admin signed in with the vault open. */
function needsAdminSession({ context, location }: { context: RouterContext; location: { href: string } }) {
  const status = context.session.getState().status;
  if (status === 'locked') throw redirect({ to: '/unlock', search: { next: location.href } });
  if (status === 'signed-out') throw redirect({ to: '/sign-in', search: { next: location.href } });
}

const setupCode = createRoute({
  getParentRoute: () => rootRoute,
  path: '/setup',
  component: lazyRouteComponent(() => import('@/features/setup/SetupCode')),
});
const setupAdmin = createRoute({
  getParentRoute: () => rootRoute,
  path: '/setup/admin',
  component: lazyRouteComponent(() => import('@/features/setup/SetupAdmin')),
});
const setupTwoStep = createRoute({
  getParentRoute: () => rootRoute,
  path: '/setup/two-step',
  beforeLoad: needsAdminSession,
  component: lazyRouteComponent(() => import('@/features/setup/SetupTwoStep')),
});
const setupServer = createRoute({
  getParentRoute: () => rootRoute,
  path: '/setup/server',
  beforeLoad: needsAdminSession,
  component: lazyRouteComponent(() => import('@/features/setup/SetupServer')),
});
const setupDone = createRoute({
  getParentRoute: () => rootRoute,
  path: '/setup/done',
  component: lazyRouteComponent(() => import('@/features/setup/SetupDone')),
});

// ---- Signing in ---------------------------------------------------------------------------

/**
 * A sign-in screen has nothing to do once the vault is open (Back from the vault lands on one): it
 * leads on to the page asked for, if that is a path on this origin, or to the vault.
 */
function leaveWhenUnlocked({ context, search }: { context: RouterContext; search: { next?: string | undefined } }) {
  if (context.session.getState().status !== 'unlocked') return;
  const target = safeNext(search.next);
  throw redirect(target ? { href: target } : { to: '/vault' });
}

const signIn = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sign-in',
  validateSearch: (search): NextSearch => nextSearch.parse(search),
  beforeLoad: (args) => {
    leaveWhenUnlocked(args);
    // Signed in with the vault shut: the master password opens it, there is no one to sign in.
    if (args.context.session.getState().status === 'locked') {
      throw redirect({ to: '/unlock', search: { next: args.search.next } });
    }
  },
  component: lazyRouteComponent(() => import('@/features/auth/SignInScreen')),
});
const password = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sign-in/password',
  validateSearch: (search): PasswordSearch => passwordSearch.parse(search),
  beforeLoad: (args) => {
    leaveWhenUnlocked(args);
    if (!args.search.email) throw redirect({ to: '/sign-in', search: { next: args.search.next } });
  },
  component: lazyRouteComponent(() => import('@/features/auth/Password')),
});
const deviceApproval = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sign-in/device',
  validateSearch: (search): PasswordSearch => passwordSearch.parse(search),
  beforeLoad: (args) => {
    leaveWhenUnlocked(args);
    if (!args.search.email) throw redirect({ to: '/sign-in', search: { next: args.search.next } });
  },
  component: lazyRouteComponent(() => import('@/features/auth/DeviceApproval')),
});
const ssoReturn = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sign-in/sso',
  validateSearch: (search): SsoSearch => ssoSearch.parse(search),
  // The one-time code was spent: Back to this address must not replay it.
  beforeLoad: ({ context }) => {
    if (context.session.getState().status === 'unlocked') throw redirect({ to: '/vault' });
  },
  component: lazyRouteComponent(() => import('@/features/auth/SsoReturn')),
});
const unlock = createRoute({
  getParentRoute: () => rootRoute,
  path: '/unlock',
  validateSearch: (search): NextSearch => nextSearch.parse(search),
  beforeLoad: ({ context, search }) => {
    const status = context.session.getState().status;
    if (status === 'signed-out') throw redirect({ to: '/sign-in' });
    leaveWhenUnlocked({ context, search });
  },
  component: lazyRouteComponent(() => import('@/features/auth/Unlock')),
});

// ---- The vault ----------------------------------------------------------------------------

const vaultLayout = createRoute({
  getParentRoute: () => rootRoute,
  id: '_vault',
  beforeLoad: ({ context, location }) => {
    const status = context.session.getState().status;
    if (status === 'locked') throw redirect({ to: '/unlock', search: { next: location.href } });
    if (status === 'signed-out') {
      throw redirect({ to: '/sign-in', search: { next: location.href } });
    }
  },
  component: lazyRouteComponent(() => import('./shells'), 'VaultShell'),
});

const main = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/vault',
  validateSearch: (search): VaultSearch => vaultSearch.parse(search),
  component: lazyRouteComponent(() => import('@/features/vault/Main')),
});
const newItem = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/vault/new',
  validateSearch: (search): NewItemSearch => newItemSearch.parse(search),
  component: lazyRouteComponent(() => import('@/features/vault/NewItem')),
});
const item = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/vault/$itemId',
  component: lazyRouteComponent(() => import('@/features/vault/Item')),
});
const editItem = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/vault/$itemId/edit',
  component: lazyRouteComponent(() => import('@/features/vault/NewItem')),
});
const trash = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/trash',
  component: lazyRouteComponent(() => import('@/features/vault/Trash')),
});
const devices = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/devices',
  component: lazyRouteComponent(() => import('@/features/account/Devices')),
});
const security = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/security',
  component: lazyRouteComponent(() => import('@/features/account/Security')),
});

// Screens added after the first slice. Their components read params with `useParams({ strict: false })`,
// so nothing here depends on a route id.
const spaces = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/spaces',
  component: lazyRouteComponent(() => import('@/features/spaces/SpaceList')),
});
const space = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/spaces/$spaceId',
  component: lazyRouteComponent(() => import('@/features/spaces/SpaceDetail')),
});
const send = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/send',
  component: lazyRouteComponent(() => import('@/features/send/Send')),
});
const importExport = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/import-export',
  component: lazyRouteComponent(() => import('@/features/import/ImportExport')),
});
const duplicates = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/duplicates',
  component: lazyRouteComponent(() => import('@/features/duplicates/Duplicates')),
});
const duplicateMerge = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/duplicates/$groupId',
  component: lazyRouteComponent(() => import('@/features/duplicates/DuplicateMerge')),
});
const itemWebsites = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/vault/$itemId/websites',
  component: lazyRouteComponent(() => import('@/features/vault/ItemWebsites')),
});
const health = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/health',
  component: lazyRouteComponent(() => import('@/features/health/Health')),
});
const storage = createRoute({
  getParentRoute: () => vaultLayout,
  path: '/storage',
  component: lazyRouteComponent(() => import('@/features/failover/Storage')),
});

// ---- Admin console ------------------------------------------------------------------------

const adminLayout = createRoute({
  getParentRoute: () => rootRoute,
  id: '_admin',
  beforeLoad: ({ context, location }) => {
    const state = context.session.getState();
    if (state.status === 'locked') throw redirect({ to: '/unlock', search: { next: location.href } });
    if (state.status === 'signed-out') {
      throw redirect({ to: '/sign-in', search: { next: location.href } });
    }
    if (!state.admin) throw redirect({ to: '/vault' });
  },
  component: lazyRouteComponent(() => import('./shells'), 'AdminShell'),
});
const adminOverview = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin',
  component: lazyRouteComponent(() => import('@/features/admin/Overview')),
});
const adminUsers = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/users',
  component: lazyRouteComponent(() => import('@/features/admin/Users')),
});
const adminEvents = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/events',
  component: lazyRouteComponent(() => import('@/features/admin/Events')),
});
const adminSettings = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/settings',
  component: lazyRouteComponent(() => import('@/features/admin/Settings')),
});

const adminSso = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/sso',
  component: lazyRouteComponent(() => import('@/features/admin/Sso')),
});
const adminMigrate = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/migrate',
  component: lazyRouteComponent(() => import('@/features/admin/Migrate')),
});
const adminFederation = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/federation',
  component: lazyRouteComponent(() => import('@/features/admin/Federation')),
});
const adminPair = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/federation/pair',
  component: lazyRouteComponent(() => import('@/features/admin/Pair')),
});
const adminPeerSecurity = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/federation/security',
  component: lazyRouteComponent(() => import('@/features/admin/PeerSecurity')),
});
const adminKeyMismatch = createRoute({
  getParentRoute: () => adminLayout,
  path: '/admin/federation/mismatch/$peerId',
  component: lazyRouteComponent(() => import('@/features/admin/KeyMismatch')),
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  about,
  setupCode,
  setupAdmin,
  setupTwoStep,
  setupServer,
  setupDone,
  signIn,
  password,
  deviceApproval,
  ssoReturn,
  unlock,
  vaultLayout.addChildren([
    main,
    newItem,
    item,
    editItem,
    itemWebsites,
    trash,
    devices,
    security,
    spaces,
    space,
    send,
    importExport,
    duplicates,
    duplicateMerge,
    health,
    storage,
  ]),
  adminLayout.addChildren([
    adminOverview,
    adminUsers,
    adminEvents,
    adminSettings,
    adminSso,
    adminMigrate,
    adminFederation,
    adminPair,
    adminPeerSecurity,
    adminKeyMismatch,
  ]),
]);

export function createAppRouter(context: RouterContext, history?: RouterHistory) {
  return createRouter({
    routeTree,
    ...(history ? { history } : {}),
    context,
    defaultPreload: 'intent',
    defaultPendingMs: 250,
    defaultPendingComponent: PendingScreen,
    defaultNotFoundComponent: NotFound,
    scrollRestoration: true,
  });
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
