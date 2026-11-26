// Locking the vault by itself. A vault left open on an unattended screen is open to whoever sits
// down at it, so two timers run while it is open:
//
//   - an idle timer: no key, click, touch or scroll for DEFAULT_IDLE_MINUTES;
//   - a hidden-tab timer: the tab has been out of sight for DEFAULT_HIDDEN_MINUTES. A tab in the
//     background is not being watched, so it gets less time than one the person is looking at.
//
// Both are cut down to the strictest session timeout among the person's spaces (`GET
// /kem/v1/policies`, which the server can't enforce itself: it never sees the vault open), and when
// that policy says `logOut` the session ends instead of locking. Timers in a hidden tab can run
// late, and a sleeping computer runs none, so the deadline is a time, checked again when the timer
// fires and when the tab comes back.
import type { PoliciesApi, PoliciesDto, TimeoutAction } from '@/api/policies';
import type { Session } from './session';

export const DEFAULT_IDLE_MINUTES = 15;
export const DEFAULT_HIDDEN_MINUTES = 5;

export interface AutoLockLimits {
  idleMs: number;
  hiddenMs: number;
  action: TimeoutAction;
}

/** The limits the defaults and the person's policy allow: the shorter of each, and the policy's action. */
export function limitsFor(
  policy?: Pick<PoliciesDto, 'sessionTimeoutMinutes' | 'sessionTimeoutAction'> | null,
): AutoLockLimits {
  const minutes = policy?.sessionTimeoutMinutes;
  const bound = typeof minutes === 'number' && Number.isFinite(minutes) && minutes > 0 ? minutes : undefined;
  const idle = Math.min(DEFAULT_IDLE_MINUTES, bound ?? DEFAULT_IDLE_MINUTES);
  const hidden = Math.min(DEFAULT_HIDDEN_MINUTES, idle);
  return {
    idleMs: idle * 60_000,
    hiddenMs: hidden * 60_000,
    action: policy?.sessionTimeoutAction === 'logOut' ? 'logOut' : 'lock',
  };
}

export interface AutoLockClock {
  /** The vault opened (or this page restored it open): the timers start. */
  start(limits: AutoLockLimits, hidden: boolean): void;
  /** The vault shut or the session ended: the timers stop. */
  stop(): void;
  /** The person did something. */
  activity(): void;
  /** The tab went out of sight or came back. */
  hidden(isHidden: boolean): void;
  setLimits(limits: AutoLockLimits): void;
  /** Whether a deadline has passed; the timer and a tab coming back call it. */
  check(): void;
}

export function createAutoLock(options: {
  expire: (action: TimeoutAction) => void;
  now?: () => number;
}): AutoLockClock {
  const now = options.now ?? (() => Date.now());
  let limits = limitsFor();
  let running = false;
  let lastActivity = 0;
  let hiddenSince: number | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  function deadline(): number {
    const idle = lastActivity + limits.idleMs;
    return hiddenSince === undefined ? idle : Math.min(idle, hiddenSince + limits.hiddenMs);
  }

  function check(): void {
    clearTimeout(timer);
    timer = undefined;
    if (!running) return;
    const left = deadline() - now();
    if (left <= 0) {
      running = false;
      options.expire(limits.action);
      return;
    }
    timer = setTimeout(check, left);
  }

  return {
    start(next, hidden) {
      limits = next;
      running = true;
      lastActivity = now();
      hiddenSince = hidden ? now() : undefined;
      check();
    },
    stop() {
      running = false;
      clearTimeout(timer);
      timer = undefined;
    },
    activity() {
      if (running) lastActivity = now();
    },
    hidden(isHidden) {
      if (!running) return;
      if (isHidden) {
        hiddenSince ??= now();
        check();
        return;
      }
      // Back in view. A page that was frozen in the background ran no timer, so the hidden limit may
      // have run out unseen: judge it while the time hidden still counts, then forget it.
      check();
      if (!running) return;
      hiddenSince = undefined;
      check();
    },
    setLimits(next) {
      limits = next;
      check();
    },
    check,
  };
}

const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'] as const;

/**
 * Runs the timers for as long as the vault is open, in this page. `expire` does what the policy
 * says (lock, or sign out) and goes where that leaves the person. Returns the function that stops it.
 */
export function startAutoLock(deps: {
  session: Pick<Session, 'getState' | 'subscribe'>;
  policies: Pick<PoliciesApi, 'mine'>;
  expire: (action: TimeoutAction) => void;
}): () => void {
  const clock = createAutoLock({ expire: deps.expire });
  const isHidden = () => document.visibilityState === 'hidden';
  let open = false;
  let epoch = 0;

  function sync(): void {
    const unlocked = deps.session.getState().status === 'unlocked';
    if (unlocked === open) return;
    open = unlocked;
    epoch += 1;
    if (!open) {
      clock.stop();
      return;
    }
    const mine = epoch;
    clock.start(limitsFor(), isHidden());
    // Until the policy comes, or if it never does, the defaults hold.
    deps.policies
      .mine()
      .then((policy) => {
        if (mine === epoch) clock.setLimits(limitsFor(policy));
      })
      .catch(() => undefined);
  }

  const onActivity = () => clock.activity();
  const onVisibility = () => clock.hidden(isHidden());
  for (const type of ACTIVITY_EVENTS) window.addEventListener(type, onActivity, { capture: true, passive: true });
  document.addEventListener('visibilitychange', onVisibility);
  const unsubscribe = deps.session.subscribe(sync);
  sync();

  return () => {
    unsubscribe();
    for (const type of ACTIVITY_EVENTS) window.removeEventListener(type, onActivity, { capture: true });
    document.removeEventListener('visibilitychange', onVisibility);
    clock.stop();
  };
}
