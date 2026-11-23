import type { ProblemBody } from './types';

const PROBLEM_PREFIX = 'urn:kemlock:problem:';

/** A non-2xx answer from the server, read from its RFC 9457 problem body. */
export class ApiError extends Error {
  readonly status: number;
  /** The problem type without its `urn:kemlock:problem:` prefix, e.g. `setup-code-wrong`. */
  readonly slug: string;
  readonly detail: string | undefined;
  readonly problem: ProblemBody | undefined;

  constructor(status: number, problem: ProblemBody | undefined, fallback?: string) {
    const slug = problem?.type?.startsWith(PROBLEM_PREFIX)
      ? problem.type.slice(PROBLEM_PREFIX.length)
      : 'unknown';
    super(problem?.title ?? fallback ?? `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.slug = slug;
    this.detail = problem?.detail;
    this.problem = problem;
  }

  /** Seconds to wait after a 429, when the server said. */
  get retryAfter(): number | undefined {
    const value = this.problem?.['retryAfter'];
    return typeof value === 'number' ? value : undefined;
  }

  /** The revision on the server after a 409 `stale-revision`; null when the item isn't there. */
  get currentRevision(): number | null | undefined {
    const value = this.problem?.['currentRevision'];
    return typeof value === 'number' || value === null ? value : undefined;
  }
}

/** The server couldn't be reached at all (offline, wrong address, blocked). */
export class NetworkError extends Error {
  constructor(cause: unknown) {
    super('The server could not be reached');
    this.name = 'NetworkError';
    this.cause = cause;
  }
}

export function isApiError(error: unknown, slug?: string): error is ApiError {
  return error instanceof ApiError && (slug === undefined || error.slug === slug);
}
