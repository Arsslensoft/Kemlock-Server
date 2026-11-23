import { ApiError } from '@/api/errors';

/** An ApiError as the server's RFC 9457 body would make it. */
export function ApiErrorFixture(
  status: number,
  slug: string,
  extra: Record<string, unknown> = {},
): ApiError {
  return new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: slug, status, ...extra });
}
