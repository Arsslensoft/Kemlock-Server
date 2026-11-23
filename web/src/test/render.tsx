import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider } from '@/i18n';

export function renderWithIntl(ui: ReactElement) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

/** A minimal fetch response, for the API client's tests. */
export function jsonResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const status = init.status ?? 200;
  return new Response(status === 204 || status === 304 ? null : JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json',
      ...init.headers,
    },
  });
}

export function problem(
  status: number,
  slug: string,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Response {
  return jsonResponse(
    { type: `urn:kemlock:problem:${slug}`, title: slug, status, ...extra },
    { status, headers },
  );
}
