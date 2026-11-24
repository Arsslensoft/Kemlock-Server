// ICU messages (FormatJS) keyed by message id. The ids are the keys of en.json; Kemlock's
// translations carry over by id. `t` is typed, so an unknown id is a compile error.
import { Children, type ReactNode, useCallback } from 'react';
import { IntlProvider, useIntl } from 'react-intl';
import en from './en.json';
import about from './en.about.json';
import account from './en.account.json';
import admin from './en.admin.json';
import tools from './en.tools.json';
import keyItems from './en.keyItems.json';

// One catalogue per area, so areas built side by side never edit the same file. An id lives in
// exactly one of them (the catalogue test checks it).
export const catalogues = { en, about, account, admin, tools, keyItems } as const;

export type MessageId =
  | keyof typeof en
  | keyof typeof about
  | keyof typeof account
  | keyof typeof admin
  | keyof typeof tools
  | keyof typeof keyItems;
export type Values = Record<string, string | number>;

export const messages: Record<string, string> = { ...en, ...about, ...account, ...admin, ...tools, ...keyItems };

export function I18nProvider({ children }: { children: ReactNode }) {
  return (
    <IntlProvider
      locale="en"
      defaultLocale="en"
      messages={messages}
      onError={(error) => {
        // A missing translation falls back to the id; a malformed message is a bug to see.
        if (String(error.code) !== 'MISSING_TRANSLATION') console.error(error);
      }}
    >
      {children}
    </IntlProvider>
  );
}

/** Plain text for an id: `t('signIn.title')`. */
export function useT(): (id: MessageId, values?: Values) => string {
  const intl = useIntl();
  return useCallback((id, values) => intl.formatMessage({ id }, values), [intl]);
}

/** Text with `<b>`, `<code>` and `<mono>` tags in the message, as React nodes. */
export function useRich(): (id: MessageId, values?: Values) => ReactNode {
  const intl = useIntl();
  return useCallback(
    (id, values) =>
      Children.toArray(
        intl.formatMessage(
          { id },
          {
            ...values,
            b: (chunks: ReactNode[]) => <b>{chunks}</b>,
            code: (chunks: ReactNode[]) => <code className="mono">{chunks}</code>,
            mono: (chunks: ReactNode[]) => <span className="mono">{chunks}</span>,
          },
        ),
      ),
    [intl],
  );
}
