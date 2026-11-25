// The login's "Websites" list: an address and a match rule on each row, add and remove. The
// rule sets how closely an address must match for autofill to offer the login.
import { useId } from 'react';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { type MatchRule, ruleLabel } from '../websites';
import { RULE_CHOICES, type SiteRow, newSiteRow, siteProblem } from './siteRows';

interface Props {
  value: SiteRow[];
  onChange: (next: SiteRow[]) => void;
  /** Show what each row needs fixed (after a Save that was refused). */
  showProblems?: boolean;
}

export function WebsitesEditor({ value, onChange, showProblems }: Props) {
  const t = useT();
  const id = useId();
  const change = (key: string, patch: Partial<Pick<SiteRow, 'uri' | 'match'>>) =>
    onChange(value.map((row) => (row.key === key ? { ...row, ...patch } : row)));
  return (
    <div className="field">
      <span id={`${id}-h`} className="fl">
        {t('itemForm.websites.title')}
      </span>
      <div role="group" aria-labelledby={`${id}-h`} className="cf-list">
        {value.map((row, index) => {
          const n = index + 1;
          const problem = showProblems ? siteProblem(row) : undefined;
          const choices: MatchRule[] = row.match === 'default' ? ['default', ...RULE_CHOICES] : RULE_CHOICES;
          return (
            <div key={row.key} className="field">
              <div className="cf-row">
                <label className="sr" htmlFor={`${id}-u${row.key}`}>
                  {t('itemForm.websites.website', { n })}
                </label>
                <input
                  id={`${id}-u${row.key}`}
                  className="site-uri"
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="https://"
                  value={row.uri}
                  aria-invalid={problem ? true : undefined}
                  onChange={(event) => change(row.key, { uri: event.target.value })}
                />
                <label className="sr" htmlFor={`${id}-m${row.key}`}>
                  {t('itemForm.websites.rule', { n })}
                </label>
                <select
                  id={`${id}-m${row.key}`}
                  className="site-rule"
                  value={row.match}
                  onChange={(event) => change(row.key, { match: event.target.value as MatchRule })}
                >
                  {choices.map((rule) => (
                    <option key={rule} value={rule}>
                      {t(ruleLabel(rule))}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  className="btn rm"
                  aria-label={t('itemForm.websites.remove', { n })}
                  onClick={() => onChange(value.filter((other) => other.key !== row.key))}
                >
                  <Icon name="close" />
                </button>
              </div>
              {problem ? (
                <span className="error" role="alert">
                  {t(problem)}
                </span>
              ) : null}
            </div>
          );
        })}
        <div>
          <Button size="small" onPress={() => onChange([...value, newSiteRow()])}>
            <Icon name="plus" />
            {t('itemForm.websites.add')}
          </Button>
        </div>
      </div>
      <span className="hint">{t('itemForm.websites.hint')}</span>
    </div>
  );
}
