import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { z } from 'zod';
import type { AdminSpace, GroupRole, GroupRule, SsoConfig, SsoUpdate, VerifiedDomain } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { useReauth } from './reauth';
import { CheckBox, ErrorNotice, Loading, PageHead, SelectBox, TextBox, Toggle } from './ui';

/** What the form holds: the saved config, with the scopes as one line and a secret being typed. */
export interface SsoForm extends Omit<SsoUpdate, 'clientSecret' | 'clearClientSecret' | 'scopes'> {
  scopes: string;
  /** A new secret, typed. Empty keeps the stored one. */
  clientSecret: string;
  /** Remove the stored secret (a public client). */
  clearClientSecret: boolean;
}

export function formFrom(config: SsoConfig): SsoForm {
  return {
    enabled: config.enabled,
    displayName: config.displayName,
    issuer: config.issuer,
    clientId: config.clientId,
    clientSecret: '',
    clearClientSecret: false,
    scopes: config.scopes.join(' '),
    allowUnknownEmailVerification: config.allowUnknownEmailVerification,
    linkByEmail: config.linkByEmail,
    createAccounts: config.createAccounts,
    requireVerifiedDomain: config.requireVerifiedDomain,
    groupRules: config.groupRules,
  };
}

/** The body of the save: a secret only when one was typed, or when it is to be removed. */
export function updateFrom(form: SsoForm): SsoUpdate {
  const { clientSecret, clearClientSecret, scopes, ...rest } = form;
  const update: SsoUpdate = { ...rest, scopes: scopes.split(/\s+/).filter((scope) => scope !== '') };
  if (clientSecret !== '') update.clientSecret = clientSecret;
  else if (clearClientSecret) update.clearClientSecret = true;
  return update;
}

const ssoSchema = z.object({
  displayName: z.string().trim().min(1, 'error.required').max(60, 'error.tooLong'),
  issuer: z.url({ protocol: /^https?$/, message: 'error.url' }),
  clientId: z.string().trim().min(1, 'error.required'),
  scopes: z.string().refine((value) => value.split(/\s+/).includes('openid'), 'admin.sso.error.scopes'),
});

export type SsoErrors = Partial<Record<'displayName' | 'issuer' | 'clientId' | 'scopes', MessageId>>;

/** Checks the fields an enabled provider needs. A disabled one saves as it is. */
export function checkSso(form: SsoForm): SsoErrors {
  if (!form.enabled) return {};
  const result = ssoSchema.safeParse(form);
  if (result.success) return {};
  const errors: SsoErrors = {};
  for (const issue of result.error.issues) {
    const key = issue.path[0];
    if (key === 'displayName' || key === 'issuer' || key === 'clientId' || key === 'scopes') {
      errors[key] ??= issue.message as MessageId;
    }
  }
  return errors;
}

const ROLES: Array<[GroupRole, MessageId]> = [
  ['owner', 'admin.sso.role.owner'],
  ['admin', 'admin.sso.role.admin'],
  ['member', 'admin.sso.role.member'],
];

export interface SsoViewProps {
  config: SsoConfig;
  spaces: AdminSpace[];
  domains: VerifiedDomain[];
  saving?: boolean;
  saved?: boolean;
  error?: unknown;
  onSave: (update: SsoUpdate) => void;
  onAddDomain: (domain: string) => void;
  onVerifyDomain: (domain: string) => void;
  onRemoveDomain: (domain: string) => void;
}

export function SsoView({
  config,
  spaces,
  domains,
  saving,
  saved,
  error,
  onSave,
  onAddDomain,
  onVerifyDomain,
  onRemoveDomain,
}: SsoViewProps) {
  const t = useT();
  const [form, setForm] = useState<SsoForm>(() => formFrom(config));
  const [tried, setTried] = useState(false);
  const [domain, setDomain] = useState('');
  const saved0 = formFrom(config);
  const dirty = JSON.stringify(form) !== JSON.stringify(saved0);
  // Checked as it is typed: a field that changed shows its error at once, and every field does
  // once Save was tried. An error goes as soon as the value is right.
  const found = checkSso(form);
  const errors: SsoErrors = {};
  for (const key of Object.keys(found) as Array<keyof SsoErrors>) {
    if (tried || form[key] !== saved0[key] || form.enabled !== saved0.enabled) errors[key] = found[key];
  }
  const set = <K extends keyof SsoForm>(key: K, value: SsoForm[K]) => setForm((f) => ({ ...f, [key]: value }));
  const setRule = (index: number, patch: Partial<GroupRule>) =>
    set(
      'groupRules',
      form.groupRules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)),
    );

  function save(): void {
    setTried(true);
    if (Object.keys(found).length === 0) onSave(updateFrom(form));
  }

  function addDomain(): void {
    const value = domain.trim().toLowerCase();
    if (value === '' || domains.some((d) => d.domain === value)) return;
    onAddDomain(value);
    setDomain('');
  }

  return (
    <>
      <PageHead
        title={t('admin.sso')}
        lede={t('admin.sso.lede')}
        actions={
          <>
            {dirty ? (
              <Button
                onPress={() => {
                  setForm(formFrom(config));
                  setTried(false);
                }}
              >
                {t('admin.discard')}
              </Button>
            ) : null}
            <Button variant="primary" isDisabled={saving || !dirty} onPress={save}>
              {t('action.save')}
            </Button>
          </>
        }
      />
      {error ? <ErrorNotice error={error} /> : null}
      {saved && !dirty ? (
        <Notice tone="info" live>
          <p>{t('admin.saved')}</p>
        </Notice>
      ) : null}

      <div className="adm-split">
        <div className="adm-col">
          <section className="card" aria-labelledby="h-idp">
            <div className="adm-head">
              <h2 id="h-idp">{t('admin.sso.idp')}</h2>
              <Toggle label={t('admin.sso.on')} checked={form.enabled} onChange={(v) => set('enabled', v)} />
            </div>
            <div className="adm-pad">
              <div className="adm-g2">
                <TextBox label={t('admin.sso.protocol')} value="OpenID Connect" readOnly />
                <TextBox
                  label={t('admin.sso.name')}
                  value={form.displayName}
                  onChange={(v) => set('displayName', v)}
                  error={errors.displayName}
                  placeholder={t('admin.sso.namePlaceholder')}
                  required={form.enabled}
                  maxLength={60}
                />
                <div className="wide">
                  <TextBox
                    label={t('admin.sso.issuer')}
                    type="url"
                    inputMode="url"
                    mono
                    value={form.issuer}
                    onChange={(v) => set('issuer', v)}
                    hint={t('admin.sso.issuerHint')}
                    placeholder="https://id.example.co/realms/staff"
                    pattern="https?://.+"
                    required={form.enabled}
                    error={errors.issuer}
                  />
                </div>
                <TextBox
                  label={t('admin.sso.clientId')}
                  mono
                  value={form.clientId}
                  onChange={(v) => set('clientId', v)}
                  required={form.enabled}
                  error={errors.clientId}
                />
                <TextBox
                  label={t('admin.sso.clientSecret')}
                  type="password"
                  value={form.clientSecret}
                  onChange={(v) => set('clientSecret', v)}
                  placeholder={config.clientSecretSet ? t('admin.secretKept') : ''}
                  hint={t('admin.secretHint')}
                  autoComplete="new-password"
                />
                <div className="wide">
                  <TextBox
                    label={t('admin.sso.scopes')}
                    mono
                    value={form.scopes}
                    onChange={(v) => set('scopes', v)}
                    placeholder="openid profile email"
                    required={form.enabled}
                    error={errors.scopes}
                  />
                </div>
              </div>
              {config.clientSecretSet ? (
                <CheckBox
                  label={t('admin.sso.clearSecret')}
                  hint={t('admin.sso.clearSecretHint')}
                  checked={form.clearClientSecret}
                  onChange={(v) => set('clearClientSecret', v)}
                />
              ) : null}
              <div className="field">
                <span className="label">{t('admin.sso.redirect')}</span>
                <div className="with-action">
                  <span className="mono">{config.callbackUrl}</span>
                  <CopyButton value={config.callbackUrl} label={t('admin.sso.copyRedirect')} />
                </div>
              </div>
              <CheckBox
                label={t('admin.sso.verified')}
                hint={t('admin.sso.verifiedHint')}
                checked={!form.allowUnknownEmailVerification}
                onChange={(v) => set('allowUnknownEmailVerification', !v)}
              />
              <CheckBox
                label={t('admin.sso.verifiedDomain')}
                hint={t('admin.sso.verifiedDomainHint')}
                checked={form.requireVerifiedDomain}
                onChange={(v) => set('requireVerifiedDomain', v)}
              />
              <CheckBox
                label={t('admin.sso.link')}
                hint={t('admin.sso.linkHint')}
                checked={form.linkByEmail}
                onChange={(v) => set('linkByEmail', v)}
              />
              <CheckBox
                label={t('admin.sso.create')}
                hint={t('admin.sso.createHint')}
                checked={form.createAccounts}
                onChange={(v) => set('createAccounts', v)}
              />
            </div>
          </section>

          <section className="card" aria-labelledby="h-map">
            <div className="adm-head">
              <h2 id="h-map">{t('admin.sso.map')}</h2>
              <Button
                size="small"
                isDisabled={spaces.length === 0}
                onPress={() =>
                  set('groupRules', [
                    ...form.groupRules,
                    { group: '', space: spaces[0]?.id ?? '', role: 'member', collections: [] },
                  ])
                }
              >
                {t('admin.sso.addRule')}
              </Button>
            </div>
            <p className="hint adm-pad">{t('admin.sso.mapHint')}</p>
            {form.groupRules.length === 0 ? (
              <p className="empty">{t('admin.sso.noRules')}</p>
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th scope="col">{t('admin.sso.col.group')}</th>
                      <th scope="col">{t('admin.sso.col.space')}</th>
                      <th scope="col">{t('admin.sso.col.role')}</th>
                      <th scope="col">{t('admin.sso.col.collections')}</th>
                      <th scope="col">
                        <span className="sr">{t('table.actions')}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {form.groupRules.map((rule, index) => (
                      <tr key={`${index}-${rule.group}`}>
                        <td>
                          <TextBox
                            label={t('admin.sso.col.group')}
                            mono
                            value={rule.group}
                            onChange={(v) => setRule(index, { group: v })}
                          />
                        </td>
                        <td>
                          <SelectBox
                            label={t('admin.sso.col.space')}
                            value={rule.space}
                            onChange={(v) => setRule(index, { space: v })}
                            options={[
                              ...(spaces.some((s) => s.id === rule.space)
                                ? []
                                : [{ value: rule.space, label: rule.space.slice(0, 8) }]),
                              ...spaces.map((s) => ({ value: s.id, label: s.id.slice(0, 8) })),
                            ]}
                          />
                        </td>
                        <td>
                          <SelectBox
                            label={t('admin.sso.col.role')}
                            value={rule.role}
                            onChange={(v) => setRule(index, { role: v as GroupRole })}
                            options={ROLES.map(([value, label]) => ({ value, label: t(label) }))}
                          />
                        </td>
                        <td>{t('admin.sso.nCollections', { n: rule.collections.length })}</td>
                        <td>
                          <Button
                            size="small"
                            aria-label={t('admin.sso.removeRule', { group: rule.group })}
                            onPress={() =>
                              set(
                                'groupRules',
                                form.groupRules.filter((_, i) => i !== index),
                              )
                            }
                          >
                            {t('admin.remove')}
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        <div className="adm-col">
          <section className="card" aria-labelledby="h-domains">
            <div className="adm-head">
              <h2 id="h-domains">{t('admin.sso.domains')}</h2>
            </div>
            <p className="hint adm-pad">{t('admin.sso.domainsHint')}</p>
            {domains.map((entry) => (
              <div className="row" key={entry.domain}>
                <span className="grow">
                  <span className="mono">{entry.domain}</span>
                  <span className="hint">
                    {entry.verified
                      ? t('admin.sso.domain.verified')
                      : t('admin.sso.domain.addTxt', { txt: entry.txtValue })}
                  </span>
                </span>
                {entry.verified ? null : (
                  <Button
                    size="small"
                    aria-label={t('admin.sso.domain.check', { domain: entry.domain })}
                    onPress={() => onVerifyDomain(entry.domain)}
                  >
                    {t('admin.sso.domain.checkShort')}
                  </Button>
                )}
                <Button
                  size="small"
                  aria-label={t('admin.sso.domain.remove', { domain: entry.domain })}
                  onPress={() => onRemoveDomain(entry.domain)}
                >
                  {t('admin.remove')}
                </Button>
              </div>
            ))}
            <div className="adm-pad">
              <TextBox
                label={t('admin.sso.domain.new')}
                mono
                value={domain}
                onChange={setDomain}
                placeholder="example.co"
              />
              <div className="actions">
                <Button size="small" onPress={addDomain}>
                  {t('admin.sso.domain.add')}
                </Button>
              </div>
            </div>
          </section>

          <section className="card" aria-labelledby="h-after">
            <div className="adm-head">
              <h2 id="h-after">{t('admin.sso.after')}</h2>
            </div>
            <div className="adm-pad">
              <p>{t('admin.sso.afterBody')}</p>
              <p className="hint">{t('admin.sso.noKeyConnector')}</p>
            </div>
          </section>
        </div>
      </div>
    </>
  );
}

export default function Sso() {
  const queryClient = useQueryClient();
  const { guard, dialog } = useReauth(admin);
  const sso = useQuery({ queryKey: ['admin', 'sso'], queryFn: () => admin.sso() });
  const domains = useQuery({ queryKey: ['admin', 'sso', 'domains'], queryFn: () => admin.ssoDomains() });
  const spaces = useQuery({ queryKey: ['admin', 'spaces'], queryFn: () => admin.spaces({ limit: 200 }) });
  // Counts saves, so that the form starts over after each one even when the server sends back the
  // same config (a new client secret alone changes nothing it returns).
  const [saves, setSaves] = useState(0);
  const save = useMutation({
    mutationFn: (update: SsoUpdate) => guard((token) => admin.saveSso(update, token)),
    onSuccess: (saved) => {
      queryClient.setQueryData(['admin', 'sso'], saved);
      setSaves((n) => n + 1);
    },
  });
  const refreshDomains = () => queryClient.invalidateQueries({ queryKey: ['admin', 'sso', 'domains'] });
  const addDomain = useMutation({
    mutationFn: (name: string) => guard((token) => admin.addSsoDomain(name, token)),
    onSuccess: refreshDomains,
  });
  const verifyDomain = useMutation({
    mutationFn: (name: string) => guard((token) => admin.verifySsoDomain(name, token)),
    onSuccess: refreshDomains,
  });
  const removeDomain = useMutation({
    mutationFn: (name: string) => guard((token) => admin.removeSsoDomain(name, token)),
    onSuccess: refreshDomains,
  });
  if (sso.isPending || domains.isPending || spaces.isPending) return <Loading />;
  if (!sso.data) return <ErrorNotice error={sso.error} />;
  return (
    <>
      <SsoView
        // The form starts from the saved config, so a save remounts it with what the server kept.
        key={`${saves}:${JSON.stringify(sso.data)}`}
        config={sso.data}
        spaces={spaces.data?.spaces ?? []}
        domains={domains.data ?? []}
        saving={save.isPending}
        saved={save.isSuccess}
        error={
          save.error ?? addDomain.error ?? verifyDomain.error ?? removeDomain.error ?? domains.error ?? spaces.error
        }
        onSave={(update) => save.mutate(update)}
        onAddDomain={(name) => addDomain.mutate(name)}
        onVerifyDomain={(name) => verifyDomain.mutate(name)}
        onRemoveDomain={(name) => removeDomain.mutate(name)}
      />
      {dialog}
    </>
  );
}
