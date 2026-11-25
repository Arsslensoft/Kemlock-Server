import { type FormEvent, useState } from 'react';
import type { EmergencyKind, GrantViewDto } from '@/api/emergency';
import { useT } from '@/i18n';
import type { Fingerprint } from '@/sharing/bundle';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import '@/styles/account.css';
import { SelectInput, TextInput } from './controls';
import { daysLeft } from './emergencyModel';

export interface EmergencyConfirmState {
  view: GrantViewDto;
  /** undefined while being worked out, null when the bundle can't be read. */
  fingerprint: Fingerprint | null | undefined;
}

export interface EmergencyActions {
  /** Resolves false when the invitation failed, so the form keeps what was typed. */
  invite: (input: { email: string; kind: EmergencyKind; waitDays: number }) => Promise<boolean> | void;
  revoke: (id: string) => void;
  startConfirm: (view: GrantViewDto) => void;
  cancelConfirm: () => void;
  confirm: () => void;
  approve: (id: string) => void;
  reject: (id: string) => void;
  accept: (id: string) => void;
  initiate: (id: string) => void;
  getKey: (id: string) => void;
}

export interface EmergencyCardProps {
  trustedContacts: GrantViewDto[] | undefined;
  grantors: GrantViewDto[] | undefined;
  confirming: EmergencyConfirmState | null;
  /** The last key release: shown once, since opening it takes the key worker. */
  released: { grantor: string; kind: EmergencyKind } | null;
  cryptoAvailable: boolean;
  busy: boolean;
  now?: Date;
  actions: EmergencyActions;
}

export function EmergencyCard({
  trustedContacts,
  grantors,
  confirming,
  released,
  cryptoAvailable,
  busy,
  now = new Date(),
  actions,
}: EmergencyCardProps) {
  const t = useT();
  const [adding, setAdding] = useState(false);
  const [email, setEmail] = useState('');
  const [kind, setKind] = useState<EmergencyKind>('view');
  const [wait, setWait] = useState('7');

  async function submit(event: FormEvent) {
    event.preventDefault();
    const waitDays = Number.parseInt(wait, 10);
    if (email.trim() === '' || !Number.isInteger(waitDays) || waitDays < 1 || waitDays > 90) return;
    const done = await actions.invite({ email: email.trim(), kind, waitDays });
    if (done === false) return;
    setEmail('');
    setAdding(false);
  }

  const fp = confirming?.fingerprint;
  const contactName = confirming?.view.grant.granteeEmail ?? '';

  return (
    <section className="card" aria-labelledby="h-em">
      <div className="card-head">
        <div className="grow">
          <h2 id="h-em">{t('emergency.title')}</h2>
          <p className="hint">{t('emergency.lede')}</p>
        </div>
        <Button size="small" onPress={() => setAdding((open) => !open)}>
          {t('emergency.add')}
        </Button>
      </div>

      {confirming ? (
        <div className="panel-body" role="group" aria-label={t('emergency.confirm.title', { name: contactName })}>
          <h3 className="lbl">{t('emergency.confirm.title', { name: contactName })}</h3>
          <p>{t('emergency.confirm.body', { name: contactName })}</p>
          {fp === undefined ? (
            <p role="status">{t('space.confirm.working')}</p>
          ) : fp === null ? (
            <Notice tone="error" live>
              <p>{t('space.confirm.unreadable', { name: contactName })}</p>
            </Notice>
          ) : (
            <>
              <p className="fp" aria-label={t('space.confirm.fingerprintLabel', { name: contactName })}>
                {fp.text}
              </p>
              {!fp.consistent ? (
                <Notice tone="error" live>
                  <p>{t('space.confirm.inconsistent')}</p>
                </Notice>
              ) : null}
            </>
          )}
          {!cryptoAvailable ? (
            <Notice tone="warn">
              <p>{t('sharing.unavailable')}</p>
            </Notice>
          ) : null}
          <div className="actions">
            <Button onPress={actions.cancelConfirm}>{t('space.confirm.notNow')}</Button>
            <Button
              variant="primary"
              isDisabled={busy || !fp || !fp.consistent || !cryptoAvailable}
              onPress={actions.confirm}
            >
              {t('space.confirm.matches')}
            </Button>
          </div>
        </div>
      ) : null}

      {trustedContacts === undefined ? (
        <p className="empty" role="status">
          {t('state.loading')}
        </p>
      ) : trustedContacts.length === 0 ? (
        <p className="empty">{t('emergency.none')}</p>
      ) : (
        trustedContacts.map((view) => {
          const { grant } = view;
          const left = daysLeft(grant.dueAt, now);
          return (
            <div className="row" key={grant.id}>
              <div className="grow">
                <div>{grant.granteeEmail}</div>
                <div className="hint">
                  {t('emergency.line', {
                    kind: t(`emergency.kind.${grant.kind}`),
                    days: grant.waitDays,
                  })}
                  {left !== null ? ` · ${t('emergency.due', { days: left })}` : ''}
                </div>
              </div>
              <span className={grant.state === 'confirmed' ? 'tag ok' : 'tag warn'}>
                {t(`emergency.state.${grant.state}`)}
              </span>
              {grant.state === 'accepted' ? (
                <Button
                  size="small"
                  variant="primary"
                  aria-label={t('emergency.confirmFor', { name: grant.granteeEmail })}
                  onPress={() => actions.startConfirm(view)}
                >
                  {t('emergency.confirm.start')}
                </Button>
              ) : null}
              {grant.state === 'recovery-initiated' ? (
                <>
                  <Button
                    size="small"
                    aria-label={t('emergency.rejectFor', { name: grant.granteeEmail })}
                    isDisabled={busy}
                    onPress={() => actions.reject(grant.id)}
                  >
                    {t('emergency.reject')}
                  </Button>
                  <Button
                    size="small"
                    aria-label={t('emergency.approveFor', { name: grant.granteeEmail })}
                    isDisabled={busy}
                    onPress={() => actions.approve(grant.id)}
                  >
                    {t('emergency.approve')}
                  </Button>
                </>
              ) : null}
              <Button
                size="small"
                variant="danger"
                aria-label={t('emergency.removeFor', { name: grant.granteeEmail })}
                isDisabled={busy}
                onPress={() => actions.revoke(grant.id)}
              >
                {t('emergency.remove')}
              </Button>
            </div>
          );
        })
      )}

      {adding ? (
        <form className="inline-form" noValidate onSubmit={submit} aria-label={t('emergency.add')}>
          <TextInput label={t('emergency.email')} type="email" value={email} onChange={setEmail} required />
          <SelectInput
            label={t('emergency.kind')}
            value={kind}
            onChange={(value) => setKind(value as EmergencyKind)}
            options={[
              { value: 'view', label: t('emergency.kind.view') },
              { value: 'takeover', label: t('emergency.kind.takeover') },
            ]}
          />
          <TextInput label={t('emergency.wait')} type="number" value={wait} onChange={setWait} />
          <Button type="submit" variant="primary" isDisabled={busy}>
            {t('emergency.invite')}
          </Button>
        </form>
      ) : null}

      {grantors && grantors.length > 0 ? (
        <>
          <div className="card-head">
            <h3 className="lbl">{t('emergency.grantors')}</h3>
          </div>
          {grantors.map((view) => {
            const { grant } = view;
            const who = view.grantorEmail ?? grant.grantorId;
            return (
              <div className="row" key={grant.id}>
                <div className="grow">
                  <div>{who}</div>
                  <div className="hint">
                    {t('emergency.line', {
                      kind: t(`emergency.kind.${grant.kind}`),
                      days: grant.waitDays,
                    })}
                  </div>
                </div>
                <span className={grant.state === 'approved' ? 'tag ok' : 'tag warn'}>
                  {t(`emergency.state.${grant.state}`)}
                </span>
                {grant.state === 'invited' ? (
                  <Button
                    size="small"
                    variant="primary"
                    isDisabled={busy}
                    aria-label={t('emergency.acceptFor', { name: who })}
                    onPress={() => actions.accept(grant.id)}
                  >
                    {t('emergency.accept')}
                  </Button>
                ) : null}
                {grant.state === 'confirmed' ? (
                  <Button
                    size="small"
                    isDisabled={busy}
                    aria-label={t('emergency.askFor', { name: who })}
                    onPress={() => actions.initiate(grant.id)}
                  >
                    {t('emergency.ask')}
                  </Button>
                ) : null}
                {grant.state === 'approved' ? (
                  <Button
                    size="small"
                    isDisabled={busy}
                    aria-label={t('emergency.keyFor', { name: who })}
                    onPress={() => actions.getKey(grant.id)}
                  >
                    {t('emergency.key')}
                  </Button>
                ) : null}
              </div>
            );
          })}
        </>
      ) : null}

      {released ? (
        <div className="panel-body">
          <Notice tone="info" live>
            <b>{t('emergency.released.title', { name: released.grantor })}</b>
            <p>{t(`emergency.released.${released.kind}`)}</p>
          </Notice>
        </div>
      ) : null}
    </section>
  );
}
