// The read-only detail sections of the newer item kinds, like the login's Sign-in card: a card of
// rows, a secret masked behind a Show button and copied with the clipboard clearing a secret
// after 30 seconds. Nothing here logs a secret.
import { type ReactNode, useEffect, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { IconButton } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import type { ItemData, VaultItem } from '../vault';
import { type CertInfo, type PgpInfo, type SshInfo, armor, certInfo, pgpInfo, sshInfo } from './keyInfo';
import { type OtpParams, codeAt, otpParamsOf, secondsLeft } from './otp';

const MASK = '••••••••••••••••••••';

function text(data: ItemData | null, key: string): string {
  const value = data?.[key];
  return typeof value === 'string' ? value : '';
}

function strings(data: ItemData | null, key: string): string[] {
  const value = data?.[key];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && v !== '') : [];
}

/** One labelled value, with an optional copy button. */
function Row({
  label,
  children,
  copy,
  copyLabel,
  secret,
}: {
  label: string;
  children: ReactNode;
  copy?: string;
  copyLabel?: string;
  secret?: boolean;
}) {
  return (
    <div className="row">
      <div className="grow">
        <div className="lbl">{label}</div>
        {children}
      </div>
      {copy ? <CopyButton value={copy} label={copyLabel ?? label} secret={secret ?? false} /> : null}
    </div>
  );
}

/** A secret shown as dots until the person asks, with Show and Copy. */
function SecretRow({
  label,
  value,
  masked = MASK,
  mono = true,
  copyValue,
}: {
  label: string;
  value: string;
  masked?: string;
  mono?: boolean;
  /** What Copy puts on the clipboard, when it is not what is shown. */
  copyValue?: string;
}) {
  const t = useT();
  const [shown, setShown] = useState(false);
  const cls = mono ? 'mono' : undefined;
  return (
    <div className="row">
      <div className="grow">
        <div className="lbl">{label}</div>
        <div className={`${cls ?? ''} wrap`.trim()}>{shown ? value : masked}</div>
      </div>
      <IconButton
        aria-label={t(shown ? 'detail.hide' : 'detail.show', { field: label.toLowerCase() })}
        onPress={() => setShown((v) => !v)}
      >
        <Icon name={shown ? 'eyeOff' : 'eye'} />
      </IconButton>
      <CopyButton value={copyValue ?? value} secret label={t('detail.copy', { field: label.toLowerCase() })} />
    </div>
  );
}

function Card({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section className="card" aria-labelledby={id}>
      <div className="card-head">
        <h2 id={id}>{title}</h2>
      </div>
      {children}
    </section>
  );
}

// ---- one-time code ----

function OtpDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const params: OtpParams | undefined = otpParamsOf(data);
  const [now, setNow] = useState(() => Date.now());
  const [code, setCode] = useState('');
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const stepKey = params ? (params.type === 'hotp' ? params.counter : Math.floor(now / 1000 / params.period)) : 0;
  useEffect(() => {
    let live = true;
    if (!params) return;
    void codeAt(params, now).then(
      (value) => live && setCode(value),
      () => live && setCode(''),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stepKey, text(data, 'secret'), params?.digits, params?.algorithm, params?.type]);
  const issuer = text(data, 'issuer');
  const label = text(data, 'label');
  const shownCode = code.length > 3 ? `${code.slice(0, Math.ceil(code.length / 2))} ${code.slice(Math.ceil(code.length / 2))}` : code;
  return (
    <Card id="h-otp" title={t('detail.otp.title')}>
      {issuer ? (
        <Row label={t('newItem.otp.issuer')}>
          <div>{issuer}</div>
        </Row>
      ) : null}
      {label ? (
        <Row label={t('detail.otp.account')}>
          <div>{label}</div>
        </Row>
      ) : null}
      {params ? (
        <Row label={t('detail.otp.code')} copy={code} copyLabel={t('detail.copy', { field: t('detail.otp.code').toLowerCase() })} secret>
          <div className="mono" data-testid="otp-code" aria-live="off">
            {shownCode || '…'}
          </div>
          <div className="muted" role="timer">
            {params.type === 'hotp'
              ? t('detail.otp.counter', { counter: params.counter })
              : t('detail.otp.secondsLeft', { seconds: secondsLeft(now, params.period) })}
          </div>
        </Row>
      ) : (
        <Row label={t('detail.otp.code')}>
          <div className="muted">{t('detail.otp.unreadable')}</div>
        </Row>
      )}
    </Card>
  );
}

// ---- backup codes ----

interface BackupCode {
  code: string;
  used: boolean;
}

export function backupCodesOf(data: ItemData | null): BackupCode[] {
  const list = data?.['codes'];
  if (!Array.isArray(list)) return [];
  return list
    .filter((e): e is Record<string, unknown> => typeof e === 'object' && e !== null && typeof (e as { code?: unknown }).code === 'string')
    .map((e) => ({ code: e['code'] as string, used: e['used'] === true }));
}

function BackupDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const codes = backupCodesOf(data);
  const unused = codes.filter((c) => !c.used);
  const service = text(data, 'serviceName');
  return (
    <Card id="h-backup" title={t('detail.backup.title')}>
      {service ? (
        <Row label={t('newItem.backupCodes.service')}>
          <div>{service}</div>
        </Row>
      ) : null}
      {codes.length === 0 ? (
        <div className="row">
          <p className="grow muted">{t('detail.backup.none')}</p>
        </div>
      ) : (
        <Row
          label={t('detail.backup.left', { left: unused.length, total: codes.length })}
          copy={unused.map((c) => c.code).join('\n')}
          copyLabel={t('detail.backup.copyUnused')}
          secret
        >
          <ul className="plain mono">
            {codes.map((c) => (
              <li key={c.code}>
                {c.used ? (
                  <>
                    <s>{c.code}</s> <span className="muted">{t('detail.backup.used')}</span>
                  </>
                ) : (
                  c.code
                )}
              </li>
            ))}
          </ul>
        </Row>
      )}
    </Card>
  );
}

// ---- card ----

/** `4111 1111 1111 1111`, in groups of four. */
export function groupDigits(digits: string): string {
  return digits.replace(/(.{4})(?=.)/g, '$1 ');
}

export function maskedNumber(digits: string): string {
  return groupDigits('•'.repeat(Math.max(0, digits.length - 4)) + digits.slice(-4));
}

function CardDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const number = text(data, 'number');
  const code = text(data, 'code');
  const pin = text(data, 'pin');
  const month = data?.['expMonth'];
  const year = data?.['expYear'];
  const expiry = typeof month === 'number' && typeof year === 'number' ? `${String(month).padStart(2, '0')}/${year}` : '';
  const brand = text(data, 'brand');
  const holder = text(data, 'cardholder');
  return (
    <Card id="h-card" title={t('detail.card.title')}>
      {brand ? (
        <Row label={t('detail.card.brand')}>
          <div>{brand}</div>
        </Row>
      ) : null}
      {holder ? (
        <Row label={t('detail.card.cardholder')} copy={holder}>
          <div>{holder}</div>
        </Row>
      ) : null}
      {number ? (
        <SecretRow
          label={t('detail.card.number')}
          value={groupDigits(number)}
          masked={maskedNumber(number)}
          copyValue={number}
        />
      ) : null}
      {expiry ? (
        <Row label={t('detail.card.expiry')}>
          <div>{expiry}</div>
        </Row>
      ) : null}
      {code ? <SecretRow label={t('detail.card.code')} value={code} masked={'•'.repeat(code.length)} /> : null}
      {pin ? <SecretRow label={t('detail.card.pin')} value={pin} masked={'•'.repeat(pin.length)} /> : null}
    </Card>
  );
}

// ---- identity ----

function addressLines(data: ItemData | null): string[] {
  const address = data?.['address'];
  if (typeof address !== 'object' || address === null || Array.isArray(address)) return [];
  const a = address as Record<string, unknown>;
  const lines = Array.isArray(a['lines']) ? a['lines'].filter((l): l is string => typeof l === 'string') : [];
  const s = (k: string) => (typeof a[k] === 'string' ? (a[k] as string) : '');
  const place = [s('postalCode'), s('city')].filter(Boolean).join(' ');
  return [...lines, place, s('region'), s('country')].filter((l) => l !== '');
}

/** The documents of an identity as lines of `key: value`; their shape is the app's own. */
export function documentLines(data: ItemData | null): string[][] {
  const docs = data?.['documents'];
  if (!Array.isArray(docs)) return [];
  return docs
    .filter((d): d is Record<string, unknown> => typeof d === 'object' && d !== null && !Array.isArray(d))
    .map((d) =>
      Object.entries(d)
        .filter(([, v]) => (typeof v === 'string' && v !== '') || typeof v === 'number')
        .map(([k, v]) => `${k}: ${String(v)}`),
    )
    .filter((lines) => lines.length > 0);
}

function IdentityDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const name = ['title', 'givenName', 'middleName', 'familyName'].map((k) => text(data, k)).filter(Boolean).join(' ');
  const address = addressLines(data);
  const docs = documentLines(data);
  const simple: [MessageId, string][] = [
    ['detail.identity.company', text(data, 'company')],
    ['detail.identity.email', text(data, 'email')],
    ['detail.identity.phone', text(data, 'phone')],
    ['detail.identity.username', text(data, 'username')],
    ['detail.identity.birthDate', text(data, 'birthDate')],
  ];
  return (
    <Card id="h-identity" title={t('detail.identity.title')}>
      {name ? (
        <Row label={t('detail.identity.name')} copy={name}>
          <div>{name}</div>
        </Row>
      ) : null}
      {simple
        .filter(([, value]) => value !== '')
        .map(([id, value]) => (
          <Row key={id} label={t(id)} copy={value}>
            <div>{value}</div>
          </Row>
        ))}
      {address.length > 0 ? (
        <Row label={t('detail.identity.address')} copy={address.join('\n')}>
          {address.map((line, i) => (
            <div key={i}>{line}</div>
          ))}
        </Row>
      ) : null}
      {docs.length > 0 ? (
        <Row label={t('detail.identity.documents')}>
          {docs.map((lines, i) => (
            <div key={i} className="mono">
              {lines.map((line) => (
                <div key={line}>{line}</div>
              ))}
            </div>
          ))}
        </Row>
      ) : null}
    </Card>
  );
}

// ---- keys ----

function useAsync<T>(make: () => Promise<T>, key: string): T | undefined {
  const [value, setValue] = useState<T>();
  useEffect(() => {
    let live = true;
    setValue(undefined);
    void make().then(
      (v) => live && setValue(v),
      () => undefined,
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return value;
}

function SshDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const algorithm = text(data, 'algorithm');
  const pub = text(data, 'public');
  const priv = text(data, 'private');
  const info: SshInfo | undefined = useAsync(() => sshInfo(algorithm, pub), `${algorithm}:${pub}`);
  return (
    <Card id="h-ssh" title={t('detail.ssh.title')}>
      {algorithm ? (
        <Row label={t('detail.ssh.algorithm')}>
          <div>{algorithm === 'ecdsa-p256' ? 'ECDSA P-256' : algorithm === 'ed25519' ? 'Ed25519' : algorithm}</div>
        </Row>
      ) : null}
      {info ? (
        <>
          <Row
            label={t('detail.ssh.public')}
            copy={info.line}
            copyLabel={t('detail.copy', { field: t('detail.ssh.public').toLowerCase() })}
          >
            <div className="mono wrap">{info.line}</div>
          </Row>
          <Row label={t('detail.ssh.fingerprint')} copy={info.fingerprint}>
            <div className="mono wrap">{info.fingerprint}</div>
          </Row>
        </>
      ) : null}
      {priv ? (
        <>
          <SecretRow label={t('detail.ssh.private')} value={priv} />
          <div className="row">
            <p className="grow muted">{t('detail.ssh.privateNote')}</p>
          </div>
        </>
      ) : null}
    </Card>
  );
}

function PgpDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const pub = text(data, 'public');
  const priv = text(data, 'private');
  const source = pub || priv;
  const info: PgpInfo | undefined = useAsync(() => pgpInfo(source), source);
  const protectedKey = data?.['protected'] === true;
  const armored = pub ? armor('PGP PUBLIC KEY BLOCK', pub) : '';
  return (
    <Card id="h-pgp" title={t('detail.pgp.title')}>
      {info?.fingerprint ? (
        <Row label={t('detail.pgp.fingerprint')} copy={info.fingerprint}>
          <div className="mono wrap">{info.fingerprint}</div>
        </Row>
      ) : null}
      {info && info.userIds.length > 0 ? (
        <Row label={t('detail.pgp.userIds')}>
          {info.userIds.map((id) => (
            <div key={id}>{id}</div>
          ))}
        </Row>
      ) : null}
      <Row label={t('detail.pgp.protected')}>
        <div>{t(protectedKey ? 'detail.pgp.protectedYes' : 'detail.pgp.protectedNo')}</div>
      </Row>
      {armored ? (
        <Row
          label={t('detail.pgp.public')}
          copy={armored}
          copyLabel={t('detail.copy', { field: t('detail.pgp.public').toLowerCase() })}
        >
          <pre className="pre">{armored}</pre>
        </Row>
      ) : (
        <div className="row">
          <p className="grow muted">{t('detail.pgp.noPublic')}</p>
        </div>
      )}
    </Card>
  );
}

const date = (d: Date) => d.toISOString().slice(0, 10);

function CertificateDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const pem = text(data, 'certificate');
  const info: CertInfo | undefined = useAsync(() => certInfo(pem), pem);
  return (
    <Card id="h-cert" title={t('detail.certificate.title')}>
      {info ? (
        <>
          <Row label={t('detail.certificate.subject')} copy={info.subject}>
            <div className="wrap">{info.subject}</div>
          </Row>
          <Row label={t('detail.certificate.issuer')}>
            <div className="wrap">{info.issuer}</div>
          </Row>
          {info.notBefore ? (
            <Row label={t('detail.certificate.validFrom')}>
              <div>{date(info.notBefore)}</div>
            </Row>
          ) : null}
          {info.notAfter ? (
            <Row label={t('detail.certificate.validTo')}>
              <div>{date(info.notAfter)}</div>
            </Row>
          ) : null}
          <Row label={t('detail.certificate.fingerprint')} copy={info.fingerprint}>
            <div className="mono wrap">{info.fingerprint}</div>
          </Row>
        </>
      ) : null}
      {pem ? (
        <Row label={t('detail.certificate.pem')} copy={pem}>
          <pre className="pre">{pem}</pre>
        </Row>
      ) : (
        <div className="row">
          <p className="grow muted">{t('detail.certificate.unreadable')}</p>
        </div>
      )}
    </Card>
  );
}

function ContactDetail({ data }: { data: ItemData | null }) {
  const t = useT();
  const pub = text(data, 'public');
  const info: PgpInfo | undefined = useAsync(() => (pub ? pgpInfo(pub) : Promise.resolve({ userIds: [] })), pub);
  const emails = [...strings(data, 'emails'), ...[text(data, 'email')].filter(Boolean)];
  const phones = [...strings(data, 'phones'), ...[text(data, 'phone')].filter(Boolean)];
  const name = text(data, 'name');
  const armored = pub ? armor('PGP PUBLIC KEY BLOCK', pub) : '';
  return (
    <Card id="h-contact" title={t('detail.contact.title')}>
      {name ? (
        <Row label={t('detail.identity.name')} copy={name}>
          <div>{name}</div>
        </Row>
      ) : null}
      {emails.length > 0 ? (
        <Row label={t('detail.contact.emails')} copy={emails.join('\n')}>
          {emails.map((e) => (
            <div key={e}>{e}</div>
          ))}
        </Row>
      ) : null}
      {phones.length > 0 ? (
        <Row label={t('detail.contact.phones')} copy={phones.join('\n')}>
          {phones.map((p) => (
            <div key={p}>{p}</div>
          ))}
        </Row>
      ) : null}
      {info?.fingerprint ? (
        <Row label={t('detail.pgp.fingerprint')} copy={info.fingerprint}>
          <div className="mono wrap">{info.fingerprint}</div>
        </Row>
      ) : null}
      {info && info.userIds.length > 0 ? (
        <Row label={t('detail.pgp.userIds')}>
          {info.userIds.map((id) => (
            <div key={id}>{id}</div>
          ))}
        </Row>
      ) : null}
      {armored ? (
        <Row
          label={t('detail.contact.public')}
          copy={armored}
          copyLabel={t('detail.copy', { field: t('detail.contact.public').toLowerCase() })}
        >
          <pre className="pre">{armored}</pre>
        </Row>
      ) : null}
    </Card>
  );
}

/** The detail card of a newer kind; null for the kinds with their own view (login, note). */
export function KindDetails({ item }: { item: VaultItem }) {
  const data = item.data;
  switch (item.kind) {
    case 'otp':
      return <OtpDetail data={data} />;
    case 'backup-codes':
      return <BackupDetail data={data} />;
    case 'card':
      return <CardDetail data={data} />;
    case 'identity':
      return <IdentityDetail data={data} />;
    case 'ssh-key':
      return <SshDetail data={data} />;
    case 'pgp-key':
      return <PgpDetail data={data} />;
    case 'certificate':
      return <CertificateDetail data={data} />;
    case 'contact':
      return <ContactDetail data={data} />;
    default:
      return null;
  }
}

