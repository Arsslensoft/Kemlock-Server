import { useState } from 'react';
import type { DuoKeysInput, SecurityKeyDto, TwoStepSetupDto } from '@/api/twoStep';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { TextInput } from './controls';

/** What a change answers: true when it went through, so the panel that asked can close. */
type Done = Promise<boolean>;

export interface SecondStepsProps {
  /** undefined while loading */
  setup: TwoStepSetupDto | undefined;
  /** undefined while loading, or where this browser can not make a security key */
  securityKeys: SecurityKeyDto[] | undefined;
  /** Whether this browser can ask for a security key. */
  securityKeysAvailable: boolean;
  /** Whether the server says the account holds a recovery code. */
  hasRecoveryCode: boolean | undefined;
  busy: boolean;
  actions: {
    addSecurityKey: (name: string) => Done;
    removeSecurityKey: (slot: number) => Done;
    emailBegin: (address: string) => Done;
    emailConfirm: (address: string, code: string) => Done;
    emailOff: () => Done;
    yubikeySet: (otps: string[], nfc: boolean) => Done;
    yubikeyOff: () => Done;
    duoSet: (keys: DuoKeysInput | null) => Done;
    duoOff: () => Done;
    /** The recovery code, or null when the account has none; undefined when the call failed. */
    showRecoveryCode: () => Promise<string | null | undefined>;
  };
}

function Tag({ on }: { on: boolean | undefined }) {
  const t = useT();
  if (on === undefined) return null;
  return <span className={on ? 'tag ok' : 'tag off'}>{on ? t('security.on') : t('security.off')}</span>;
}

/** The second steps beyond an authenticator app and passkeys, as rows of the two-step card. */
export function SecondStepsCard({
  setup,
  securityKeys,
  securityKeysAvailable,
  hasRecoveryCode,
  busy,
  actions,
}: SecondStepsProps) {
  const t = useT();
  const loading = setup === undefined;
  return (
    <>
      <SecurityKeysRows
        keys={securityKeys}
        available={securityKeysAvailable}
        busy={busy}
        onAdd={actions.addSecurityKey}
        onRemove={actions.removeSecurityKey}
      />
      <YubikeyRows
        setup={setup}
        busy={busy}
        onSet={actions.yubikeySet}
        onOff={actions.yubikeyOff}
      />
      <DuoRows setup={setup} busy={busy} onSet={actions.duoSet} onOff={actions.duoOff} />
      <EmailRows
        setup={setup}
        busy={busy}
        onBegin={actions.emailBegin}
        onConfirm={actions.emailConfirm}
        onOff={actions.emailOff}
      />
      <RecoveryRows has={loading ? undefined : hasRecoveryCode} busy={busy} onShow={actions.showRecoveryCode} />
      <p className="hint">{t('security.secondSteps.beside')}</p>
    </>
  );
}

function SecurityKeysRows({
  keys,
  available,
  busy,
  onAdd,
  onRemove,
}: {
  keys: SecurityKeyDto[] | undefined;
  available: boolean;
  busy: boolean;
  onAdd: (name: string) => Done;
  onRemove: (slot: number) => Done;
}) {
  const t = useT();
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState('');
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.webauthn')}</div>
          <div className="hint">{t('security.method.webauthn.hint')}</div>
        </div>
        <Tag on={keys === undefined ? undefined : keys.length > 0} />
        {available && !naming ? (
          <Button size="small" isDisabled={busy || keys === undefined} onPress={() => setNaming(true)}>
            {t('security.webauthn.add')}
          </Button>
        ) : null}
      </div>
      {!available ? <p className="hint">{t('security.passkeys.unavailable')}</p> : null}
      {naming ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            const given = name.trim() === '' ? t('security.webauthn.defaultName') : name.trim();
            void onAdd(given).then((done) => {
              if (!done) return;
              setNaming(false);
              setName('');
            });
          }}
        >
          <TextInput label={t('security.webauthn.name')} value={name} onChange={setName} />
          <p className="hint">{t('security.webauthn.touch')}</p>
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy}>
              {t('security.webauthn.make')}
            </Button>
            <Button onPress={() => setNaming(false)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
      {keys?.map((key) => (
        <div className="row" key={key.id} data-testid="security-key">
          <div className="grow">{key.name}</div>
          <Button
            size="small"
            isDisabled={busy}
            aria-label={t('security.webauthn.remove', { name: key.name })}
            onPress={() => void onRemove(key.id)}
          >
            {t('security.passkeys.removeLabel')}
          </Button>
        </div>
      ))}
    </>
  );
}

function YubikeyRows({
  setup,
  busy,
  onSet,
  onOff,
}: {
  setup: TwoStepSetupDto | undefined;
  busy: boolean;
  onSet: (otps: string[], nfc: boolean) => Done;
  onOff: () => Done;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [otps, setOtps] = useState<string[]>(['', '', '', '', '']);
  const [nfc, setNfc] = useState(false);
  const on = setup === undefined ? undefined : setup.yubikey !== null;
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.yubikey')}</div>
          <div className="hint">{t('security.method.yubikey.hint')}</div>
        </div>
        <Tag on={on} />
        {setup && !open && setup.yubikeyOffered ? (
          <Button size="small" isDisabled={busy} onPress={() => setOpen(true)}>
            {on ? t('security.change') : t('security.setUp')}
          </Button>
        ) : null}
        {on ? (
          <Button size="small" isDisabled={busy} onPress={() => void onOff()}>
            {t('security.turnOff')}
          </Button>
        ) : null}
      </div>
      {setup && !setup.yubikeyOffered ? <p className="hint">{t('security.yubikey.notOffered')}</p> : null}
      {setup?.yubikey ? (
        <div className="row" data-testid="yubikey-ids">
          <div className="grow mono">{setup.yubikey.keys.join(' · ')}</div>
        </div>
      ) : null}
      {open ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            void onSet(otps, nfc).then((done) => {
              if (!done) return;
              setOpen(false);
              setOtps(['', '', '', '', '']);
            });
          }}
        >
          <p className="hint">{t('security.yubikey.how')}</p>
          {otps.map((value, index) => (
            <TextInput
              key={index}
              mono
              label={t('security.yubikey.field', { n: index + 1 })}
              value={value}
              onChange={(next) => setOtps(otps.map((old, i) => (i === index ? next : old)))}
            />
          ))}
          <label className="check">
            <input type="checkbox" checked={nfc} onChange={(event) => setNfc(event.target.checked)} />
            {t('security.yubikey.nfc')}
          </label>
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy || otps.every((o) => o.trim() === '')}>
              {t('security.yubikey.save')}
            </Button>
            <Button onPress={() => setOpen(false)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
    </>
  );
}

function DuoRows({
  setup,
  busy,
  onSet,
  onOff,
}: {
  setup: TwoStepSetupDto | undefined;
  busy: boolean;
  onSet: (keys: DuoKeysInput | null) => Done;
  onOff: () => Done;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [host, setHost] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const on = setup === undefined ? undefined : setup.duo !== null;
  const own = host.trim() !== '' || clientId.trim() !== '' || clientSecret.trim() !== '';
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.duo')}</div>
          <div className="hint">
            {setup?.duo
              ? setup.duo.integration === 'own'
                ? t('security.duo.own', { host: setup.duo.host ?? '' })
                : t('security.duo.server')
              : t('security.method.duo.hint')}
          </div>
        </div>
        <Tag on={on} />
        {setup && !open ? (
          <Button size="small" isDisabled={busy} onPress={() => setOpen(true)}>
            {on ? t('security.change') : t('security.setUp')}
          </Button>
        ) : null}
        {on ? (
          <Button size="small" isDisabled={busy} onPress={() => void onOff()}>
            {t('security.turnOff')}
          </Button>
        ) : null}
      </div>
      {open ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            const keys = own ? { host: host.trim(), clientId: clientId.trim(), clientSecret: clientSecret.trim() } : null;
            void onSet(keys).then((done) => {
              if (!done) return;
              setOpen(false);
              setHost('');
              setClientId('');
              setClientSecret('');
            });
          }}
        >
          <p className="hint">{setup?.duoServerKeys ? t('security.duo.howServer') : t('security.duo.how')}</p>
          <TextInput label={t('security.duo.host')} value={host} onChange={setHost} mono />
          <TextInput label={t('security.duo.clientId')} value={clientId} onChange={setClientId} mono />
          <TextInput label={t('security.duo.clientSecret')} value={clientSecret} onChange={setClientSecret} mono />
          <div className="actions">
            <Button
              type="submit"
              variant="primary"
              isDisabled={busy || (!own && !setup?.duoServerKeys)}
            >
              {own || !setup?.duoServerKeys ? t('security.duo.save') : t('security.duo.useServer')}
            </Button>
            <Button onPress={() => setOpen(false)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
    </>
  );
}

function EmailRows({
  setup,
  busy,
  onBegin,
  onConfirm,
  onOff,
}: {
  setup: TwoStepSetupDto | undefined;
  busy: boolean;
  onBegin: (address: string) => Done;
  onConfirm: (address: string, code: string) => Done;
  onOff: () => Done;
}) {
  const t = useT();
  const [stage, setStage] = useState<'closed' | 'address' | 'code'>('closed');
  const [address, setAddress] = useState('');
  const [code, setCode] = useState('');
  const on = setup === undefined ? undefined : setup.email !== null;
  function close() {
    setStage('closed');
    setCode('');
  }
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.email')}</div>
          <div className="hint">
            {setup?.email ? t('security.email.to', { address: setup.email }) : t('security.method.email.hint')}
          </div>
        </div>
        <Tag on={on} />
        {setup && stage === 'closed' && setup.emailOffered ? (
          <Button size="small" isDisabled={busy} onPress={() => setStage('address')}>
            {on ? t('security.change') : t('security.setUp')}
          </Button>
        ) : null}
        {on ? (
          <Button size="small" isDisabled={busy} onPress={() => void onOff()}>
            {t('security.turnOff')}
          </Button>
        ) : null}
      </div>
      {setup && !setup.emailOffered ? <p className="hint">{t('security.email.notOffered')}</p> : null}
      {stage === 'address' ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            void onBegin(address.trim()).then((done) => {
              if (done) setStage('code');
            });
          }}
        >
          <TextInput label={t('security.email.address')} type="email" value={address} onChange={setAddress} required />
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy || address.trim() === ''}>
              {t('security.email.send')}
            </Button>
            <Button onPress={close}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
      {stage === 'code' ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            void onConfirm(address.trim(), code.trim()).then((done) => {
              if (done) close();
            });
          }}
        >
          <p className="hint">{t('security.email.sent', { address: address.trim() })}</p>
          <TextInput label={t('security.email.code')} value={code} onChange={setCode} mono required />
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy || code.trim() === ''}>
              {t('security.email.confirm')}
            </Button>
            <Button onPress={close}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
    </>
  );
}

function RecoveryRows({
  has,
  busy,
  onShow,
}: {
  has: boolean | undefined;
  busy: boolean;
  onShow: () => Promise<string | null | undefined>;
}) {
  const t = useT();
  const [code, setCode] = useState<string | null | undefined>(undefined);
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.recovery')}</div>
          <div className="hint">{t('security.method.recovery.hint')}</div>
        </div>
        <Tag on={has} />
        {has && code === undefined ? (
          <Button size="small" isDisabled={busy} onPress={() => void onShow().then(setCode)}>
            {t('security.recovery.show')}
          </Button>
        ) : null}
      </div>
      {code ? (
        <div className="panel-body" data-testid="recovery-code">
          <p className="hint">{t('security.recovery.keep')}</p>
          <span className="cmd">
            <code>{code.match(/.{1,4}/g)?.join(' ') ?? code}</code>
            <CopyButton value={code} label={t('security.recovery.copy')} secret big />
          </span>
          <div className="actions">
            <Button onPress={() => setCode(undefined)}>{t('security.recovery.hide')}</Button>
          </div>
        </div>
      ) : null}
      {code === null ? <p className="hint">{t('security.recovery.none')}</p> : null}
    </>
  );
}
