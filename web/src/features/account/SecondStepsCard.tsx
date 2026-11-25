import { useState } from 'react';
import type { DuoKeysInput, Proof, SecurityKeyDto, TwoStepSetupDto } from '@/api/twoStep';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { TextInput } from './controls';
import { type KeyProof, ProofInput, proofBlank, proofValue } from './ProofInput';

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
  /** Whether an authenticator app is on: the card can't see it, and it counts as a second step. */
  totpOn?: boolean;
  /** Answers a fresh proof with a security key or passkey; undefined when the account has none. */
  keyProof?: KeyProof | undefined;
  busy: boolean;
  actions: {
    /** With another second step on, `proof` is the fresh proof that adding one asks for. */
    addSecurityKey: (name: string, proof?: Proof) => Done;
    /** Mails the one-time code that proves the owner, for turning a second step off. */
    askProof: () => Done;
    removeSecurityKey: (slot: number, proof: Proof) => Done;
    emailBegin: (address: string) => Done;
    emailConfirm: (address: string, code: string, proof?: Proof) => Done;
    emailOff: (proof: Proof) => Done;
    yubikeySet: (otps: string[], nfc: boolean, proof?: Proof) => Done;
    yubikeyOff: (proof: Proof) => Done;
    duoSet: (keys: DuoKeysInput | null, proof?: Proof) => Done;
    duoOff: (proof: Proof) => Done;
    /** The recovery code, or null when the account has none; undefined when the call failed. */
    showRecoveryCode: (proof: Proof) => Promise<string | null | undefined>;
  };
}

/** The fresh proof that adding a second step beside one that is on asks for: the mailed code. */
function ProofField({
  value,
  onChange,
  onAgain,
  busy,
  keyProof,
}: {
  value: Proof;
  onChange: (next: Proof) => void;
  onAgain: () => void;
  busy: boolean;
  keyProof?: KeyProof | undefined;
}) {
  const t = useT();
  return (
    <>
      <p className="hint">{t('security.proofAdd.sent')}</p>
      <ProofInput value={value} onChange={onChange} keyProof={keyProof} busy={busy} required={false} />
      <div className="actions">
        <Button isDisabled={busy} onPress={onAgain}>
          {t('security.proof.again')}
        </Button>
      </div>
    </>
  );
}

/** What is being turned off, until its proof comes. */
type Removal = { kind: 'email' | 'yubikey' | 'duo' } | { kind: 'key'; slot: number };

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
  totpOn = false,
  busy,
  keyProof,
  actions,
}: SecondStepsProps) {
  const t = useT();
  const loading = setup === undefined;
  // Beside a second step that is on, adding one asks for the same fresh proof as turning one off.
  const anotherOn =
    totpOn || Boolean(setup?.email || setup?.yubikey || setup?.duo) || (securityKeys?.length ?? 0) > 0;
  const askProof = () => void actions.askProof();
  // Turning a second step off asks for a fresh proof: a code mailed to the account's address.
  const [removing, setRemoving] = useState<Removal | null>(null);
  const [proof, setProof] = useState<Proof>('');
  function askToRemove(what: Removal) {
    setRemoving(what);
    setProof('');
    void actions.askProof();
  }
  async function remove() {
    if (!removing) return;
    const code = proofValue(proof);
    const done =
      removing.kind === 'key'
        ? await actions.removeSecurityKey(removing.slot, code)
        : removing.kind === 'email'
          ? await actions.emailOff(code)
          : removing.kind === 'yubikey'
            ? await actions.yubikeyOff(code)
            : await actions.duoOff(code);
    if (done) setRemoving(null);
  }
  return (
    <>
      <SecurityKeysRows
        keys={securityKeys}
        available={securityKeysAvailable}
        busy={busy}
        proofNeeded={anotherOn}
        keyProof={keyProof}
        onAskProof={askProof}
        onAdd={actions.addSecurityKey}
        onRemove={(slot) => askToRemove({ kind: 'key', slot })}
      />
      <YubikeyRows
        setup={setup}
        busy={busy}
        proofNeeded={anotherOn}
        keyProof={keyProof}
        onAskProof={askProof}
        onSet={actions.yubikeySet}
        onOff={() => askToRemove({ kind: 'yubikey' })}
      />
      <DuoRows
        setup={setup}
        busy={busy}
        proofNeeded={anotherOn}
        keyProof={keyProof}
        onAskProof={askProof}
        onSet={actions.duoSet}
        onOff={() => askToRemove({ kind: 'duo' })}
      />
      <EmailRows
        setup={setup}
        busy={busy}
        proofNeeded={anotherOn}
        keyProof={keyProof}
        onAskProof={askProof}
        onBegin={actions.emailBegin}
        onConfirm={actions.emailConfirm}
        onOff={() => askToRemove({ kind: 'email' })}
      />
      {removing ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            void remove();
          }}
        >
          <p className="hint">{t('security.proof.sent')}</p>
          <ProofInput value={proof} onChange={setProof} keyProof={keyProof} busy={busy} />
          <div className="actions">
            <Button type="submit" variant="danger" isDisabled={busy || proofBlank(proof)}>
              {t('security.proof.confirm')}
            </Button>
            <Button isDisabled={busy} onPress={() => void actions.askProof()}>
              {t('security.proof.again')}
            </Button>
            <Button onPress={() => setRemoving(null)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
      <RecoveryRows
        has={loading ? undefined : hasRecoveryCode}
        busy={busy}
        keyProof={keyProof}
        onAskProof={askProof}
        onShow={actions.showRecoveryCode}
      />
      <p className="hint">{t('security.secondSteps.beside')}</p>
    </>
  );
}

function SecurityKeysRows({
  keys,
  available,
  busy,
  proofNeeded,
  keyProof,
  onAskProof,
  onAdd,
  onRemove,
}: {
  keys: SecurityKeyDto[] | undefined;
  available: boolean;
  busy: boolean;
  proofNeeded: boolean;
  keyProof?: KeyProof | undefined;
  onAskProof: () => void;
  onAdd: (name: string, proof?: Proof) => Done;
  onRemove: (slot: number) => void;
}) {
  const t = useT();
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState('');
  const [proof, setProof] = useState<Proof>('');
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.webauthn')}</div>
          <div className="hint">{t('security.method.webauthn.hint')}</div>
        </div>
        <Tag on={keys === undefined ? undefined : keys.length > 0} />
        {available && !naming ? (
          <Button
            size="small"
            isDisabled={busy || keys === undefined}
            onPress={() => {
              setNaming(true);
              setProof('');
              if (proofNeeded) onAskProof();
            }}
          >
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
            const code = proofValue(proof);
            void (!proofBlank(code) ? onAdd(given, code) : onAdd(given)).then((done) => {
              if (!done) return;
              setNaming(false);
              setName('');
              setProof('');
            });
          }}
        >
          <TextInput label={t('security.webauthn.name')} value={name} onChange={setName} />
          {proofNeeded ? <ProofField value={proof} onChange={setProof} onAgain={onAskProof} busy={busy} keyProof={keyProof} /> : null}
          <p className="hint">{t('security.webauthn.touch')}</p>
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy || (proofNeeded && proofBlank(proof))}>
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
            onPress={() => onRemove(key.id)}
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
  proofNeeded,
  keyProof,
  onAskProof,
  onSet,
  onOff,
}: {
  setup: TwoStepSetupDto | undefined;
  busy: boolean;
  proofNeeded: boolean;
  keyProof?: KeyProof | undefined;
  onAskProof: () => void;
  onSet: (otps: string[], nfc: boolean, proof?: Proof) => Done;
  onOff: () => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [proof, setProof] = useState<Proof>('');
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
        {setup && !on && !open && setup.yubikeyOffered ? (
          <Button
            size="small"
            isDisabled={busy}
            onPress={() => {
              setOpen(true);
              setProof('');
              if (proofNeeded) onAskProof();
            }}
          >
            {t('security.setUp')}
          </Button>
        ) : null}
        {on ? (
          <Button size="small" isDisabled={busy} onPress={onOff}>
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
            const code = proofValue(proof);
            void (!proofBlank(code) ? onSet(otps, nfc, code) : onSet(otps, nfc)).then((done) => {
              if (!done) return;
              setOpen(false);
              setOtps(['', '', '', '', '']);
              setProof('');
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
          {proofNeeded ? <ProofField value={proof} onChange={setProof} onAgain={onAskProof} busy={busy} keyProof={keyProof} /> : null}
          <div className="actions">
            <Button
              type="submit"
              variant="primary"
              isDisabled={busy || otps.every((o) => o.trim() === '') || (proofNeeded && proofBlank(proof))}
            >
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
  proofNeeded,
  keyProof,
  onAskProof,
  onSet,
  onOff,
}: {
  setup: TwoStepSetupDto | undefined;
  busy: boolean;
  proofNeeded: boolean;
  keyProof?: KeyProof | undefined;
  onAskProof: () => void;
  onSet: (keys: DuoKeysInput | null, proof?: Proof) => Done;
  onOff: () => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [proof, setProof] = useState<Proof>('');
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
        {setup && !on && !open ? (
          <Button
            size="small"
            isDisabled={busy}
            onPress={() => {
              setOpen(true);
              setProof('');
              if (proofNeeded) onAskProof();
            }}
          >
            {t('security.setUp')}
          </Button>
        ) : null}
        {on ? (
          <Button size="small" isDisabled={busy} onPress={onOff}>
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
            const code = proofValue(proof);
            void (!proofBlank(code) ? onSet(keys, code) : onSet(keys)).then((done) => {
              if (!done) return;
              setOpen(false);
              setProof('');
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
          {proofNeeded ? <ProofField value={proof} onChange={setProof} onAgain={onAskProof} busy={busy} keyProof={keyProof} /> : null}
          <div className="actions">
            <Button
              type="submit"
              variant="primary"
              isDisabled={busy || (!own && !setup?.duoServerKeys) || (proofNeeded && proofBlank(proof))}
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
  proofNeeded,
  keyProof,
  onAskProof,
  onBegin,
  onConfirm,
  onOff,
}: {
  setup: TwoStepSetupDto | undefined;
  busy: boolean;
  proofNeeded: boolean;
  keyProof?: KeyProof | undefined;
  onAskProof: () => void;
  onBegin: (address: string) => Done;
  onConfirm: (address: string, code: string, proof?: Proof) => Done;
  onOff: () => void;
}) {
  const t = useT();
  const [stage, setStage] = useState<'closed' | 'address' | 'code'>('closed');
  const [address, setAddress] = useState('');
  const [code, setCode] = useState('');
  const [proof, setProof] = useState<Proof>('');
  const on = setup === undefined ? undefined : setup.email !== null;
  function close() {
    setStage('closed');
    setCode('');
    setProof('');
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
        {setup && !on && stage === 'closed' && setup.emailOffered ? (
          <Button size="small" isDisabled={busy} onPress={() => setStage('address')}>
            {t('security.setUp')}
          </Button>
        ) : null}
        {on ? (
          <Button size="small" isDisabled={busy} onPress={onOff}>
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
              if (!done) return;
              setStage('code');
              // The proof is asked for with the code that is entered, which turns the method on.
              if (proofNeeded) onAskProof();
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
            const fresh = proofValue(proof);
            const answered = !proofBlank(fresh)
              ? onConfirm(address.trim(), code.trim(), fresh)
              : onConfirm(address.trim(), code.trim());
            void answered.then((done) => {
              if (done) close();
            });
          }}
        >
          <p className="hint">{t('security.email.sent', { address: address.trim() })}</p>
          <TextInput label={t('security.email.code')} value={code} onChange={setCode} mono required />
          {proofNeeded ? <ProofField value={proof} onChange={setProof} onAgain={onAskProof} busy={busy} keyProof={keyProof} /> : null}
          <div className="actions">
            <Button
              type="submit"
              variant="primary"
              isDisabled={busy || code.trim() === '' || (proofNeeded && proofBlank(proof))}
            >
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
  keyProof,
  onAskProof,
  onShow,
}: {
  has: boolean | undefined;
  busy: boolean;
  keyProof?: KeyProof | undefined;
  onAskProof: () => void;
  onShow: (proof: Proof) => Promise<string | null | undefined>;
}) {
  const t = useT();
  const [code, setCode] = useState<string | null | undefined>(undefined);
  // The code proves removals and additions, so showing it asks for a fresh proof first.
  const [asking, setAsking] = useState(false);
  const [proof, setProof] = useState<Proof>('');
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.method.recovery')}</div>
          <div className="hint">{t('security.method.recovery.hint')}</div>
        </div>
        <Tag on={has} />
        {has && code === undefined && !asking ? (
          <Button
            size="small"
            isDisabled={busy}
            onPress={() => {
              setAsking(true);
              setProof('');
              onAskProof();
            }}
          >
            {t('security.recovery.show')}
          </Button>
        ) : null}
      </div>
      {asking ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            void onShow(proofValue(proof)).then((shown) => {
              if (shown === undefined) return;
              setCode(shown);
              setAsking(false);
              setProof('');
            });
          }}
        >
          <p className="hint">{t('security.recovery.proof')}</p>
          <ProofInput value={proof} onChange={setProof} keyProof={keyProof} busy={busy} />
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy || proofBlank(proof)}>
              {t('security.recovery.show')}
            </Button>
            <Button isDisabled={busy} onPress={onAskProof}>
              {t('security.proof.again')}
            </Button>
            <Button onPress={() => setAsking(false)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
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
