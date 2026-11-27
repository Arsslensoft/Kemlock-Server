import { useEffect, useId, useState } from 'react';
import { useT } from '@/i18n';

/** The last group of digits of a fingerprint: what the person types to say they compared it. */
export function lastGroup(fingerprint: string): string {
  return fingerprint.trim().split(/\s+/).at(-1) ?? '';
}

/** Whether `typed` is the last group of `fingerprint`, spaces aside. A fingerprint with no group matches nothing. */
export function typedLastGroup(fingerprint: string, typed: string): boolean {
  const want = lastGroup(fingerprint);
  return want !== '' && typed.replace(/\s+/g, '') === want;
}

/**
 * The box a person types the last group of a fingerprint into, so "they are the same" is not a
 * button pressed without looking (the way a new device is approved). It reports whether what was
 * typed is right, on every change and when it first shows. Give it a `key` of the fingerprint, so a
 * different one starts empty.
 */
export function TypeLastGroup({
  fingerprint,
  onMatch,
}: {
  fingerprint: string;
  onMatch: (matches: boolean) => void;
}) {
  const t = useT();
  const id = useId();
  const [typed, setTyped] = useState('');
  const right = typedLastGroup(fingerprint, typed);
  useEffect(() => {
    onMatch(right);
  }, [right, onMatch]);
  return (
    <div className="field">
      <label htmlFor={id}>{t('fingerprint.typeLast')}</label>
      <input
        id={id}
        className="mono"
        value={typed}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => setTyped(event.target.value)}
      />
    </div>
  );
}
