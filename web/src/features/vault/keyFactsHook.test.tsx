// useKeyFacts: the fingerprints of the key items, read in the browser, and when they are pending.
import { renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { vaultItem } from '@/test/tools-fixtures';
import { useKeyFacts } from './keyFacts';
import type { VaultItem } from './vault';

// A key made with `ssh-keygen`: its SPKI (base64) and what `ssh-keygen -l` printed.
const ED25519 = 'MCowBQYDK2VwAyEA3LfzBHECprL7AEkJxPpn2ZwoU6PYV9hFKE+Ya2lbWPA=';
const FINGERPRINT = 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8';

const sshKey = (name: string): VaultItem => vaultItem('ssh-key', { name, algorithm: 'ed25519', public: ED25519 });

describe('useKeyFacts', () => {
  it('is never pending for a vault with no key', () => {
    const items = [vaultItem('login', { name: 'a' }), vaultItem('note', { name: 'b' })];
    const { result } = renderHook(() => useKeyFacts(items));
    expect(result.current.pending).toBe(false);
    expect(result.current.facts.size).toBe(0);
  });

  it('is pending until the first key is read, then holds its fingerprint', async () => {
    const key = sshKey('Router');
    const items = [key];
    const { result } = renderHook(() => useKeyFacts(items));
    expect(result.current.pending).toBe(true);
    await waitFor(() => expect(result.current.pending).toBe(false));
    expect(result.current.facts.get(key.id)?.fingerprint).toBe(FINGERPRINT);
  });

  it('is pending again for a key that is added, and not for a change elsewhere', async () => {
    const first = sshKey('Router');
    const { result, rerender } = renderHook(({ items }: { items: VaultItem[] }) => useKeyFacts(items), {
      initialProps: { items: [first] },
    });
    await waitFor(() => expect(result.current.pending).toBe(false));

    // A login added to the vault reads nothing again and flashes nothing.
    rerender({ items: [first, vaultItem('login', { name: 'a' })] });
    expect(result.current.pending).toBe(false);

    // A second key is pending until it is read, and then both are known.
    const second = sshKey('Build server');
    rerender({ items: [first, second] });
    expect(result.current.pending).toBe(true);
    await waitFor(() => expect(result.current.pending).toBe(false));
    expect(result.current.facts.get(second.id)?.fingerprint).toBe(FINGERPRINT);
    expect(result.current.facts.get(first.id)?.fingerprint).toBe(FINGERPRINT);
  });

  it('is pending again for a key that changed, which has a new revision', async () => {
    const key = sshKey('Router');
    const { result, rerender } = renderHook(({ items }: { items: VaultItem[] }) => useKeyFacts(items), {
      initialProps: { items: [key] },
    });
    await waitFor(() => expect(result.current.pending).toBe(false));
    rerender({ items: [{ ...key, revision: key.revision + 1 }] });
    expect(result.current.pending).toBe(true);
    await waitFor(() => expect(result.current.pending).toBe(false));
  });
});
