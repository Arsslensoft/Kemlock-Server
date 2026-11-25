import { describe, expect, it } from 'vitest';
import { vaultItem } from '@/test/tools-fixtures';
import { KEY_KINDS, forgetKeyFacts, keyFactsOf } from './keyFacts';

// A key made with `ssh-keygen`: its SPKI (base64) and what `ssh-keygen -l` printed.
const ED25519 = 'MCowBQYDK2VwAyEA3LfzBHECprL7AEkJxPpn2ZwoU6PYV9hFKE+Ya2lbWPA=';
const ED25519_FINGERPRINT = 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8';

describe('the facts of a key item', () => {
  it('are the OpenSSH fingerprint and algorithm of an SSH key, worked out from its public half', async () => {
    const facts = await keyFactsOf(vaultItem('ssh-key', { name: 'k', algorithm: 'ed25519', public: ED25519 }));
    expect(facts).toEqual({ fingerprint: ED25519_FINGERPRINT, algorithm: 'ed25519' });
  });

  it('believe a fingerprint the item stores, which another app may have written', async () => {
    const facts = await keyFactsOf(vaultItem('ssh-key', { name: 'k', fingerprint: 'SHA256:stored', algorithm: 'ed25519' }));
    expect(facts?.fingerprint).toBe('SHA256:stored');
  });

  it('are nothing for a key whose halves can\'t be read', async () => {
    expect(await keyFactsOf(vaultItem('ssh-key', { name: 'k', algorithm: 'ed25519', public: 'not a key' }))).toBeUndefined();
    expect(await keyFactsOf(vaultItem('ssh-key', { name: 'k' }))).toBeUndefined();
    expect(await keyFactsOf(vaultItem('pgp-key', { name: 'k' }))).toBeUndefined();
    expect(await keyFactsOf(vaultItem('certificate', { name: 'c', certificate: 'nope' }))).toBeUndefined();
  });

  it('are nothing for an item that could not be opened, or one with no fingerprint', async () => {
    expect(await keyFactsOf(vaultItem('ssh-key', null))).toBeUndefined();
    expect(await keyFactsOf(vaultItem('login', { name: 'l', fingerprint: 'x' }))).toBeUndefined();
  });

  it('take a stored fingerprint for a certificate or a PGP key too', async () => {
    expect((await keyFactsOf(vaultItem('certificate', { name: 'c', fingerprint: 'AB:CD' })))?.fingerprint).toBe('AB:CD');
    expect((await keyFactsOf(vaultItem('pgp-key', { name: 'p', fingerprint: '9F3A' })))?.fingerprint).toBe('9F3A');
  });

  it('are asked of the kinds that have a fingerprint, a contact when it holds a key', () => {
    expect([...KEY_KINDS]).toEqual(['ssh-key', 'pgp-key', 'certificate', 'contact']);
  });

  it('are nothing for a contact with no key, or one that can\'t be read', async () => {
    expect(await keyFactsOf(vaultItem('contact', { name: 'Alex', email: 'a@b.c' }))).toBeUndefined();
    expect(await keyFactsOf(vaultItem('contact', { name: 'Alex', public: 'not a key' }))).toBeUndefined();
  });

  it('can be forgotten when the vault locks', () => {
    expect(() => forgetKeyFacts()).not.toThrow();
  });
});
