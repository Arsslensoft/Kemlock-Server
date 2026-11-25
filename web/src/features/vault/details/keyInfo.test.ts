import { describe, expect, it } from 'vitest';
import { generateEd25519, toB64 } from '../forms/keyMaterial';
import { armor, certInfo, pgpInfo, sshInfo } from './keyInfo';

const der = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = parts.reduce<number[]>((all, p) => [...all, ...p], []);
  const length = body.length < 128 ? [body.length] : [0x81, body.length];
  return Uint8Array.from([tag, ...length, ...body]);
};
const text = (tag: number, value: string) => der(tag, new TextEncoder().encode(value));
const name = (cn: string) => der(0x30, der(0x31, der(0x30, der(0x06, Uint8Array.from([0x55, 0x04, 0x03])), text(0x0c, cn))));

describe('SSH key info', () => {
  it('writes the OpenSSH line and a SHA256 fingerprint of an Ed25519 key', async () => {
    const key = await generateEd25519();
    const info = await sshInfo('ed25519', key.public);
    expect(info?.line).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI/);
    expect(info?.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    const blob = Uint8Array.from(atob(info!.line.split(' ')[1]!), (c) => c.charCodeAt(0));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', blob));
    expect(info?.fingerprint).toBe(`SHA256:${toB64(digest).replace(/=+$/, '')}`);
  });

  // Keys made with `ssh-keygen`, their SPKI (base64) and what `ssh-keygen -l` printed.
  it.each([
    [
      'ed25519',
      'MCowBQYDK2VwAyEA3LfzBHECprL7AEkJxPpn2ZwoU6PYV9hFKE+Ya2lbWPA=',
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINy38wRxAqay+wBJCcT6Z9mcKFOj2FfYRShPmGtpW1jw',
      'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8',
    ],
    [
      'ecdsa-p256',
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMB41G3kSlU8/RUAexjUYm6cN49STIAtqBL7avUiqcRJZNyvPRCBDt8AlLkqIbmZZDVEQappXmCNSNX7zlj3iyQ==',
      'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDAeNRt5EpVPP0VAHsY1GJunDePUkyALagS+2r1IqnESWTcrz0QgQ7fAJS5KiG5mWQ1REGqaV5gjUjV+85Y94sk=',
      'SHA256:RNAAHhWMuzmQ3XfX5YUo591+Afn04LjbEripUnyLS28',
    ],
  ])('matches ssh-keygen -l for a %s key', async (algorithm, spki, line, fingerprint) => {
    expect(await sshInfo(algorithm, spki)).toEqual({ line, fingerprint });
  });

  it('shows nothing for a key it does not know', async () => {
    expect(await sshInfo('ed25519', toB64(Uint8Array.of(1, 2, 3)))).toBeUndefined();
  });
});

describe('PGP key info', () => {
  it('hashes the public key packet and lists the user ids', async () => {
    // A v4 RSA public key packet: version, time, algorithm 1, two 8-bit MPIs.
    const body = Uint8Array.from([4, 0, 0, 0, 1, 1, 0, 8, 0xc3, 0, 8, 0x03]);
    const packet = Uint8Array.from([0xc6, body.length, ...body]);
    const uid = new TextEncoder().encode('Ada <ada@example.org>');
    const all = Uint8Array.from([...packet, 0xcd, uid.length, ...uid]);
    const expected = new Uint8Array(
      await crypto.subtle.digest('SHA-1', Uint8Array.from([0x99, 0, body.length, ...body])),
    );
    const info = await pgpInfo(toB64(all));
    expect(info.userIds).toEqual(['Ada <ada@example.org>']);
    expect(info.fingerprint?.replace(/ /g, '').toLowerCase()).toBe(
      Array.from(expected, (b) => b.toString(16).padStart(2, '0')).join(''),
    );
  });

  it('wraps a binary key in armor', () => {
    expect(armor('PGP PUBLIC KEY BLOCK', 'A'.repeat(70))).toBe(
      `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${'A'.repeat(64)}\n${'A'.repeat(6)}\n-----END PGP PUBLIC KEY BLOCK-----\n`,
    );
  });
});

describe('certificate info', () => {
  it('reads subject, issuer, validity and fingerprint', async () => {
    const tbs = der(
      0x30,
      der(0xa0, der(0x02, Uint8Array.of(2))),
      der(0x02, Uint8Array.of(1)),
      der(0x30, der(0x06, Uint8Array.of(0x2a))),
      name('Test CA'),
      der(0x30, text(0x17, '240101000000Z'), text(0x18, '20300615120000Z')),
      name('example.org'),
    );
    const cert = der(0x30, tbs, der(0x30, der(0x06, Uint8Array.of(0x2a))), der(0x03, Uint8Array.of(0, 1)));
    const pem = `-----BEGIN CERTIFICATE-----\n${toB64(cert)}\n-----END CERTIFICATE-----`;
    const info = await certInfo(pem);
    expect(info?.subject).toBe('CN=example.org');
    expect(info?.issuer).toBe('CN=Test CA');
    expect(info?.notBefore?.toISOString()).toBe('2024-01-01T00:00:00.000Z');
    expect(info?.notAfter?.toISOString()).toBe('2030-06-15T12:00:00.000Z');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', cert));
    expect(info?.fingerprint).toBe(Array.from(digest, (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':'));
  });

  it('gives nothing for text that is not a certificate', async () => {
    expect(await certInfo('nope')).toBeUndefined();
  });
});
