import { describe, expect, it } from 'vitest';
import { login, vaultItem } from '@/test/tools-fixtures';
import { analyse, countByKind, issueId } from './analyse';

const NOW = new Date('2026-11-21T12:00:00Z');
const STRONG = 'w9!Kp2rTq7#mXv4LbZ8e';

describe('analyse', () => {
  it('finds exposed passwords from the lookup, and only those', () => {
    const old = login('Old forum', 'sam', STRONG, ['forum.example']);
    const fine = login('Fine', 'sam', `${STRONG}x`, ['fine.example']);
    const { issues } = analyse([old, fine], new Map([[old.id, 1204], [fine.id, 0]]), NOW);
    const exposed = issues.filter((i) => i.kind === 'exposed');
    expect(exposed).toHaveLength(1);
    expect(exposed[0]).toMatchObject({
      title: 'Old forum',
      severity: 'bad',
      itemIds: [old.id],
      detail: { id: 'health.exposed.detail', values: { count: 1204 } },
    });
  });

  it('shows no exposed passwords when the lookup is off or has not run', () => {
    const old = login('Old forum', 'sam', STRONG, ['forum.example']);
    expect(analyse([old], undefined, NOW).issues.filter((i) => i.kind === 'exposed')).toEqual([]);
  });

  it('groups reused passwords', () => {
    const a = login('Stream A', 'sam', STRONG, ['a.example']);
    const b = login('Stream B', 'sam', STRONG, ['b.example']);
    const c = login('Other', 'sam', `${STRONG}z`, ['c.example']);
    const { issues } = analyse([a, b, c], undefined, NOW);
    const reused = issues.filter((i) => i.kind === 'reused');
    expect(reused).toHaveLength(1);
    expect(reused[0]?.itemIds.sort()).toEqual([a.id, b.id].sort());
    expect(countByKind(issues).reused).toBe(2);
  });

  it('flags weak passwords and says why', () => {
    const lower = login('Home NAS', 'admin', 'abcdefgh', ['nas.local']);
    const { issues } = analyse([lower], undefined, NOW);
    const weak = issues.find((i) => i.kind === 'weak');
    expect(weak?.detail).toEqual({ id: 'health.weak.lower', values: { length: 8 } });
  });

  it('lists services that offer a code and have none in the vault', () => {
    const dropbox = login('Dropbox', 'sam', STRONG, ['https://www.dropbox.com']);
    const github = login('GitHub', 'sam', `${STRONG}1`, ['https://github.com']);
    const githubCode = vaultItem('otp', { name: 'GitHub', secret: 'JBSWY3DP', websites: ['github.com'] });
    const { issues } = analyse([dropbox, github, githubCode], undefined, NOW);
    const none = issues.find((i) => i.kind === 'noCode');
    expect(none?.itemIds).toEqual([dropbox.id]);
    expect(none?.detail.values).toMatchObject({ count: 1, sites: 'dropbox.com' });
  });

  it('counts a code whose name mentions the service', () => {
    const discord = login('Discord', 'sam', STRONG, ['discord.com']);
    const code = vaultItem('otp', { name: 'Discord account', secret: 'JBSWY3DP' });
    expect(analyse([discord, code], undefined, NOW).issues.some((i) => i.kind === 'noCode')).toBe(false);
  });

  it('warns about a key that expires within 60 days, and one that has expired', () => {
    const soon = vaultItem('pgp-key', { name: 'Sam work', expiresAt: '2026-12-12T00:00:00Z' });
    const far = vaultItem('pgp-key', { name: 'Far', expiresAt: '2030-01-01T00:00:00Z' });
    const past = vaultItem('pgp-key', { name: 'Old', expiresAt: '2026-11-01T00:00:00Z' });
    const { issues } = analyse([soon, far, past], undefined, NOW);
    const expiring = issues.filter((i) => i.kind === 'expiring');
    expect(expiring.map((i) => i.title).sort()).toEqual(['Old', 'Sam work']);
    expect(expiring.find((i) => i.title === 'Sam work')?.detail).toEqual({
      id: 'health.expiring.detail',
      values: { date: '2026-12-12', days: 21 },
    });
    expect(expiring.find((i) => i.title === 'Old')?.detail.id).toBe('health.expired.detail');
  });

  it('lists what is in good shape', () => {
    const ok = login('Ok', 'sam', STRONG, ['https://ok.example']);
    expect(analyse([ok], undefined, NOW).good.map((g) => g.id)).toEqual([
      'health.good.synced',
      'health.good.https',
    ]);
    const plain = login('Plain', 'sam', `${STRONG}q`, ['http://plain.example']);
    expect(analyse([plain], undefined, NOW).good.map((g) => g.id)).toEqual(['health.good.synced']);
  });

  it('gives an issue the same id on every run, so "dealt with" sticks', () => {
    expect(issueId('reused', ['b', 'a'])).toBe(issueId('reused', ['a', 'b']));
    expect(issueId('weak', ['a'])).not.toBe(issueId('exposed', ['a']));
  });
});
