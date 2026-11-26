import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { login, renderInRouter } from '@/test/tools-fixtures';
import { analyse } from './analyse';
import { HealthView } from './Health';

const NOW = new Date('2026-11-21T12:00:00Z');
const STRONG = 'w9!Kp2rTq7#mXv4LbZ8e';

function analysis() {
  const forum = login('Old forum', 'sam', STRONG, ['forum.example']);
  const a = login('Stream A', 'sam', `${STRONG}1`, ['a.example']);
  const b = login('Stream B', 'sam', `${STRONG}1`, ['b.example']);
  const nas = login('Home NAS', 'admin', 'abcdefgh', ['nas.local']);
  return analyse([forum, a, b, nas], new Map([[forum.id, 1204]]), NOW);
}

describe('HealthView', () => {
  it('counts what is wrong and lists each problem with a way to fix it', async () => {
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn onHibp={vi.fn()} onDealtWith={vi.fn()} />,
    );
    expect(screen.getByRole('heading', { name: 'Vault health', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '3 things to fix' })).toBeInTheDocument();
    const tile = (label: string) => screen.getByText(label).closest('.stat') as HTMLElement;
    expect(within(tile('Exposed passwords')).getByText('1')).toBeInTheDocument();
    expect(within(tile('Reused passwords')).getByText('2')).toBeInTheDocument();
    expect(within(tile('Weak passwords')).getByText('1')).toBeInTheDocument();
    expect(screen.getByText('This password is in Pwned Passwords 1,204 times.')).toBeInTheDocument();
    expect(screen.getByText('8 characters, all lower case.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Change it' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Generate one' })).toBeInTheDocument();
  });

  it('marks a problem dealt with', async () => {
    const onDealtWith = vi.fn();
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn onHibp={vi.fn()} onDealtWith={onDealtWith} />,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Mark dealt with: Old forum' }));
    expect(onDealtWith).toHaveBeenCalledWith(expect.objectContaining({ kind: 'exposed', title: 'Old forum' }));
  });

  it('lists what is in good shape', async () => {
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn onHibp={vi.fn()} onDealtWith={vi.fn()} />,
    );
    expect(screen.getByText('All 4 items synced, end-to-end encrypted')).toBeInTheDocument();
    expect(screen.getByText('No website saved with http://')).toBeInTheDocument();
  });

  it('has a switch for Pwned Passwords that explains what it sends', async () => {
    const onHibp = vi.fn();
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn onHibp={onHibp} onDealtWith={vi.fn()} />,
    );
    const toggle = screen.getByRole('switch', { name: 'Look passwords up in Pwned Passwords' });
    expect(toggle).toBeChecked();
    expect(screen.getByText(/first 5 characters of each password's SHA-1 hash/)).toBeInTheDocument();
    await userEvent.setup().click(toggle);
    expect(onHibp).toHaveBeenCalledWith(false);
  });

  it('shows the breach-list switch as unavailable, not as off', async () => {
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn={false} onHibp={vi.fn()} onDealtWith={vi.fn()} />,
    );
    const toggle = screen.getByRole('switch', { name: 'Keep the breach list up to date' });
    expect(toggle).toBeDisabled();
    expect(screen.getByText(/this server has no breach-list route yet/)).toBeInTheDocument();
  });

  it('says when a lookup is running or failed, and when nothing is wrong', async () => {
    await renderInRouter(
      <HealthView
        analysis={{ issues: [], good: [] }}
        hibpOn
        checking
        checkFailed
        onHibp={vi.fn()}
        onDealtWith={vi.fn()}
      />,
    );
    expect(screen.getByText('Checking Pwned Passwords')).toBeInTheDocument();
    expect(screen.getByText("Pwned Passwords couldn't be reached, so exposed passwords aren't shown. Check your connection and reload.")).toBeInTheDocument();
    expect(screen.getByText('Nothing to fix right now.')).toBeInTheDocument();
  });

  it('asks before the first lookup, saying what is sent and to whom, and sends nothing itself', async () => {
    const onHibp = vi.fn();
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn={false} askHibp onHibp={onHibp} onDealtWith={vi.fn()} />,
    );
    expect(screen.getByText('Check your passwords against known breaches?')).toBeInTheDocument();
    expect(screen.getByText(/api.pwnedpasswords.com, a service run by Have I Been Pwned/)).toBeInTheDocument();
    expect(screen.getByText(/the first 5 characters of the SHA-1 hash of each password/)).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Look passwords up in Pwned Passwords' })).not.toBeChecked();
    expect(onHibp).not.toHaveBeenCalled();
  });

  it('takes yes and no from the question', async () => {
    const onHibp = vi.fn();
    const user = userEvent.setup();
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn={false} askHibp onHibp={onHibp} onDealtWith={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: 'Check my passwords' }));
    expect(onHibp).toHaveBeenLastCalledWith(true);
    await user.click(screen.getByRole('button', { name: "Don't check" }));
    expect(onHibp).toHaveBeenLastCalledWith(false);
  });

  it('does not ask once the account has answered', async () => {
    await renderInRouter(
      <HealthView analysis={analysis()} hibpOn={false} onHibp={vi.fn()} onDealtWith={vi.fn()} />,
    );
    expect(screen.queryByText('Check your passwords against known breaches?')).not.toBeInTheDocument();
  });
});
