import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { NOW, migration } from './fixtures';
import { MigrateView, checkSource, stepOf } from './Migrate';

function view(props: Partial<Parameters<typeof MigrateView>[0]> = {}) {
  const onStart = vi.fn();
  renderWithIntl(<MigrateView host="vault.example.org" now={NOW} onStart={onStart} {...props} />);
  return { onStart };
}

describe('stepOf', () => {
  it('follows the move: read and planned, running, then done', () => {
    expect(stepOf(undefined)).toBe(1);
    expect(stepOf(migration())).toBe(1);
    expect(stepOf(migration({ state: 'failed' }))).toBe(1);
    expect(stepOf(migration({ state: 'planned' }))).toBe(2);
    expect(stepOf(migration({ state: 'running' }))).toBe(3);
    expect(stepOf(migration({ state: 'done' }))).toBe(4);
  });
});

describe('checkSource', () => {
  it('accepts a folder or a database address, and only complains about what is neither', () => {
    expect(checkSource('')).toBeUndefined();
    expect(checkSource('/srv/vaultwarden/data')).toBeUndefined();
    expect(checkSource('C:\vw\data')).toBeUndefined();
    expect(checkSource('postgres://vw@db/vw')).toBeUndefined();
    expect(checkSource('vaultwarden')).toBe('admin.migrate.error.source');
    expect(checkSource('https://example.co')).toBe('admin.migrate.error.source');
  });
});

describe('MigrateView', () => {
  it('shows an error for a source that is not a path, and does not read it', async () => {
    const { onStart } = view();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden data folder on this server/));
    await user.paste('vaultwarden');
    expect(await screen.findByText(/Type a folder path/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check it' })).toBeDisabled();
    expect(onStart).not.toHaveBeenCalled();
  });

  it('needs a source before it reads anything', async () => {
    const { onStart } = view();
    const check = screen.getByRole('button', { name: 'Check it' });
    expect(check).toBeDisabled();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden data folder on this server/));
    await user.paste(' /srv/vaultwarden/data ');
    await waitFor(() => expect(check).toBeEnabled());
    await user.click(check);
    await waitFor(() => expect(onStart).toHaveBeenCalledWith({ from: '/srv/vaultwarden/data' }));
  });

  it('passes the data folder of a database server along', async () => {
    const { onStart } = view();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden data folder on this server/));
    await user.paste('postgres://vw@db/vaultwarden');
    await user.click(screen.getByLabelText(/Data folder beside the database/));
    await user.paste('/srv/vaultwarden/data');
    const check = screen.getByRole('button', { name: 'Check it' });
    await waitFor(() => expect(check).toBeEnabled());
    await user.click(check);
    await waitFor(() =>
      expect(onStart).toHaveBeenCalledWith({ from: 'postgres://vw@db/vaultwarden', files: '/srv/vaultwarden/data' }),
    );
  });

  it('shows the plan the server made, and says nothing was copied when it only reads', () => {
    view({
      status: migration({
        state: 'planned',
        applies: false,
        source: '/srv/vaultwarden/data',
        plan: '42 users\n5302 items',
        at: NOW - 600,
      }),
    });
    expect(screen.getByRole('heading', { name: 'What a move would do' })).toBeInTheDocument();
    expect(screen.getByText(/5302 items/)).toBeInTheDocument();
    expect(screen.getByText('Read 10 minutes ago')).toBeInTheDocument();
    expect(screen.getByText(/kemlock-cli import-vaultwarden/)).toBeInTheDocument();
    expect(screen.getByText('Check it', { selector: 'li' })).toHaveAttribute('aria-current', 'step');
  });

  it('shows why a move failed, and when it ended', () => {
    view({ status: migration({ state: 'failed', error: 'no db.sqlite3 in that folder', finishedAt: NOW - 60 }) });
    expect(screen.getByRole('alert')).toHaveTextContent('The move stopped. no db.sqlite3 in that folder');
    expect(screen.getByRole('alert')).toHaveTextContent('It ended 1 minute ago.');
  });

  it('shows what a running move is doing, and the plan it follows', () => {
    view({
      status: migration({
        state: 'running',
        source: '/srv/vaultwarden/data',
        plan: '42 users\n5302 items',
        stage: 'writing items',
        at: NOW - 120,
      }),
    });
    expect(screen.getByRole('heading', { name: 'Moving now' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('writing items');
    expect(screen.getByText('Started 2 minutes ago')).toBeInTheDocument();
    expect(screen.getByText('Copy', { selector: 'li' })).toHaveAttribute('aria-current', 'step');
    // Nothing is said of a plan that only reads.
    expect(screen.queryByText(/kemlock-cli import-vaultwarden/)).not.toBeInTheDocument();
  });

  it('says what a finished move wrote, and when it finished', () => {
    view({
      status: migration({
        state: 'done',
        source: '/srv/vaultwarden/data',
        plan: '42 users',
        report: '42 users, 5302 items and 12 attachments were written.',
        finishedAt: NOW - 3600,
      }),
    });
    expect(screen.getByRole('heading', { name: 'Done' })).toBeInTheDocument();
    expect(screen.getByText(/42 users, 5302 items and 12 attachments were written/)).toBeInTheDocument();
    expect(screen.getByText('Finished 1 hour ago')).toBeInTheDocument();
    expect(screen.getByText('Switch the address', { selector: 'li' })).toHaveAttribute('aria-current', 'step');
  });

  it('names the address to switch', () => {
    view();
    expect(screen.getByText(/Point vault\.example\.org at Kemlock Server/)).toBeInTheDocument();
  });
});
