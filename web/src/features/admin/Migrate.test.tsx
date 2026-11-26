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
  it('follows the server: any plausible text, which the server then holds to the import folder', () => {
    expect(checkSource('')).toBeUndefined();
    expect(checkSource('   ')).toBeUndefined();
    expect(checkSource('db.sqlite3')).toBeUndefined();
    expect(checkSource('data')).toBeUndefined();
    expect(checkSource('data/db.sqlite3')).toBeUndefined();
  });

  it('never takes a database URL, which only kemlock-cli import-vaultwarden reads', () => {
    expect(checkSource('postgres://vw@db/vw')).toBe('admin.migrate.error.url');
    expect(checkSource('MYSQL://vw@db/vw')).toBe('admin.migrate.error.url');
    expect(checkSource('mariadb://vw@db/vw')).toBe('admin.migrate.error.url');
  });

  it('refuses text the server would: too long, or with control characters', () => {
    expect(checkSource('x'.repeat(1025))).toBe('admin.migrate.error.source');
    expect(checkSource('x'.repeat(1024))).toBeUndefined();
    expect(checkSource('/srv/a\nb')).toBe('admin.migrate.error.source');
    expect(checkSource('/srv/a\u0000b')).toBe('admin.migrate.error.source');
  });
});

describe('MigrateView', () => {
  it('shows an error for a source that is too long, and does not read it', async () => {
    const { onStart } = view();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden database in the import folder/));
    await user.paste('x'.repeat(1025));
    expect(await screen.findByText(/at most 1024 characters/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check it' })).toBeDisabled();
    expect(onStart).not.toHaveBeenCalled();
  });

  it('needs a source before it reads anything', async () => {
    const { onStart } = view();
    const check = screen.getByRole('button', { name: 'Check it' });
    expect(check).toBeDisabled();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden database in the import folder/));
    await user.paste(' db.sqlite3 ');
    await waitFor(() => expect(check).toBeEnabled());
    await user.click(check);
    await waitFor(() => expect(onStart).toHaveBeenCalledWith({ from: 'db.sqlite3' }));
  });

  it('says where the file goes, and refuses a database URL before sending anything', async () => {
    const { onStart } = view();
    expect(screen.getByText(/into the import folder inside this server's data folder/)).toBeInTheDocument();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden database in the import folder/));
    await user.paste('postgres://vw@db/vaultwarden');
    expect(await screen.findByText(/A database URL can't be given here/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check it' })).toBeDisabled();
    expect(onStart).not.toHaveBeenCalled();
  });

  it('passes the folder of the files along', async () => {
    const { onStart } = view();
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByLabelText(/Vaultwarden database in the import folder/));
    await user.paste('db.sqlite3');
    await user.click(screen.getByLabelText(/Folder with its files, inside the import folder/));
    await user.paste('vw/files');
    const check = screen.getByRole('button', { name: 'Check it' });
    await waitFor(() => expect(check).toBeEnabled());
    await user.click(check);
    await waitFor(() => expect(onStart).toHaveBeenCalledWith({ from: 'db.sqlite3', files: 'vw/files' }));
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
