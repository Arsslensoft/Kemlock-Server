import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { DEFAULT_FILTERS, EventsView, queryFor, sinceFor } from './Events';
import { USERS, event } from './fixtures';

describe('sinceFor', () => {
  it('reaches back a day, a week or a month', () => {
    expect(sinceFor('24h', 1_000_000)).toBe(1_000_000 - 86_400);
    expect(sinceFor('7d', 1_000_000)).toBe(1_000_000 - 7 * 86_400);
    expect(sinceFor('30d', 1_000_000)).toBe(1_000_000 - 30 * 86_400);
  });
});

describe('queryFor', () => {
  it('asks for a time, and a kind as the prefix of the action codes', () => {
    expect(queryFor(DEFAULT_FILTERS, 1_000_000)).toEqual({ from: 1_000_000 - 86_400 });
    expect(queryFor({ kind: 'item', user: 'u1', when: '7d' }, 1_000_000)).toEqual({
      from: 1_000_000 - 7 * 86_400,
      action: 'item.*',
      actor: 'u1',
    });
  });
});

describe('EventsView', () => {
  const events = [
    event({ id: 'a', action: 'device.sign_out' }),
    event({ id: 'b', action: 'item.put', target: '3f6a…91b4' }),
    event({ id: 'c', action: 'something.new', actor: null, actorEmail: null, ip: null }),
  ];

  function view(props: Partial<Parameters<typeof EventsView>[0]> = {}) {
    const onFilters = vi.fn();
    const onExport = vi.fn();
    renderWithIntl(
      <EventsView
        events={events}
        users={USERS}
        filters={DEFAULT_FILTERS}
        onFilters={onFilters}
        onExport={onExport}
        {...props}
      />,
    );
    return { onFilters, onExport };
  }

  it('words known events, shows an unknown one as its code, and names who did it', () => {
    view();
    expect(screen.getByText('Signed a device out')).toBeInTheDocument();
    expect(screen.getByText('Saved an item')).toBeInTheDocument();
    expect(screen.getByText('3f6a…91b4')).toBeInTheDocument();
    expect(screen.getByText('something.new')).toBeInTheDocument();
    expect(screen.getByText('Server')).toBeInTheDocument();
    expect(screen.getAllByText('jordan@example.co')).toHaveLength(2);
    expect(screen.getAllByText('203.0.113.0')).toHaveLength(2);
  });

  it('changes a filter without losing the others', async () => {
    const { onFilters } = view();
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText('Kind of event'), 'item');
    expect(onFilters).toHaveBeenLastCalledWith({ kind: 'item', user: '', when: '24h' });
    await user.selectOptions(screen.getByLabelText('When'), '7d');
    expect(onFilters).toHaveBeenLastCalledWith({ kind: 'all', user: '', when: '7d' });
    await user.selectOptions(screen.getByLabelText('User'), 'u1');
    expect(onFilters).toHaveBeenLastCalledWith({ kind: 'all', user: 'u1', when: '24h' });
  });

  it('asks the server for the CSV, and says when it was cut short', async () => {
    const { onExport } = view({ truncated: true });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Export as CSV' }));
    expect(onExport).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('status')).toHaveTextContent(/100,000 rows/);
  });

  it('says when nothing happened, and has nothing to export', () => {
    view({ events: [] });
    expect(screen.getByText('No events in this time.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export as CSV' })).toBeDisabled();
  });

  it('pages by cursor', async () => {
    const onMore = vi.fn();
    view({ hasMore: true, onMore });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Show older events' }));
    expect(onMore).toHaveBeenCalled();
  });
});
