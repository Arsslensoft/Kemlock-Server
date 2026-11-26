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
    event({ id: 'd', action: 'auth.passkey_sign_in' }),
    event({ id: 'c', action: 'something.new', actor: null, actorEmail: null, ip: null }),
    event({
      id: 'e',
      action: 'bw.event',
      target: JSON.stringify({
        type: 1107,
        cipherId: '265920f3-088e-47d9-bd7b-dfc31cd17f1a',
        organizationId: 'dd99347a-052a-44a5-9441-517e4aefd8a9',
        deviceType: 9,
        ipAddress: '203.0.113.0/24',
      }),
    }),
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

  it('words every event, even one it has no message for, and names who did it', () => {
    view();
    expect(screen.getByText('Signed a device out')).toBeInTheDocument();
    expect(screen.getByText('Saved an item')).toBeInTheDocument();
    expect(screen.getByText('Signed in with a passkey')).toBeInTheDocument();
    expect(screen.getByText('3f6a…91b4')).toBeInTheDocument();
    expect(screen.getByText('Other: new')).toBeInTheDocument();
    expect(screen.queryByText('something.new')).not.toBeInTheDocument();
    // A Bitwarden event: its type in words, and the item it was about instead of the JSON.
    expect(screen.getByText('Viewed an item (Bitwarden API)')).toBeInTheDocument();
    expect(screen.getByText('265920f3-088e-47d9-bd7b-dfc31cd17f1a')).toBeInTheDocument();
    expect(screen.queryByText(/"type"/)).not.toBeInTheDocument();
    // The code stays on the cell, for matching a row to the CSV export.
    expect(screen.getByText('Other: new').closest('td')).toHaveAttribute('title', 'something.new');
    expect(screen.getByText('Server')).toBeInTheDocument();
    expect(screen.getAllByText('jordan@example.co')).toHaveLength(4);
    expect(screen.getAllByText('203.0.113.0')).toHaveLength(4);
  });

  it('renders markup in an event as inert text, never as elements', () => {
    const hostile = '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script>';
    const { container } = renderWithIntl(
      <EventsView
        events={[
          event({ id: 'x1', action: `item.${hostile}`, target: hostile }),
          event({ id: 'x2', action: 'bw.event', target: JSON.stringify({ type: 1107, cipherId: hostile }) }),
          event({ id: 'x3', action: hostile, actorEmail: hostile, ip: hostile }),
        ]}
        users={USERS}
        filters={DEFAULT_FILTERS}
        onFilters={vi.fn()}
        onExport={vi.fn()}
      />,
    );
    expect(container.querySelector('tbody img, tbody script')).toBeNull();
    expect((window as { __xss?: number }).__xss).toBeUndefined();
    // A server target is shown as text, as it is; a Bitwarden one only if it is a UUID.
    expect(screen.getAllByText(hostile)).toHaveLength(3);
  });

  it('words the device and custom field changes, and shows what each names', () => {
    view({
      events: [
        event({ id: 'u', action: 'device.untrust', target: '50000000-0000-4000-8000-0000000000a1' }),
        event({ id: 'c', action: 'admin.custom_field.create', target: '7d0f3a52-6c1d-4f3b-9a58-2e3b5a0a9c11' }),
        event({ id: 'e', action: 'admin.custom_field.update' }),
        event({ id: 'd', action: 'admin.custom_field.delete' }),
        event({ id: 'o', action: 'admin.custom_field.allow_own', target: 'false' }),
      ],
    });
    expect(screen.getByText('Stopped trusting a device')).toBeInTheDocument();
    expect(screen.getByText('Added a custom field')).toBeInTheDocument();
    expect(screen.getByText('Changed a custom field')).toBeInTheDocument();
    expect(screen.getByText('Removed a custom field')).toBeInTheDocument();
    expect(screen.getByText('Changed whether people may add their own fields')).toBeInTheDocument();
    expect(screen.getByText('7d0f3a52-6c1d-4f3b-9a58-2e3b5a0a9c11')).toBeInTheDocument();
    expect(screen.queryByText('device.untrust')).toBeNull();
    expect(screen.queryByText('admin.custom_field.create')).toBeNull();
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
