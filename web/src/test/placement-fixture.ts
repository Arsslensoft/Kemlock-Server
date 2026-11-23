import type { Placement } from '@/api/placement';

// Two vaults: the person's own, whose home server is down and served by a replica with a change
// waiting, and a space whose home is up.
export const PLACEMENT: Placement = {
  vaults: [
    {
      id: 'me',
      name: 'Your vault',
      servers: [
        { id: 's1', name: 'Home server', place: 'Home · France', role: 'home', status: 'offline', offlineSince: '2026-11-22T09:12:00Z', inUse: false },
        { id: 's2', name: 'VPS', place: 'Germany', role: 'replica', status: 'online', inUse: true },
      ],
      pending: { id: 'c1', summary: 'Adding jordan@example.org to Family', askedAt: '2026-11-22T09:40:00Z' },
    },
    {
      id: 'sp1',
      name: 'Example Co',
      servers: [
        { id: 's3', name: 'Office server', role: 'home', status: 'online', inUse: true },
        { id: 's2', name: 'VPS', role: 'replica', status: 'online', inUse: false },
      ],
    },
  ],
  apps: [{ name: 'This browser', server: 'VPS' }],
};
