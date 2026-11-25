import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it } from 'vitest';
import { refreshSpaces, spacesKey, writableCollectionsKey } from './refresh';

describe('refreshSpaces', () => {
  it('stales the space list, one space, and the collections a new item may go to', async () => {
    const client = new QueryClient();
    client.setQueryData(spacesKey, []);
    client.setQueryData(['spaces', 's1'], {});
    client.setQueryData(writableCollectionsKey, []);
    client.setQueryData(['vault'], []);
    await refreshSpaces(client);
    expect(client.getQueryState(spacesKey)?.isInvalidated).toBe(true);
    expect(client.getQueryState(['spaces', 's1'])?.isInvalidated).toBe(true);
    expect(client.getQueryState(writableCollectionsKey)?.isInvalidated).toBe(true);
    expect(client.getQueryState(['vault'])?.isInvalidated).toBe(false);
  });
});
