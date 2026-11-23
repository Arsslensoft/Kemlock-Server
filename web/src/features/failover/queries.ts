import { queryOptions } from '@tanstack/react-query';
import { createPlacementApi } from '@/api/placement';
import { api } from '@/app/services';

export const placementApi = createPlacementApi(api);

/** Polled slowly: the banner has to notice a home server that went away or came back. */
export const placementQuery = queryOptions({
  queryKey: ['placement'],
  queryFn: () => placementApi.placement(),
  refetchInterval: 30_000,
  staleTime: 10_000,
  retry: false,
});
