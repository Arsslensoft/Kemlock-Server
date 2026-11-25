import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { describeAccountError } from '../account/errors';
import { useRun } from '../account/useRun';
import { spaceDeps, spacesKey } from './deps';
import { refreshSpaces } from './refresh';
import { createSpace, loadSpaceList } from './model';
import { SpaceListView } from './SpaceListView';

export default function SpaceList() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const list = useQuery({ queryKey: spacesKey, queryFn: () => loadSpaceList(spaceDeps) });
  const create = useRun();

  return (
    <SpaceListView
      rows={list.data}
      loading={list.isPending}
      error={list.error ? describeAccountError(list.error) : undefined}
      creating={create.pending}
      createError={create.error}
      cryptoAvailable={spaceDeps.crypto.available}
      onOpen={(id) => void navigate({ to: '/spaces/$spaceId', params: { spaceId: id } })}
      onCreate={(input) => {
        void create.run(() => createSpace(spaceDeps, input)).then(async (made) => {
          if (!made) return;
          await refreshSpaces(queryClient);
          await navigate({ to: '/spaces/$spaceId', params: { spaceId: made.space.id } });
        });
      }}
    />
  );
}
