// What writing an item into a space needs: the space key and the collection keys sealed to this
// account, opened in the worker, and the list of collections this account may write to. No React in
// here, so it is tested with fakes.
//
// An item of a space is sealed under the key of its collection (docs/crypto.md leaves the key
// wrap's choice open; see crates/kemlock-wasm/src/spaces.rs), so a member who holds a collection
// holds exactly its items. The server decides who may write (edit on the collection); this list
// only keeps the form from offering what is certain to be refused.
import type { CollectionPermission, GroupDto, SpaceViewDto } from '@/api/spaces';
import { decodeB64 } from '@/lib/b64url';
import type { SpaceDeps } from './model';

const EDIT: CollectionPermission[] = ['edit', 'edit-hide-passwords', 'manage'];

/** Opens the space key and every collection key sealed to this account, and returns the space. */
export async function openSpaceKeys(deps: SpaceDeps, spaceId: string): Promise<SpaceViewDto> {
  const view = await deps.api.get(spaceId);
  const sealed = view.me.sealedSpaceKey;
  if (!sealed) throw new Error('the space key is not sealed to this account yet');
  await deps.crypto.openSpace({
    spaceId,
    keyVersion: view.me.keyVersion ?? view.space.keyVersion,
    sealed: decodeB64(sealed),
  });
  for (const copy of view.collectionKeys) {
    await deps.crypto.openCollection({
      spaceId,
      collectionId: copy.collection,
      keyVersion: copy.keyVersion,
      sealed: decodeB64(copy.sealed),
    });
  }
  return view;
}

/**
 * A loader for `VaultDeps.ensureSpaceKeys`: opens a space's keys at most once while they are
 * held. `forget` drops the memory when the vault locks, because the worker forgets the keys then.
 */
export function createSpaceKeyLoader(deps: SpaceDeps) {
  const loaded = new Map<string, Promise<void>>();
  return {
    ensure(spaceId: string): Promise<void> {
      let pending = loaded.get(spaceId);
      if (!pending) {
        pending = openSpaceKeys(deps, spaceId).then(() => undefined);
        // A failure is not remembered: the next item of the space tries again.
        pending.catch(() => loaded.delete(spaceId));
        loaded.set(spaceId, pending);
      }
      return pending;
    },
    forget(): void {
      loaded.clear();
    },
  };
}

export interface WritableCollection {
  spaceId: string;
  spaceName: string;
  collectionId: string;
  collectionName: string;
}

/** Whether a grant, directly or through a group, lets `user` edit `collection`. */
export function canEditCollection(
  view: Pick<SpaceViewDto, 'me' | 'grants'>,
  groups: Array<Pick<GroupDto, 'id' | 'members'>>,
  collection: string,
): boolean {
  const { role, user } = view.me;
  if (role === 'owner' || role === 'admin') return true;
  return view.grants.some((grant) => {
    if (grant.collection !== collection || !EDIT.includes(grant.permission)) return false;
    const [kind, id] = grant.grantee.split(':');
    if (kind === 'user') return id === user;
    if (kind === 'group') return groups.find((g) => g.id === id)?.members.includes(user) ?? false;
    return false;
  });
}

/**
 * The collections of the spaces this account belongs to that it holds a key for and may edit, with
 * their names opened. A space whose keys do not open is left out, not an error.
 */
export async function loadWritableCollections(deps: SpaceDeps): Promise<WritableCollection[]> {
  const summaries = await deps.api.list();
  const out: WritableCollection[] = [];
  for (const summary of summaries) {
    if (summary.member.state !== 'confirmed' || !summary.member.sealedSpaceKey) continue;
    const spaceId = summary.space.id;
    try {
      const view = await openSpaceKeys(deps, spaceId);
      const held = new Set(view.collectionKeys.map((copy) => copy.collection));
      const name = (kind: 'space' | 'collection', id: string, sealed: string) =>
        deps.crypto.openName({
          spaceId,
          keyVersion: view.space.keyVersion,
          kind,
          id,
          ciphertext: decodeB64(sealed),
        });
      const spaceName = await name('space', spaceId, view.space.name);
      for (const collection of view.collections) {
        if (!held.has(collection.id) || !canEditCollection(view, view.groups, collection.id)) continue;
        out.push({
          spaceId,
          spaceName,
          collectionId: collection.id,
          collectionName: await name('collection', collection.id, collection.name),
        });
      }
    } catch {
      // This space's keys did not open here: it offers nothing, and the others still do.
    }
  }
  return out;
}
