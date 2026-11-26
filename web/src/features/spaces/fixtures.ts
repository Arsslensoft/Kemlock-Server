// A small space for the tests: me (owner), Theo who accepted and waits for confirmation, Lee who
// is confirmed in a group, two collections and the grants between them.
import type {
  CollectionDto,
  MemberDto,
  MemberViewDto,
  SpaceDto,
  SpaceViewDto,
  SpacesApi,
} from '@/api/spaces';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
import { fingerprintBytes, fingerprintText } from '@/sharing/bundle';
import { makeBundleB64 } from '@/test/bundles';
import { vi } from 'vitest';
import type { SpaceDetail } from './model';

export const SPACE = '10000000-0000-4000-8000-000000000001';
export const ME = '20000000-0000-4000-8000-000000000001';
export const THEO = '20000000-0000-4000-8000-000000000002';
export const LEE = '20000000-0000-4000-8000-000000000003';
export const INFRA = '30000000-0000-4000-8000-000000000001';
export const FINANCE = '30000000-0000-4000-8000-000000000002';
export const OPS = '40000000-0000-4000-8000-000000000001';

/** What the fake crypto's `sealName` makes, as the server would hold it. */
export function sealedName(kind: string, id: string, name: string, keyVersion = 1): string {
  return encodeB64(utf8(JSON.stringify([SPACE, keyVersion, kind, id, name])));
}

export function member(user: string, over: Partial<MemberDto> = {}): MemberDto {
  return {
    user,
    role: 'member',
    custom: [],
    state: 'confirmed',
    invitedBy: ME,
    invitedAt: 1_700_000_000,
    acceptedAt: 1_700_000_100,
    sealedSpaceKey: encodeB64(utf8('sealed-space-key')),
    keyVersion: 1,
    confirmation: null,
    revokedAt: null,
    ...over,
  };
}

export function memberView(user: string, email: string, over: Partial<MemberViewDto> = {}): MemberViewDto {
  return {
    ...member(user),
    email,
    name: null,
    publicBundle: makeBundleB64(user),
    bundleSignature: encodeB64(utf8('sig')),
    userKeyVersion: 1,
    needsReconfirmation: false,
    ...over,
  };
}

export const space: SpaceDto = {
  id: SPACE,
  name: sealedName('space', SPACE, 'Example Co'),
  keyVersion: 1,
  keysPendingSince: null,
  createdAt: 1_700_000_000,
};

function collection(id: string, name: string): CollectionDto {
  return { id, parent: null, name: sealedName('collection', id, name), keyVersion: 1, staleSince: null };
}

export function spaceView(over: Partial<SpaceViewDto> = {}): SpaceViewDto {
  return {
    space,
    me: member(ME, { role: 'owner' }),
    collections: [collection(INFRA, 'Infrastructure'), collection(FINANCE, 'Finance')],
    groups: [{ id: OPS, name: sealedName('group', OPS, 'Ops'), members: [LEE] }],
    grants: [
      { collection: INFRA, grantee: `group:${OPS}`, permission: 'edit' },
      { collection: FINANCE, grantee: `user:${THEO}`, permission: 'view' },
    ],
    collectionKeys: [
      { collection: INFRA, keyVersion: 1, sealed: encodeB64(utf8('ck-infra')) },
      { collection: FINANCE, keyVersion: 1, sealed: encodeB64(utf8('ck-finance')) },
    ],
    ...over,
  };
}

export function members(): MemberViewDto[] {
  return [
    memberView(ME, 'sam@example.co', { role: 'owner', name: 'Sam Rivera' }),
    memberView(THEO, 'theo@example.co', { state: 'accepted', name: 'Theo Grant' }),
    memberView(LEE, 'lee@example.co', { name: 'Lee Wong' }),
  ];
}

/**
 * The member as someone else's confirmation would leave them: `by` signed (as the fake crypto
 * signs) that they compared this member's bundle.
 */
export async function confirmedBy(by: string, view: MemberViewDto): Promise<MemberViewDto> {
  const fingerprint = await fingerprintBytes(decodeB64(view.publicBundle));
  const statement = utf8(JSON.stringify(['confirm', SPACE, view.user, view.userKeyVersion]));
  return {
    ...view,
    confirmation: {
      by,
      at: 1_700_000_200,
      fingerprint: encodeB64(fingerprint),
      memberKeyVersion: view.userKeyVersion,
      statement: encodeB64(statement),
      signature: encodeB64(utf8(`sig>confirm>${fromUtf8(statement)}`)),
    },
  };
}

/** The fingerprint text of a member's listed bundle: what the fake crypto answers as my own. */
export async function fingerprintTextOf(view: MemberViewDto): Promise<string> {
  return fingerprintText(await fingerprintBytes(decodeB64(view.publicBundle)));
}

/** The members with Lee confirmed by me, so a key may be sealed to either. */
export async function confirmedMembers(): Promise<MemberViewDto[]> {
  return Promise.all(members().map((m) => (m.user === LEE ? confirmedBy(ME, m) : m)));
}

/** A loaded detail, names already open, for the view tests. */
export function detail(over: Partial<SpaceDetail> = {}): SpaceDetail {
  const view = spaceView();
  return {
    view,
    members: members(),
    name: 'Example Co',
    readable: true,
    collections: [
      { ...(view.collections[0] as CollectionDto), title: 'Infrastructure' },
      { ...(view.collections[1] as CollectionDto), title: 'Finance' },
    ],
    groups: [{ ...(view.groups[0] as SpaceViewDto['groups'][number]), title: 'Ops' }],
    ...over,
  };
}

/** A fake spaces client: every call is a typed mock that resolves with a plausible answer. */
export function fakeSpacesApi() {
  return {
    list: vi.fn<SpacesApi['list']>(async () => [{ space, member: member(ME, { role: 'owner' }) }]),
    create: vi.fn<SpacesApi['create']>(async () => spaceView()),
    get: vi.fn<SpacesApi['get']>(async () => spaceView()),
    members: vi.fn<SpacesApi['members']>(async () => members()),
    invite: vi.fn<SpacesApi['invite']>(async () => member(THEO, { state: 'invited' })),
    accept: vi.fn<SpacesApi['accept']>(async () => member(ME)),
    confirm: vi.fn<SpacesApi['confirm']>(async () => member(THEO)),
    changeRole: vi.fn<SpacesApi['changeRole']>(async () => member(THEO)),
    revoke: vi.fn<SpacesApi['revoke']>(async () => ({ exposed: [], keysPending: true })),
    restore: vi.fn<SpacesApi['restore']>(async () => member(THEO)),
    remove: vi.fn<SpacesApi['remove']>(async () => ({ exposed: [], keysPending: true })),
    createCollection: vi.fn<SpacesApi['createCollection']>(async () =>
      collection(INFRA, 'Infrastructure'),
    ),
    editCollection: vi.fn<SpacesApi['editCollection']>(async () => collection(INFRA, 'Infrastructure')),
    deleteCollection: vi.fn<SpacesApi['deleteCollection']>(async () => undefined),
    createGroup: vi.fn<SpacesApi['createGroup']>(async () => ({ id: OPS, name: '', members: [] })),
    editGroup: vi.fn<SpacesApi['editGroup']>(async () => ({ id: OPS, name: '', members: [] })),
    deleteGroup: vi.fn<SpacesApi['deleteGroup']>(async () => undefined),
    grant: vi.fn<SpacesApi['grant']>(async () => ({
      collection: INFRA,
      grantee: `user:${LEE}`,
      permission: 'view',
    })),
    revokeGrant: vi.fn<SpacesApi['revokeGrant']>(async () => undefined),
  };
}
