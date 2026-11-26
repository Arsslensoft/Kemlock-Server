// The /kem/v1/spaces routes, as crates/kemlock-api-kem/src/routes/spaces.rs writes them: camelCase,
// ids are UUIDs, times are Unix seconds, every binary value is base64url without padding. Names
// are encrypted under the space key, so the server only ever holds them as base64url ciphertext.
import type { Api } from './client';

export type SpaceRole = 'owner' | 'admin' | 'custom' | 'member';
export type MemberState = 'invited' | 'accepted' | 'confirmed' | 'revoked';
export type CustomPermission = 'manage-users' | 'manage-groups' | 'create-collections';
export type CollectionPermission =
  | 'view'
  | 'view-hide-passwords'
  | 'edit'
  | 'edit-hide-passwords'
  | 'manage';

export const ROLES: SpaceRole[] = ['owner', 'admin', 'custom', 'member'];
export const CUSTOM_PERMISSIONS: CustomPermission[] = [
  'manage-users',
  'manage-groups',
  'create-collections',
];
export const COLLECTION_PERMISSIONS: CollectionPermission[] = [
  'view',
  'view-hide-passwords',
  'edit',
  'edit-hide-passwords',
  'manage',
];

export interface SpaceDto {
  id: string;
  /** The name under the space key. */
  name: string;
  keyVersion: number;
  /** Set while the space waits for its keys to be replaced; writes are paused (423). */
  keysPendingSince: number | null;
  createdAt: number;
}

export interface ConfirmationDto {
  by: string;
  at: number;
  fingerprint: string;
  memberKeyVersion: number;
  statement: string;
  signature: string;
}

export interface MemberDto {
  user: string;
  role: SpaceRole;
  custom: CustomPermission[];
  state: MemberState;
  invitedBy: string;
  invitedAt: number;
  acceptedAt: number | null;
  /** The space key sealed to this member; present only while confirmed. */
  sealedSpaceKey: string | null;
  keyVersion: number | null;
  confirmation: ConfirmationDto | null;
  revokedAt: number | null;
}

export interface MemberViewDto extends MemberDto {
  email: string;
  name: string | null;
  /** The account's public-key bundle: what the fingerprint is of. */
  publicBundle: string;
  bundleSignature: string;
  userKeyVersion: number;
  needsReconfirmation: boolean;
  /**
   * An invited member of a Bitwarden organization who has a Bitwarden invitation, so an owner or
   * admin can copy its link. Left out by a server that doesn't say, which counts as no.
   */
  bitwardenInvitation?: boolean;
}

export interface CollectionDto {
  id: string;
  parent: string | null;
  name: string;
  keyVersion: number;
  staleSince: number | null;
}

export interface GroupDto {
  id: string;
  name: string;
  members: string[];
}

export interface GrantDto {
  collection: string;
  /** `user:<uuid>` or `group:<uuid>`. */
  grantee: string;
  permission: CollectionPermission;
}

export interface KeyCopyDto {
  collection: string;
  keyVersion: number;
  sealed: string;
}

export interface SpaceSummaryDto {
  space: SpaceDto;
  member: MemberDto;
}

export interface SpaceViewDto {
  space: SpaceDto;
  me: MemberDto;
  collections: CollectionDto[];
  groups: GroupDto[];
  grants: GrantDto[];
  /** The collection keys sealed to the caller. */
  collectionKeys: KeyCopyDto[];
  /**
   * Whether the space is a Bitwarden organization, so the page offers an invited member's invitation
   * link only there. Left out by a server that doesn't say, which counts as no.
   */
  bitwardenOrganization?: boolean;
}

export interface OffboardedDto {
  exposed: Array<{ collection: string; liveItems: number }>;
  keysPending: boolean;
}

export interface UserKeyDto {
  user: string;
  sealed: string;
}
export interface CollectionKeyDto {
  collection: string;
  user: string;
  sealed: string;
}

export interface CreateSpaceRequest {
  id: string;
  name: string;
  sealedSpaceKey: string;
  collection: { id: string; name: string; sealedKey: string };
}

export interface InviteRequest {
  email: string;
  role: SpaceRole;
  custom?: CustomPermission[];
  grants?: Array<{ collection: string; permission: CollectionPermission }>;
}

export interface ConfirmRequest {
  /** The 64-byte fingerprint the confirmer compared. */
  fingerprint: string;
  statement: string;
  /** The confirmer's sig1 signature over the statement. */
  signature: string;
  sealedSpaceKey: string;
  collectionKeys: Array<{ collection: string; sealed: string }>;
}

export interface CreateCollectionRequest {
  id: string;
  parent?: string | null;
  name: string;
  grants?: Array<{ grantee: string; permission: CollectionPermission }>;
  keys?: UserKeyDto[];
}

export interface EditCollectionRequest {
  name?: string;
  parent?: string;
  moveToTop?: boolean;
}

export interface CreateGroupRequest {
  id: string;
  name: string;
  members?: string[];
}

export interface EditGroupRequest {
  name?: string;
  members?: string[];
  keys?: CollectionKeyDto[];
}

export interface GrantRequest {
  collection: string;
  grantee: string;
  permission: CollectionPermission;
  keys?: UserKeyDto[];
}

/** A signed record of a space's chain, as the server serves it (docs/crypto.md, "Wire form"). */
export interface ChainRecordDto {
  /** The record's exact bytes, base64url. */
  entry: string;
  /** The signer's sig1 signature, base64url. */
  signature: string;
  /** A rekey's second signature. */
  cosignature?: string;
}

/** The hash of a box a record committed (GET /chain/{seq}/seals). */
export interface SealHashDto {
  bundleVersion: number;
  /** "space" or "collection:<uuid>" */
  key: string;
  member: string;
  sealHash: string;
  version: number;
}

const base = (space?: string) => `/kem/v1/spaces${space ? `/${space}` : ''}`;

type Http = Pick<Api, 'request' | 'send'>;

export function createSpacesApi(http: Http) {
  return {
    list: () => http.request<SpaceSummaryDto[]>({ method: 'GET', path: base() }),
    create: (body: CreateSpaceRequest) =>
      http.request<SpaceViewDto>({ method: 'POST', path: base(), body }),
    get: (space: string) => http.request<SpaceViewDto>({ method: 'GET', path: base(space) }),
    /** The space's chain from `from` (default 0): empty for a space that has none. */
    chain: (space: string, from?: number) =>
      http.request<ChainRecordDto[]>({
        method: 'GET',
        path: `${base(space)}/chain`,
        ...(from === undefined ? {} : { query: { from } }),
      }),
    /** The seal hashes record `seq` committed. */
    chainSeals: (space: string, seq: number) =>
      http.request<SealHashDto[]>({ method: 'GET', path: `${base(space)}/chain/${seq}/seals` }),
    members: (space: string) =>
      http.request<MemberViewDto[]>({ method: 'GET', path: `${base(space)}/members` }),
    invite: (space: string, body: InviteRequest) =>
      http.request<MemberDto>({ method: 'POST', path: `${base(space)}/members`, body }),
    /** `user` may be `me`. */
    accept: (space: string, user: string) =>
      http.request<MemberDto>({ method: 'POST', path: `${base(space)}/members/${user}/accept` }),
    confirm: (space: string, user: string, body: ConfirmRequest) =>
      http.request<MemberDto>({
        method: 'POST',
        path: `${base(space)}/members/${user}/confirm`,
        body,
      }),
    changeRole: (space: string, user: string, role: SpaceRole, custom: CustomPermission[]) =>
      http.request<MemberDto>({
        method: 'PUT',
        path: `${base(space)}/members/${user}/role`,
        body: { role, custom },
      }),
    revoke: (space: string, user: string) =>
      http.request<OffboardedDto>({ method: 'POST', path: `${base(space)}/members/${user}/revoke` }),
    restore: (space: string, user: string) =>
      http.request<MemberDto>({ method: 'POST', path: `${base(space)}/members/${user}/restore` }),
    remove: (space: string, user: string) =>
      http.request<OffboardedDto>({ method: 'DELETE', path: `${base(space)}/members/${user}` }),
    createCollection: (space: string, body: CreateCollectionRequest) =>
      http.request<CollectionDto>({ method: 'POST', path: `${base(space)}/collections`, body }),
    editCollection: (space: string, collection: string, body: EditCollectionRequest) =>
      http.request<CollectionDto>({
        method: 'PUT',
        path: `${base(space)}/collections/${collection}`,
        body,
      }),
    deleteCollection: (space: string, collection: string) =>
      http.send({ method: 'DELETE', path: `${base(space)}/collections/${collection}` }),
    createGroup: (space: string, body: CreateGroupRequest) =>
      http.request<GroupDto>({ method: 'POST', path: `${base(space)}/groups`, body }),
    editGroup: (space: string, group: string, body: EditGroupRequest) =>
      http.request<GroupDto>({ method: 'PUT', path: `${base(space)}/groups/${group}`, body }),
    deleteGroup: (space: string, group: string) =>
      http.send({ method: 'DELETE', path: `${base(space)}/groups/${group}` }),
    grant: (space: string, body: GrantRequest) =>
      http.request<GrantDto>({ method: 'PUT', path: `${base(space)}/grants`, body }),
    revokeGrant: (space: string, collection: string, grantee: string) =>
      http.send({
        method: 'DELETE',
        path: `${base(space)}/grants/${collection}/${grantee}`,
      }),
  };
}

export type SpacesApi = ReturnType<typeof createSpacesApi>;
