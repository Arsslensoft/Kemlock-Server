// Compile-time only: ties the hand-written wire types to the OpenAPI types that
// `npm run gen:api` generates from the running server. Not part of the normal typecheck (the
// generated file isn't committed); tsconfig.wire.json runs it.
import type { components } from './schema.gen';
import type * as W from './types';

type Schemas = components['schemas'];

/** What the server sends must fit what the client reads. */
type Reads<Generated, Client> = [Generated] extends [Client] ? true : never;
/** What the client sends must fit what the server accepts. */
type Sends<Client, Generated> = [Client] extends [Generated] ? true : never;

export const checks: [
  Reads<Schemas['ConfigResponse'], W.ConfigResponse>,
  Reads<Schemas['SetupVerifyResponse'], W.SetupVerifyResponse>,
  Reads<Schemas['PreloginResponse'], W.PreloginResponse>,
  Reads<Schemas['MethodsResponse'], W.MethodsResponse>,
  Reads<Schemas['RegisterStartResponse'], W.RegisterStartResponse>,
  Reads<Schemas['RegisterFinishResponse'], W.RegisterFinishResponse>,
  Reads<Schemas['OpaqueStartResponse'], W.OpaqueStartResponse>,
  Reads<Schemas['SignInResponse'], W.SignInResponse>,
  Reads<Schemas['TokenResponse'], W.TokenResponse>,
  Reads<Schemas['TotpEnrolResponse'], W.TotpEnrolResponse>,
  Reads<Schemas['ItemDto'], W.ItemDto>,
  Reads<Schemas['BatchResponse'], W.BatchResponse>,
  Reads<Schemas['SyncResponse'], W.SyncResponse>,
  Sends<W.SetupVerifyRequest, Schemas['SetupVerifyRequest']>,
  Sends<W.EmailRequest, Schemas['EmailRequest']>,
  Sends<W.RegisterStartRequest, Schemas['RegisterStartRequest']>,
  Sends<W.RegisterFinishRequest, Schemas['RegisterFinishRequest']>,
  Sends<W.OpaqueStartRequest, Schemas['OpaqueStartRequest']>,
  Sends<W.OpaqueFinishRequest, Schemas['OpaqueFinishRequest']>,
  Sends<W.TwoFactorRequest, Schemas['TwoFactorRequest']>,
  Sends<W.RefreshRequest, Schemas['RefreshRequest']>,
  Sends<W.TotpConfirmRequest, Schemas['TotpConfirmRequest']>,
  Sends<W.ItemDto, Schemas['ItemDto']>,
  Sends<W.BatchRequest, Schemas['BatchRequest']>,
] = [
  true, true, true, true, true, true, true, true, true, true, true, true, true,
  true, true, true, true, true, true, true, true, true, true, true,
];
