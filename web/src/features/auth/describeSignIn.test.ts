import { describe, expect, it } from 'vitest';
import { ApiError, NetworkError } from '@/api/errors';
import { PasskeyError, SecurityKeyRejectedError } from '@/lib/passkey';
import { describePasskeySignInError, describeSignInError, secondStepIsOver } from './describeSignIn';
import { NoSignInWaiting } from './signIn';

const unauthorized = () =>
  new ApiError(401, { type: 'urn:kemlock:problem:unauthorized', title: 'no', status: 401 });

describe('describeSignInError', () => {
  it('words a passkey that did not answer', () => {
    expect(describeSignInError(new PasskeyError('cancelled')).id).toBe('signIn.passkeyCancelled');
    expect(describeSignInError(new PasskeyError('unavailable')).id).toBe('signIn.passkeyUnavailable');
  });

  it('describes anything else as everywhere else', () => {
    expect(describeSignInError(unauthorized()).id).toBe('error.credentials');
    expect(describeSignInError(new NetworkError(new Error('offline'))).id).toBe('error.network');
  });
});

describe('describePasskeySignInError', () => {
  it('does not call a refused security key a wrong password', () => {
    expect(describeSignInError(new SecurityKeyRejectedError()).id).toBe('password.keyRejected');
  });

  it('does not call a refused passkey a wrong password', () => {
    // The browser offered a security key added as a second step: /auth/passkey/verify says 401.
    expect(describePasskeySignInError(unauthorized()).id).toBe('signIn.passkeyRejected');
  });

  it('keeps the other words', () => {
    expect(describePasskeySignInError(new PasskeyError('cancelled')).id).toBe('signIn.passkeyCancelled');
    expect(describePasskeySignInError(new NetworkError(new Error('offline'))).id).toBe('error.network');
    expect(
      describePasskeySignInError(new ApiError(500, { type: 'urn:kemlock:problem:internal', title: 'x', status: 500 })).id,
    ).toBe('error.server');
  });
});

describe('secondStepIsOver', () => {
  it('sends the person back to the password when the challenge expired, was used or is gone', () => {
    const expired = unauthorized();
    expect(secondStepIsOver(expired, describeSignInError(expired))).toBe(true);
    const gone = new NoSignInWaiting('code');
    expect(secondStepIsOver(gone, describeSignInError(gone))).toBe(true);
  });

  it('lets a dropped connection or a missing key be tried again', () => {
    const offline = new NetworkError(new Error('offline'));
    expect(secondStepIsOver(offline, describeSignInError(offline))).toBe(false);
    const key = new SecurityKeyRejectedError();
    expect(secondStepIsOver(key, describeSignInError(key))).toBe(false);
  });
});
