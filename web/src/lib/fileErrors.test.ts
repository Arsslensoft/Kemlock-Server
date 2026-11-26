import { describe, expect, it } from 'vitest';
import { describeError } from './errors';
import { ApiErrorFixture } from './lib.fixture';

describe('what the files route refuses', () => {
  it('says the attachment quota in the messages the item page uses too', () => {
    expect(describeError(ApiErrorFixture(403, 'storage-disabled')).id).toBe('error.storageDisabled');
    expect(describeError(ApiErrorFixture(413, 'storage-limit-reached')).id).toBe('error.storageFull');
    expect(describeError(ApiErrorFixture(413, 'storage-limit-exceeded')).id).toBe('error.storageTooBig');
  });

  it('says a file that is larger than the server takes', () => {
    expect(describeError(ApiErrorFixture(413, 'file-too-large', { maxSize: 1000 })).id).toBe('itemForm.error.fileTooLarge');
  });
});

describe('what an account whose email is not confirmed is told', () => {
  it('says to open the link in the mail', () => {
    expect(describeError(ApiErrorFixture(403, 'email-not-confirmed')).id).toBe('error.emailNotConfirmed');
  });
});
