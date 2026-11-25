import { describe, expect, it, vi } from 'vitest';
import { ApiError } from './errors';
import { NO_DEFINITIONS, appliesTo, createCustomFieldsApi, readDefinitions } from './customFields';

const FIELD = { id: 'f1', name: 'Employee ID', type: 'text', kinds: 'all' };

describe('readDefinitions', () => {
  it('reads the fields and whether people may add their own', () => {
    expect(
      readDefinitions({
        fields: [FIELD, { id: 'f2', name: 'Security question', type: 'hidden', kinds: ['login', 'card'] }],
        allowOwn: false,
      }),
    ).toEqual({
      fields: [
        { id: 'f1', name: 'Employee ID', type: 'text', kinds: 'all' },
        { id: 'f2', name: 'Security question', type: 'hidden', kinds: ['login', 'card'] },
      ],
      allowOwn: false,
    });
  });

  it('takes a bare list, with people allowed to add their own', () => {
    expect(readDefinitions([FIELD])).toEqual({ fields: [{ ...FIELD }], allowOwn: true });
  });

  it('leaves out a field it cannot read, and a field type it does not know', () => {
    const read = readDefinitions({
      fields: [FIELD, { id: '', name: 'x', type: 'text', kinds: 'all' }, { id: 'f9', name: 'Y', type: 'date', kinds: 'all' }, 7, null],
    });
    expect(read.fields.map((field) => field.id)).toEqual(['f1']);
  });

  it('means no fields and own fields allowed when the answer is nothing', () => {
    expect(readDefinitions(null)).toEqual(NO_DEFINITIONS);
    expect(readDefinitions({})).toEqual(NO_DEFINITIONS);
  });
});

describe('appliesTo', () => {
  it('offers a field on every kind when it says all, else on the kinds it names', () => {
    expect(appliesTo({ id: 'a', name: 'A', type: 'text', kinds: 'all' }, 'contact')).toBe(true);
    expect(appliesTo({ id: 'a', name: 'A', type: 'text', kinds: ['login'] }, 'login')).toBe(true);
    expect(appliesTo({ id: 'a', name: 'A', type: 'text', kinds: ['login'] }, 'card')).toBe(false);
  });
});

describe('the custom fields client', () => {
  it('asks GET /kem/v1/custom-fields', async () => {
    const request = vi.fn(async () => ({ fields: [FIELD], allowOwn: true }));
    const result = await createCustomFieldsApi({ request } as never).list();
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/custom-fields' });
    expect(result.fields).toHaveLength(1);
  });

  it('takes a server without the route as one with no admin fields', async () => {
    const request = vi.fn(async () => {
      throw new ApiError(404, undefined, 'not found');
    });
    expect(await createCustomFieldsApi({ request } as never).list()).toEqual(NO_DEFINITIONS);
  });

  it('lets any other failure through', async () => {
    const request = vi.fn(async () => {
      throw new ApiError(500, undefined, 'boom');
    });
    await expect(createCustomFieldsApi({ request } as never).list()).rejects.toThrow('boom');
  });
});
