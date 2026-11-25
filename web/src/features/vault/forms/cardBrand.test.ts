import { describe, expect, it } from 'vitest';
import {
  cardCodeProblem,
  cardDigits,
  cardNumberProblem,
  cvcStatus,
  detectBrand,
  formatCardNumber,
  groupDigits,
  luhn,
  numberStatus,
} from './cardBrand';

// Well-known test numbers, each passing the Luhn check.
const SAMPLES: Array<[string, string]> = [
  ['4111111111111111', 'Visa'],
  ['4222222222222', 'Visa'],
  ['5555555555554444', 'Mastercard'],
  ['2221000000000009', 'Mastercard'],
  ['378282246310005', 'American Express'],
  ['6011111111111117', 'Discover'],
  ['30569309025904', 'Diners Club'],
  ['3530111333300000', 'JCB'],
  ['6200000000000005', 'UnionPay'],
  ['6759649826438453', 'Maestro'],
];

describe('detectBrand', () => {
  it('names the eight brands from the start of the number', () => {
    for (const [number, brand] of SAMPLES) expect(detectBrand(number)?.name, number).toBe(brand);
    expect(detectBrand('4')?.name).toBe('Visa');
    expect(detectBrand('34')?.name).toBe('American Express');
  });

  it('names none for a number no brand starts like', () => {
    expect(detectBrand('')).toBeUndefined();
    expect(detectBrand('000000000000')).toBeUndefined();
    expect(detectBrand('9')).toBeUndefined();
  });
});

describe('luhn', () => {
  it('passes the test numbers and fails a mistyped digit', () => {
    for (const [number] of SAMPLES) expect(luhn(number), number).toBe(true);
    expect(luhn('4111111111111112')).toBe(false);
    expect(luhn('378282246310006')).toBe(false);
  });
});

describe('grouping', () => {
  it('groups for the brand, and by fours for a number of no brand', () => {
    expect(formatCardNumber('4111111111111111')).toBe('4111 1111 1111 1111');
    expect(formatCardNumber('378282246310005')).toBe('3782 822463 10005');
    expect(formatCardNumber('30569309025904')).toBe('3056 930902 5904');
    expect(formatCardNumber('0000 0000 0000 000')).toBe('0000 0000 0000 000');
    expect(groupDigits('41111', detectBrand('41111'))).toBe('4111 1');
  });

  it('keeps digits only, at most 19', () => {
    expect(cardDigits('4111-1111 1111.1111')).toBe('4111111111111111');
    expect(formatCardNumber('4'.repeat(25)).replace(/ /g, '')).toHaveLength(19);
  });
});

describe('numberStatus', () => {
  it('asks for the number, then says the brand while it is typed', () => {
    expect(numberStatus('', false)).toMatchObject({ state: 'pending', message: 'itemForm.card.type' });
    expect(numberStatus('4111', false)).toMatchObject({
      state: 'pending',
      message: 'itemForm.card.keepTyping',
      values: { brand: 'Visa' },
    });
  });

  it('is valid once it has a length its brand can have and passes the check', () => {
    expect(numberStatus('4111111111111111', false)).toMatchObject({ state: 'ok', message: 'itemForm.card.valid' });
    expect(numberStatus('378282246310005', false)).toMatchObject({ state: 'ok', values: { brand: 'American Express' } });
  });

  it('is wrong when the check digit is wrong, or when there are too many digits', () => {
    expect(numberStatus('4111111111111112', false)).toMatchObject({ state: 'err', message: 'itemForm.card.luhn' });
    expect(numberStatus('37828224631000511', false)).toMatchObject({ state: 'err', message: 'itemForm.card.tooMany' });
  });

  it('waits for the box to lose focus before judging a number that could still grow', () => {
    // 13 digits is a Visa length, but the number may go on to 16.
    expect(numberStatus('4222222222222', false).state).toBe('pending');
    expect(numberStatus('4222222222222', true).state).toBe('ok');
  });

  it('takes a number of no brand as complete at 12 digits', () => {
    expect(numberStatus('00000000000', false).state).toBe('pending');
    expect(numberStatus('000000000000', false)).toMatchObject({ state: 'ok', message: 'itemForm.card.validUnknown' });
    expect(numberStatus('000000000001', false).state).toBe('err');
  });
});

describe('cardNumberProblem', () => {
  it('lets an empty number be, and refuses a wrong length or a wrong check digit', () => {
    expect(cardNumberProblem('')).toBeUndefined();
    expect(cardNumberProblem('4111111111111111')).toBeUndefined();
    expect(cardNumberProblem('411111111111')).toBe('itemForm.card.length');
    expect(cardNumberProblem('37828224631000')).toBe('itemForm.card.length');
    expect(cardNumberProblem('4111111111111112')).toBe('itemForm.card.luhn');
    expect(cardNumberProblem('00000000000')).toBe('itemForm.card.length');
    expect(cardNumberProblem('9'.repeat(20))).toBe('error.cardNumber');
  });
});

describe('the security code', () => {
  it('takes 4 digits for American Express, 3 for the others, 3 or 4 before a brand is known', () => {
    const amex = detectBrand('378282246310005');
    const visa = detectBrand('4111111111111111');
    expect(cvcStatus('', amex, false).message).toBe('itemForm.card.cvc.four');
    expect(cvcStatus('', visa, false).message).toBe('itemForm.card.cvc.three');
    expect(cvcStatus('', undefined, false).message).toBe('itemForm.card.cvc.either');
  });

  it('is wrong at once when it has more digits than the brand uses', () => {
    const visa = detectBrand('4111111111111111');
    expect(cvcStatus('1234', visa, false)).toMatchObject({
      state: 'err',
      message: 'itemForm.card.cvc.uses',
      values: { brand: 'Visa', digits: 3 },
    });
    expect(cvcStatus('1234', undefined, false).state).not.toBe('err');
  });

  it('is wrong when a stored code is longer than any brand\'s, even one of no brand', () => {
    expect(cvcStatus('12345', undefined, false)).toMatchObject({ state: 'err', message: 'itemForm.card.cvc.short' });
    expect(cvcStatus('12345', detectBrand('4111111111111111'), false).state).toBe('err');
    expect(cardCodeProblem('12345', '')).toBe('itemForm.card.cvc.short');
  });

  it('says it is short once the box lost focus', () => {
    const amex = detectBrand('378282246310005');
    expect(cvcStatus('123', amex, false).state).toBe('hint');
    expect(cvcStatus('123', amex, true)).toMatchObject({ state: 'err', values: { digits: 4 } });
    expect(cvcStatus('12', undefined, true)).toMatchObject({ state: 'err', message: 'itemForm.card.cvc.short' });
  });

  it('is checked on Save against the brand', () => {
    expect(cardCodeProblem('', '4111111111111111')).toBeUndefined();
    expect(cardCodeProblem('123', '4111111111111111')).toBeUndefined();
    expect(cardCodeProblem('1234', '4111111111111111')).toBe('itemForm.card.cvc.mismatch');
    expect(cardCodeProblem('123', '378282246310005')).toBe('itemForm.card.cvc.mismatch');
    expect(cardCodeProblem('1234', '378282246310005')).toBeUndefined();
    expect(cardCodeProblem('123', '')).toBeUndefined();
    expect(cardCodeProblem('1234', '')).toBeUndefined();
    expect(cardCodeProblem('12', '')).toBe('itemForm.card.cvc.short');
    expect(cardCodeProblem('12a', '')).toBe('itemForm.card.cvc.short');
  });
});
