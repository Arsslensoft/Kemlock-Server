// What the card form knows about a card number as it is typed: the brand it starts like, how it is
// grouped, whether its length and its check digit (Luhn) are right, and how many digits the
// security code takes. There is no Brand box: the brand comes from the number.
import type { MessageId, Values } from '@/i18n';

export interface CardBrand {
  name: string;
  /** What the number starts with. */
  re: RegExp;
  /** The lengths a number of this brand can have. */
  lens: number[];
  /** How the digits are grouped, the last group taking what is left. */
  groups: number[];
  /** Digits in the security code. */
  cvc: 3 | 4;
}

const FROM_16_TO_19 = [16, 17, 18, 19];

// The order matters: the first that matches wins.
export const BRANDS: CardBrand[] = [
  { name: 'American Express', re: /^3[47]/, lens: [15], groups: [4, 6, 5], cvc: 4 },
  { name: 'Diners Club', re: /^3(0[0-5]|[689])/, lens: [14, 15, 16, 17, 18, 19], groups: [4, 6, 4], cvc: 3 },
  { name: 'JCB', re: /^35(2[89]|[3-8])/, lens: FROM_16_TO_19, groups: [4, 4, 4, 4, 3], cvc: 3 },
  { name: 'Discover', re: /^(6011|65|64[4-9])/, lens: FROM_16_TO_19, groups: [4, 4, 4, 4, 3], cvc: 3 },
  { name: 'UnionPay', re: /^62/, lens: FROM_16_TO_19, groups: [4, 4, 4, 4, 3], cvc: 3 },
  {
    name: 'Maestro',
    re: /^(5018|5020|5038|6304|6759|676[1-3])/,
    lens: [12, 13, 14, 15, 16, 17, 18, 19],
    groups: [4, 4, 4, 4, 3],
    cvc: 3,
  },
  {
    name: 'Mastercard',
    re: /^(5[1-5]|222[1-9]|22[3-9]|2[3-6]|27[01]|2720)/,
    lens: [16],
    groups: [4, 4, 4, 4],
    cvc: 3,
  },
  { name: 'Visa', re: /^4/, lens: [13, 16, 19], groups: [4, 4, 4, 4, 3], cvc: 3 },
];

const MOST_DIGITS = 19;
const UNKNOWN_GROUPS = [4, 4, 4, 4, 3];

/** The digits of a card number typed or pasted (kemlock-core `cardDigits`), at most 19. */
export function cardDigits(text: string): string {
  return text.replace(/[^0-9]/g, '');
}

export function detectBrand(digits: string): CardBrand | undefined {
  return BRANDS.find((brand) => brand.re.test(digits));
}

/** Whether the check digit is right (the Luhn check). */
export function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** The digits in groups of the brand's, such as `4111 1111 1111 1111`. */
export function groupDigits(digits: string, brand: CardBrand | undefined): string {
  const out: string[] = [];
  let at = 0;
  for (const size of brand ? brand.groups : UNKNOWN_GROUPS) {
    if (at >= digits.length) break;
    out.push(digits.slice(at, at + size));
    at += size;
  }
  if (at < digits.length) out.push(digits.slice(at));
  return out.join(' ');
}

/** What a typed number is made of: digits only, grouped for its brand, at most 19. */
export function formatCardNumber(text: string): string {
  const digits = cardDigits(text).slice(0, MOST_DIGITS);
  return groupDigits(digits, detectBrand(digits));
}

export interface Status {
  state: 'pending' | 'ok' | 'err';
  message: MessageId;
  values?: Values;
}

/**
 * How the number reads so far. It is complete once it has a length its brand can have (and, short
 * of the longest, once the box lost focus or it has 16 digits); an unknown brand is complete at 12
 * digits. A complete number must pass the Luhn check.
 */
export function numberStatus(digits: string, blurred: boolean): Status {
  const brand = detectBrand(digits);
  const longest = brand ? Math.max(...brand.lens) : MOST_DIGITS;
  if (digits.length > 0 && brand && digits.length > longest) {
    return { state: 'err', message: 'itemForm.card.tooMany', values: { brand: brand.name } };
  }
  const complete = brand
    ? brand.lens.includes(digits.length) && (digits.length === longest || blurred || digits.length >= 16)
    : digits.length >= 12;
  if (!complete) {
    return brand
      ? { state: 'pending', message: 'itemForm.card.keepTyping', values: { brand: brand.name } }
      : { state: 'pending', message: 'itemForm.card.type' };
  }
  if (!luhn(digits)) return { state: 'err', message: 'itemForm.card.luhn' };
  return brand
    ? { state: 'ok', message: 'itemForm.card.valid', values: { brand: brand.name } }
    : { state: 'ok', message: 'itemForm.card.validUnknown' };
}

/** Why a number can't be saved, if it can't: only an empty one is always fine. */
export function cardNumberProblem(digits: string): MessageId | undefined {
  if (digits === '') return undefined;
  const brand = detectBrand(digits);
  if (digits.length > MOST_DIGITS) return 'error.cardNumber';
  if (brand ? !brand.lens.includes(digits.length) : digits.length < 12) return 'itemForm.card.length';
  return luhn(digits) ? undefined : 'itemForm.card.luhn';
}

export interface CvcStatus {
  state: 'hint' | 'ok' | 'err';
  message: MessageId;
  values?: Values;
}

/**
 * How the security code reads: 4 digits for American Express, 3 for the other brands, 3 or 4 before
 * a brand is known. Too many is wrong at once; too few is said once the box lost focus.
 */
export function cvcStatus(code: string, brand: CardBrand | undefined, blurred: boolean): CvcStatus {
  const want = brand?.cvc;
  const hint: CvcStatus = {
    state: 'hint',
    message: want === 4 ? 'itemForm.card.cvc.four' : want === 3 ? 'itemForm.card.cvc.three' : 'itemForm.card.cvc.either',
  };
  if (code === '') return hint;
  if (want !== undefined && code.length > want) {
    return { state: 'err', message: 'itemForm.card.cvc.uses', values: { brand: brand?.name ?? '', digits: want } };
  }
  if (blurred && want !== undefined && code.length < want) {
    return { state: 'err', message: 'itemForm.card.cvc.uses', values: { brand: brand?.name ?? '', digits: want } };
  }
  if (blurred && code.length < 3) return { state: 'err', message: 'itemForm.card.cvc.short' };
  return hint;
}

/** Why a security code can't be saved, if it can't: an empty one is always fine. */
export function cardCodeProblem(code: string, digits: string): MessageId | undefined {
  if (code === '') return undefined;
  if (!/^[0-9]{3,4}$/.test(code)) return 'itemForm.card.cvc.short';
  const want = detectBrand(digits)?.cvc;
  return want !== undefined && code.length !== want ? 'itemForm.card.cvc.mismatch' : undefined;
}
