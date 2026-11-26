// Whether this account has said Pwned Passwords may be asked about its passwords. Opening Health used
// to send one SHA-1 prefix per distinct password, with the person's address, to a third party with
// nobody having said yes. Now nothing is sent until they do, and the answer is kept for the account
// in this browser (the number of passwords and the prefixes are not a secret, but whether to look
// them up is a choice of the person, not of the page).
const KEY = 'kemlock.health.hibp';

/** The part of `Storage` this module uses, so tests can pass a fake. */
export type ChoiceStorage = Pick<Storage, 'getItem' | 'setItem'>;

function browserStorage(): ChoiceStorage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

function keyFor(account: string): string {
  return `${KEY}.${account}`;
}

/** `true` or `false` once the account has answered; `undefined` while nobody has been asked. */
export function readHibpChoice(account: string, storage: ChoiceStorage | undefined = browserStorage()): boolean | undefined {
  try {
    const value = storage?.getItem(keyFor(account));
    return value === 'on' ? true : value === 'off' ? false : undefined;
  } catch {
    return undefined;
  }
}

export function writeHibpChoice(
  account: string,
  on: boolean,
  storage: ChoiceStorage | undefined = browserStorage(),
): void {
  try {
    storage?.setItem(keyFor(account), on ? 'on' : 'off');
  } catch {
    // The answer holds for this page only; the next visit asks again.
  }
}
