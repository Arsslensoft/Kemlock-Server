// The vaults of a test person: Personal, and one space called Family (the `SPACE` of tools-fixtures).
import { type Vaults, vaultLabel, vaultOptions } from '@/features/vault/vaults';
import { SPACE } from './tools-fixtures';

export const WORDS = { personal: 'Personal', space: 'A space' };

/** The id the Vault filter stores for the Family space. */
export const FAMILY_ID = SPACE.slice('space:'.length);

const options = vaultOptions([{ id: FAMILY_ID, name: 'Family', state: 'confirmed' }], [], WORDS);

export const VAULTS: Vaults = {
  options,
  labelOf: (owner) => vaultLabel(owner, options, WORDS),
};
