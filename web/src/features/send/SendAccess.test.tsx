import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import type { AccessDto } from '@/api/sends';
import { encodeB64, utf8 } from '@/lib/b64url';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { renderWithIntl } from '@/test/render';
import SendAccess from './SendAccess';
import type { RecipientDeps } from './recipient';
import { makeSend } from './sendCrypto';


const ACCESS_ID =encodeB64(new Uint8Array(16).fill(9));

function problem(status: number, slug: string): ApiError {
  return new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: slug, status });
}

async function sealed(kind: 'text' | 'file', json: object) {
  resetFakeCrypto();
  await crypto.unlock('u', utf8('wrapped:u'), new Uint8Array(), new Uint8Array());
  const key = (
    await makeSend(
      { kind: 'text', name: 'n', text: 't', deleteAfterDays: 1, maxViews: null, hideEmail: false },
      { crypto },
    )
  ).key;
  const parts = await crypto.sealSend({
    id: ACCESS_ID,
    kind,
    linkKey: key,
    payloadJson: JSON.stringify(json),
    metaJson: '{}',
  });
  await crypto.lock();
  return { key, payload: encodeB64(parts.payload) };
}

const access = (kind: 'text' | 'file', payload: string): AccessDto => ({
  id: ACCESS_ID,
  kind,
  payload,
  fileSize: null,
  expiresAt: null,
  deletionAt: 1_795_000_000,
  senderEmail: 'sam@example.co',
});

describe('SendAccess', () => {
  beforeEach(() => resetFakeCrypto());

  it('shows a note opened with the key from the link', async () => {
    const { key, payload } = await sealed('text', { name: 'Door code', text: '4 7 1 9' });
    const deps: RecipientDeps = {
      access: { open: async () => access('text', payload), file: vi.fn() },
      crypto,
    };
    renderWithIntl(<SendAccess link={{ accessId: ACCESS_ID, key }} deps={deps} />);
    expect(await screen.findByRole('heading', { name: 'Door code', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('4 7 1 9')).toBeInTheDocument();
    expect(screen.getByText(/From sam@example\.co/)).toBeInTheDocument();
  });

  it('asks for the password, says when it is wrong, and opens with the right one', async () => {
    const { key, payload } = await sealed('text', { name: 'Vault door', text: 'open sesame' });
    const proof = encodeB64(await crypto.sendProof(ACCESS_ID, key, 'swordfish'));
    const open = vi.fn(async (_id: string, password?: string) => {
      if (password === undefined) throw problem(401, 'send-password-required');
      if (password !== proof) throw problem(401, 'send-wrong-password');
      return access('text', payload);
    });
    renderWithIntl(
      <SendAccess link={{ accessId: ACCESS_ID, key }} deps={{ access: { open, file: vi.fn() }, crypto }} />,
    );
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Open the Send' }));
    expect(await screen.findByText('That password is wrong.')).toBeInTheDocument();
    await user.clear(screen.getByLabelText('Password'));
    await user.type(screen.getByLabelText('Password'), 'swordfish');
    await user.click(screen.getByRole('button', { name: 'Open the Send' }));
    expect(await screen.findByText('open sesame')).toBeInTheDocument();
  });

  it('downloads a file Send as the decrypted bytes', async () => {
    const { key, payload } = await sealed('file', { name: 'lease.pdf', mime: 'application/pdf', size: 3 });
    const fileBytes = await crypto.sealSendFile(key, utf8('abc'));
    const save = vi.fn();
    const deps: RecipientDeps = {
      access: { open: async () => access('file', payload), file: async () => fileBytes },
      crypto,
    };
    renderWithIntl(<SendAccess link={{ accessId: ACCESS_ID, key }} deps={deps} save={save} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Download lease.pdf' }));
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const [name, mime, bytes] = save.mock.calls[0] as [string, string, Uint8Array];
    expect([name, mime, new TextDecoder().decode(bytes)]).toEqual(['lease.pdf', 'application/pdf', 'abc']);
  });

  it('says a link that is not a Send link is not one, and asks the server nothing', () => {
    const open = vi.fn();
    renderWithIntl(<SendAccess link={null} deps={{ access: { open, file: vi.fn() }, crypto }} />);
    expect(screen.getByRole('heading', { name: 'This link is not a Send link' })).toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  });

  it('says so when the Send is gone', async () => {
    const deps: RecipientDeps = {
      access: { open: () => Promise.reject(problem(404, 'not-found')), file: vi.fn() },
      crypto,
    };
    renderWithIntl(<SendAccess link={{ accessId: ACCESS_ID, key: 'A'.repeat(43) }} deps={deps} />);
    expect(await screen.findByRole('heading', { name: 'This Send is not available' })).toBeInTheDocument();
  });
});
