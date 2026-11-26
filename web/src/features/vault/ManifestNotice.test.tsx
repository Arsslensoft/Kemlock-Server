import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { NO_WARNING, type ManifestWarning } from '@/manifest/keeper';
import { renderWithIntl } from '@/test/render';
import { ManifestNoticeView } from './ManifestNotice';

const OWN = 'user:99999999-9999-4999-8999-999999999999';
const ID = '11111111-1111-4111-8111-111111111111';

describe('ManifestNoticeView', () => {
  it('shows nothing when all is as signed', () => {
    const { container } = renderWithIntl(<ManifestNoticeView warning={NO_WARNING} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('counts what is older, missing and back, and says what to do', () => {
    const warning: ManifestWarning = {
      manifests: [],
      items: [
        { owner: OWN, id: ID, verdict: 'rolled-back', revision: 1, manifestRevision: 2 },
        { owner: OWN, id: `${ID}x`, verdict: 'rolled-back', revision: 1, manifestRevision: 2 },
        { owner: OWN, id: 'b', verdict: 'missing', manifestRevision: 2 },
        { owner: OWN, id: 'c', verdict: 'resurrected', revision: 3 },
      ],
    };
    renderWithIntl(<ManifestNoticeView warning={warning} />);
    expect(screen.getByRole('status')).toHaveTextContent("What the server holds doesn't match what your devices signed");
    expect(screen.getByText('2 items are older than your devices last saw them.')).toBeInTheDocument();
    expect(screen.getByText('1 item your devices saw is missing.')).toBeInTheDocument();
    expect(screen.getByText('1 deleted item came back.')).toBeInTheDocument();
    expect(screen.getByText(/tell your administrator/)).toBeInTheDocument();
  });

  it.each([
    ['rolled-back' as const, /older signed list of items than this browser has already seen/],
    ['invalid' as const, /could not be verified/],
    ['dropped' as const, /no signed list of items, though this browser has seen one/],
  ])('says what is wrong with a manifest that is %s', (problem, words) => {
    renderWithIntl(<ManifestNoticeView warning={{ manifests: [{ owner: OWN, problem }], items: [] }} />);
    expect(screen.getByText(words)).toBeInTheDocument();
  });

  it('says each problem once, however many owners have it', () => {
    renderWithIntl(
      <ManifestNoticeView
        warning={{
          manifests: [
            { owner: OWN, problem: 'invalid' },
            { owner: 'space:44444444-4444-4444-8444-444444444444', problem: 'invalid' },
          ],
          items: [],
        }}
      />,
    );
    expect(screen.getAllByText(/could not be verified/)).toHaveLength(1);
  });
});
