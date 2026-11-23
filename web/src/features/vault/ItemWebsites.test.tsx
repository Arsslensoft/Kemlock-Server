import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { WebsitesView, type WebsiteRow } from './ItemWebsites';

function Harness({
  initial,
  onSave = vi.fn(),
}: {
  initial: WebsiteRow[];
  onSave?: (rows: WebsiteRow[]) => void;
}) {
  const [rows, setRows] = useState(initial);
  return (
    <WebsitesView
      name="Example Co SSO"
      rows={rows}
      onChange={setRows}
      onSave={() => onSave(rows)}
      onCancel={vi.fn()}
    />
  );
}

const START: WebsiteRow[] = [
  { key: 1, uri: 'example.co', match: 'domain' },
  { key: 2, uri: 'example-co.okta.com', match: 'host' },
];

describe('WebsitesView', () => {
  it('names the login and counts its websites', () => {
    renderWithIntl(<Harness initial={START} />);
    expect(screen.getByRole('heading', { name: 'Websites of Example Co SSO', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/Each website has its own rule/)).toBeInTheDocument();
    expect(screen.getByLabelText('Website 1')).toHaveValue('example.co');
    expect(screen.getByLabelText('Match for website 2')).toHaveValue('host');
  });

  it('explains each rule in words, and the preview follows an edit', async () => {
    renderWithIntl(<Harness initial={START} />);
    const user = userEvent.setup();
    expect(screen.getAllByText('Fills on example.co and every site under it').length).toBeGreaterThan(0);
    await user.selectOptions(screen.getByLabelText('Match for website 1'), 'exact');
    expect(screen.getAllByText(/Browser: this address only\. Phones: example\.co only/).length).toBeGreaterThan(0);
  });

  it('warns about the rules Bitwarden calls dangerous', async () => {
    renderWithIntl(<Harness initial={START} />);
    const user = userEvent.setup();
    expect(screen.queryByText(/dangerous if used carelessly/)).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Match for website 2'), 'regex');
    expect(screen.getByText(/dangerous if used carelessly/)).toBeInTheDocument();
  });

  it('adds and removes a website', async () => {
    renderWithIntl(<Harness initial={START} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a website' }));
    const added = screen.getByLabelText('Website 3');
    expect(added).toHaveValue('');
    expect(screen.getByLabelText('Match for website 3')).toHaveValue('default');
    await user.type(added, 'wiki.example.co');
    await user.click(screen.getByRole('button', { name: 'Remove example.co' }));
    expect(screen.queryByLabelText('Website 3')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Website 1')).toHaveValue('example-co.okta.com');
  });

  it('shows where phones fill', () => {
    renderWithIntl(<Harness initial={START} />);
    expect(screen.getByText('example.co, example-co.okta.com')).toBeInTheDocument();
  });

  it('hands the edited rows to save', async () => {
    const onSave = vi.fn();
    renderWithIntl(<Harness initial={START} onSave={onSave} />);
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText('Match for website 1'), 'never');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith([
      { key: 1, uri: 'example.co', match: 'never' },
      { key: 2, uri: 'example-co.okta.com', match: 'host' },
    ]);
  });
});
