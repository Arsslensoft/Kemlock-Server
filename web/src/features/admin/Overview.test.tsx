import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { AdminOverview } from '@/api/admin';
import { renderWithIntl } from '@/test/render';
import { OverviewStats } from './Overview';

const OVERVIEW: AdminOverview = {
  users: 42,
  admins: 2,
  disabledUsers: 1,
  devices: 97,
  spaces: 3,
  liveItems: 6118,
  events24h: 1204,
  pendingInvites: 3,
  openRequests: 1,
  overdueRequests: 0,
  mailConfigured: false,
};

const CONFIG = { features: ['sso', 'federation', 'push', 'sends', 'webauthn', 'opaque', 'pq'] };

/** The stat cards, each as its label and what is in it. */
function cards(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>('.stat'));
}

describe('the Overview numbers', () => {
  it('are one row of five: users, devices, spaces, events and features', () => {
    renderWithIntl(<OverviewStats config={CONFIG} overview={OVERVIEW} />);
    const labels = cards().map((card) => card.querySelector('span:not(.si):not(.hint)')?.textContent);
    expect(labels).toEqual(['Users', 'Devices', 'Spaces', 'Events in the last 24 hours', 'Features']);
    expect(document.querySelectorAll('.stats')).toHaveLength(1);
  });

  it('have no Version and no Setup card', () => {
    renderWithIntl(<OverviewStats config={CONFIG} overview={OVERVIEW} />);
    expect(screen.queryByText('Version')).toBeNull();
    expect(screen.queryByText('Setup')).toBeNull();
    expect(screen.queryByText('Anyone can sign up')).toBeNull();
  });

  it('give every card an icon', () => {
    renderWithIntl(<OverviewStats config={CONFIG} overview={OVERVIEW} />);
    for (const card of cards()) {
      const icon = card.querySelector('.si');
      expect(icon, card.textContent ?? '').not.toBeNull();
      expect(icon?.querySelector('svg')).not.toBeNull();
      // Decoration: the label names the card.
      expect(icon).toHaveAttribute('aria-hidden', 'true');
    }
  });

  it('draw Features with the sliders, as the mockup does, and not the gear', () => {
    renderWithIntl(<OverviewStats config={CONFIG} overview={OVERVIEW} />);
    const features = cards()[4] as HTMLElement;
    const icon = features.querySelector('.si svg') as SVGElement;
    // Three sliders: a line each, with a knob each.
    expect(icon.querySelectorAll('circle')).toHaveLength(3);
    expect(icon.querySelector('path')?.getAttribute('d')).toBe('M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12');
    // The Settings page's gear has a single circle and rays.
    const users = cards()[0] as HTMLElement;
    expect(users.querySelectorAll('.si circle').length).not.toBe(3);
  });

  it('show the real counts, with the admins, the live items and the feature names beneath', () => {
    renderWithIntl(<OverviewStats config={CONFIG} overview={OVERVIEW} />);
    const [users, devices, spaces, events, features] = cards() as [
      HTMLElement,
      HTMLElement,
      HTMLElement,
      HTMLElement,
      HTMLElement,
    ];
    expect(within(users).getByText('42')).toBeInTheDocument();
    expect(within(users).getByText('2 admins')).toBeInTheDocument();
    expect(within(devices).getByText('97')).toBeInTheDocument();
    expect(within(spaces).getByText('3')).toBeInTheDocument();
    expect(within(spaces).getByText('6,118 live items')).toBeInTheDocument();
    expect(within(events).getByText('1,204')).toBeInTheDocument();
    expect(within(features).getByText('7')).toBeInTheDocument();
    expect(within(features).getByText('sso, federation, push, sends, webauthn, opaque, pq')).toBeInTheDocument();
  });

  it('show the features alone while the counts are not there, and nothing before either', () => {
    const { unmount } = renderWithIntl(<OverviewStats config={CONFIG} overview={undefined} />);
    expect(cards()).toHaveLength(1);
    expect(screen.getByText('Features')).toBeInTheDocument();
    unmount();
    renderWithIntl(<OverviewStats config={undefined} overview={undefined} />);
    expect(cards()).toHaveLength(0);
  });
});
