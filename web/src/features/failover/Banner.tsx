// The "home server offline" banner: shown above every vault screen while a vault's home server is
// down and a replica is serving it. Nothing at all when the server has no placement or all is well.
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useRich, useT } from '@/i18n';
import { type Placement, offlineHomes } from '@/api/placement';
import { buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import '@/styles/tools.css';
import { placementQuery } from './queries';

export function FailoverBannerView({ placement }: { placement: Placement | null | undefined }) {
  const t = useT();
  const rich = useRich();
  const down = offlineHomes(placement);
  const first = down[0];
  if (!first) return null;
  const replica = first.replica?.name ?? t('failover.aReplica');
  return (
    <div className="failover-banner" role="status">
      <Icon name="cloudOff" />
      <p>{rich('failover.banner', { home: first.home.name, replica })}</p>
      <Link to="/storage" className={buttonClass({ size: 'small' })}>
        {t('failover.where')}
      </Link>
    </div>
  );
}

export function FailoverBanner() {
  const { data } = useQuery(placementQuery);
  return <FailoverBannerView placement={data} />;
}
