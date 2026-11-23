// The one admin client the screens' default exports use. Views never import this, so tests give
// them fakes instead.
import { createAdminApi } from '@/api/admin';
import { api } from '@/app/services';

export const admin = createAdminApi(api);
