import { useContext } from 'react';

import { MerchantSessionContext, type MerchantSession } from './merchant-session-context';

export function useMerchantSession(): MerchantSession {
  const value = useContext(MerchantSessionContext);
  if (value === null) throw new Error('MerchantSessionProvider is required');
  return value;
}
