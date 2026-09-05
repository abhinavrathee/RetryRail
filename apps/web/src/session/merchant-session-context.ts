import { createContext } from 'react';

export interface MerchantSession {
  authorization: string;
  replayToken: string;
  authorityEpoch: number;
  isUnlocked: boolean;
  isDialogOpen: boolean;
  openDialog: () => void;
  closeDialog: () => void;
  lock: () => void;
  save: (authorization: string, replayToken: string) => void;
}

export const MerchantSessionContext = createContext<MerchantSession | null>(null);
