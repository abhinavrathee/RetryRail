import {
  useCallback,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react';

import { MerchantSessionContext } from './merchant-session-context';

export function MerchantSessionProvider({ children }: PropsWithChildren): React.JSX.Element {
  const [authorization, setAuthorization] = useState('');
  const [replayToken, setReplayToken] = useState('');
  const [authorityEpoch, setAuthorityEpoch] = useState(0);
  const [isDialogOpen, setDialogOpen] = useState(false);
  const openDialog = useCallback(() => { setDialogOpen(true); }, []);
  const closeDialog = useCallback(() => { setDialogOpen(false); }, []);
  const lock = useCallback(() => {
    setAuthorization('');
    setReplayToken('');
    setAuthorityEpoch((current) => current + 1);
    setDialogOpen(false);
  }, []);
  const save = useCallback((nextAuthorization: string, nextReplayToken: string) => {
    setAuthorization(nextAuthorization);
    setReplayToken(nextReplayToken);
    setDialogOpen(false);
  }, []);
  const value = useMemo(
    () => ({
      authorization,
      replayToken,
      authorityEpoch,
      isUnlocked: authorization.length > 0,
      isDialogOpen,
      openDialog,
      closeDialog,
      lock,
      save,
    }),
    [
      authorization,
      replayToken,
      authorityEpoch,
      isDialogOpen,
      openDialog,
      closeDialog,
      lock,
      save,
    ],
  );
  return (
    <MerchantSessionContext.Provider value={value}>
      {children}
    </MerchantSessionContext.Provider>
  );
}
