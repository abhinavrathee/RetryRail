import { BladeProvider } from '@razorpay/blade/components';
import { bladeTheme } from '@razorpay/blade/tokens';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { App } from './App';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000,
    },
  },
});

export default function AppRoot(): React.JSX.Element {
  return (
    <BladeProvider colorScheme="light" themeTokens={bladeTheme}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </BladeProvider>
  );
}
