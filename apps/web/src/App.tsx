import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { lazy, Suspense } from 'react';

import { AppShell } from './components/Shell';
import { MerchantSessionProvider } from './session/MerchantSession';

const OverviewPage = lazy(async () => {
  const module = await import('./pages/OverviewPage');
  return { default: module.OverviewPage };
});
const IncidentPage = lazy(async () => {
  const module = await import('./pages/IncidentPage');
  return { default: module.IncidentPage };
});
const RecoveryPage = lazy(async () => {
  const module = await import('./pages/RecoveryPage');
  return { default: module.RecoveryPage };
});
const ImpactPage = lazy(async () => {
  const module = await import('./pages/ImpactPage');
  return { default: module.ImpactPage };
});
const DemoPage = lazy(async () => {
  const module = await import('./pages/DemoPage');
  return { default: module.DemoPage };
});
const NotFoundPage = lazy(async () => {
  const module = await import('./pages/DemoPage');
  return { default: module.NotFoundPage };
});

export function App(): React.JSX.Element {
  return (
    <BrowserRouter>
      <MerchantSessionProvider>
        <AppShell>
          <Suspense fallback={<div className="state-card" role="status">Loading control-room view…</div>}>
            <Routes>
              <Route element={<OverviewPage />} path="/" />
              <Route element={<IncidentPage />} path="/incidents/:incidentId" />
              <Route element={<RecoveryPage />} path="/incidents/:incidentId/recover" />
              <Route element={<ImpactPage />} path="/impact" />
              <Route element={<DemoPage />} path="/demo" />
              <Route element={<NotFoundPage />} path="*" />
            </Routes>
          </Suspense>
        </AppShell>
      </MerchantSessionProvider>
    </BrowserRouter>
  );
}
