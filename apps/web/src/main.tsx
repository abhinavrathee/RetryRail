import React, { Suspense, lazy } from 'react';
import ReactDOM from 'react-dom/client';

import './styles.css';

const AppRoot = lazy(() => import('./AppRoot'));

const rootElement = document.querySelector<HTMLDivElement>('#root');
if (rootElement === null) {
  throw new Error('RetryRail root element was not found');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <Suspense fallback={<div className="boot-state" role="status">Starting RetryRail…</div>}>
      <AppRoot />
    </Suspense>
  </React.StrictMode>,
);
