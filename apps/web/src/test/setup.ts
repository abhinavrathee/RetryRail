import '@testing-library/jest-dom/vitest';

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});

class ResizeObserverStub implements ResizeObserver {
  disconnect(): void {
    // jsdom has no layout engine; this intentional stub has nothing to disconnect.
  }
  observe(): void {
    // Component tests do not exercise resize-driven layout.
  }
  unobserve(): void {
    // Component tests do not retain observed elements.
  }
}

globalThis.ResizeObserver = ResizeObserverStub;
