import type { PropsWithChildren } from 'react';

type ProviderProps = PropsWithChildren<{
  colorScheme: string;
  themeTokens: unknown;
}>;

type BoxProps = PropsWithChildren<{
  backgroundColor?: string;
  minHeight?: string;
}>;

type HeadingProps = PropsWithChildren<{
  as?: 'h1' | 'h2' | 'h3';
  size?: string;
}>;

type TextProps = PropsWithChildren<{
  color?: string;
  size?: string;
}>;

type BadgeProps = PropsWithChildren<{
  color?: string;
  size?: string;
}>;

export function BladeProvider({ children }: ProviderProps): React.JSX.Element {
  return <>{children}</>;
}

export function Box({ children }: BoxProps): React.JSX.Element {
  return <div data-blade-component="box">{children}</div>;
}

export function Heading({ as: Element = 'h2', children }: HeadingProps): React.JSX.Element {
  return <Element data-blade-component="heading">{children}</Element>;
}

export function Text({ children }: TextProps): React.JSX.Element {
  return <p data-blade-component="text">{children}</p>;
}

export function Badge({ children }: BadgeProps): React.JSX.Element {
  return <span data-blade-component="badge">{children}</span>;
}

