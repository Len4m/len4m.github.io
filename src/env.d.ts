/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

// Declaraciones para PrismJS
declare module 'prismjs' {
  export function highlight(text: string, grammar: any, language?: string): string;
  export const languages: {
    js: any;
    javascript: any;
    python: any;
    [key: string]: any;
  };
}

declare module 'prismjs/components/prism-clike';
declare module 'prismjs/components/prism-javascript';
declare module 'prismjs/components/prism-python';
