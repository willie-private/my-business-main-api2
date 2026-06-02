import { renderPage } from 'vite-plugin-ssr/server';

export function render(url, context) {
  const html = renderPage(url, context);  // Pre-render HTML
  return html;  // Returning the static HTML
}