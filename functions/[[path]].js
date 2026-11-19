// Cloudflare Pages catch-all: every dynamic route is handled by the panel app in src/index.js.
// Static files are served directly by Pages from public/ (public/static/* is the UI).
import app from '../src/index.js';

export async function onRequest(context) {
  return app.fetch(context.request, context.env, context);
}
