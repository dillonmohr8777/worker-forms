# worker-forms

Netlify Forms, rebuilt on Cloudflare Workers + D1. Keep your plain HTML forms, host your pages anywhere, and store every
submission in your own Cloudflare account on the free plan. MIT licensed.

One small Worker takes form posts from your pages, stores each one in a D1 database, and sends the visitor to your thank-you
page (or answers JSON). Optional: file uploads in Workers KV and spam checks with Turnstile. No server, no paid plan.

## What it does

- `POST /f/<site-key>` stores the fields in D1. Accepts urlencoded, multipart and JSON bodies. Only pages on
  `ALLOWED_HOSTS` may post. 64 KB for ordinary bodies, 8 posts per visitor per form per 10 minutes (`RATE_MAX`).
- Honeypot: a filled `bot-field` (or the field named by the hidden `_hp` input) is stored flagged `spam = 1` and the
  visitor still sees success.
- `GET /forms.js` is a drop-in for pages whose forms submit by script (`fetch("/", {method: "POST", body})`, the Netlify
  AJAX pattern). It sends those requests to the Worker and leaves every other request alone.
- File uploads (with the `UPLOADS` KV binding): pdf, images, office documents, txt, csv; 10 MB per submission, 10 files.
  Files stay in KV for 14 days and the row lists them under `_files`. Without the binding, files are noted, not stored.
- Turnstile (with the `TURNSTILE_SECRET` secret): a missing or failed token never drops a lead. The row is stored with
  `spam = 2` so your notifier can flag it "unverified".
- No raw IP is stored: the rate limit uses a salted hash.

Files: `src/worker.js` (the Worker), `src/forms.js` (the browser drop-in), `schema.sql` (the D1 table),
`wrangler.example.toml` (config template).

## Set up from zero

Needs Node and a free Cloudflare account.

1. `npm i -g wrangler && wrangler login`
2. Database: `wrangler d1 create forms`. Then `cp wrangler.example.toml wrangler.toml` and fill in `ALLOWED_HOSTS`,
   `HASH_SALT` and the printed `database_id`.
3. Table: `wrangler d1 execute forms --remote --file schema.sql`
4. Uploads (optional): `wrangler kv namespace create UPLOADS` and paste its id into `wrangler.toml`, or delete the
   `[[kv_namespaces]]` block to run without uploads.
5. Deploy: `wrangler deploy`. Note the `https://forms.<you>.workers.dev` address it prints.
6. Read leads: `wrangler d1 execute forms --remote --command "SELECT * FROM submissions ORDER BY id DESC LIMIT 20"`

Local test: `wrangler dev --local` (apply the schema with `--local` first). If your installed workerd supports an older
compatibility date than the file asks for, pass `--compatibility-date <supported date>`.

## Point a form at it

Plain form:

```html
<form method="POST" action="https://forms.<you>.workers.dev/f/contact">
  <input type="hidden" name="form-name" value="contact">
  <input type="hidden" name="_next" value="https://www.example.com/thanks/">
  <p hidden><input name="bot-field"></p>
  <input name="email" type="email" required>
  <button>Send</button>
</form>
```

`_next` must be an absolute URL on an allowed host; without it the Worker shows a plain thank-you page with a link back.

A form that already posts by script to `/`: add one tag and change nothing else.

```html
<script src="https://forms.<you>.workers.dev/forms.js" data-site="contact" defer></script>
```

## Coming from Netlify Forms

A Netlify form (`<form name="contact" data-netlify="true" netlify-honeypot="bot-field" action="/thanks/">`) needs three
changes: set `action` to `https://forms.<you>.workers.dev/f/<site-key>`, add the hidden `form-name` input (Netlify adds it
at build time, so exported pages often have it already), and turn a relative `action` into an absolute `_next`. If you
used `netlify-honeypot="x"`, add `<input type="hidden" name="_hp" value="x">`. The `data-netlify` attribute can stay or go.
If you publish with a script, those changes fit in a small HTML rewrite step at build time.

## Turnstile (optional, free)

1. Create a widget in the Cloudflare dashboard (Turnstile) listing your page hostnames. Copy the site key and secret.
2. `wrangler secret put TURNSTILE_SECRET` and paste the secret. Never put it in `wrangler.toml`.
3. Inside each form: `<div class="cf-turnstile" data-sitekey="YOUR-SITE-KEY" data-appearance="interaction-only"></div>`,
   and once per page: `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`.
4. To test without a real widget, use Cloudflare's published test secrets in a `.dev.vars` file with `wrangler dev`:
   `1x0000000000000000000000000000000AA` always passes, `2x0000000000000000000000000000000AA` always fails.

## Notifications

The Worker only stores. To get an email per lead, run a small poller on any machine or schedule:

1. Read new rows: `SELECT id, site, form, page, data, spam, created_at FROM submissions WHERE notified_at IS NULL AND spam IN (0, 2) ORDER BY id`
   (`wrangler d1 execute forms --remote --json --command "..."`, or the D1 HTTP API).
2. Send each one with whatever mailer you use; add "[unverified]" to the subject when `spam = 2`.
3. Mark it right after sending: `UPDATE submissions SET notified_at = datetime('now') WHERE id = <id>`.
4. For uploads, read each `_files[].key` from KV, store the file where you keep documents, then delete the KV key.

Columns: `submissions(id, site, form, page, data JSON, ip_hash, ua, spam, created_at, notified_at)`. `spam`: 0 ok,
1 honeypot, 2 Turnstile missing or failed.

## Limits

`forms.js` covers `fetch`, not XMLHttpRequest or `navigator.sendBeacon`. KV files expire after 14 days. Turnstile cannot be
solved by headless browsers, so automated tests only reach the unverified path.
