# Derbent Auth Engine

Self-hosted authentication and SSO engine for Cloudflare Workers, powered by React, Hono, D1, KV, and Worker RPC.

- Cross-subdomain SSO and app-isolated accounts
- Email/password, Magic Link, GitHub OAuth, and Google OAuth login
- TOTP Two-Factor Authentication (2FA) with QR setup and replay protection
- Stateful opaque sessions in KV (no JWTs) with User-Agent hijack protection
- Pure Cloudflare Worker RPC for consuming Workers (`verifySession`, `logoutSession`)
- Audit logging with scheduled retention pruning and async email queue delivery
- React 19 + Base UI + Tailwind CSS v4 SPA backed by `/api/*` JSON endpoints

```text
Browser / SPA (React + Base UI)
  │
  ▼
Derbent Worker (/api/*, /auth/*) ──► D1 (users, apps, settings, audit_logs)
  ▲                               ├── KV (sessions, tokens, config cache, rate limits)
  │                               └── Queue (derbent-email-queue ──► Resend)
Worker RPC (WorkerEntrypoint)
  │
Consuming App Worker ──► Cloudflare Cache API
```

---

## Project Structure

- `shared/` — Valibot schemas and TypeScript contracts (`ApiResponse<T>`, auth & admin DTOs, SVG sanitizer)
- `worker/` — Cloudflare Worker (`DerbentWorker extends WorkerEntrypoint`), Hono API handlers, services, repositories, and middleware
- `src/` — React 19 SPA pages, History-API router, API client, QR generator, and theme state
- `ui/` — Base UI + Tailwind CSS v4 design system primitives
- `migrations/` — D1 SQL schema migrations (`0001_init.sql`)

---

## Getting Started

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Configure Cloudflare Resources

Update `cloudflare.config.ts` with your D1 database, KV namespace, Queue (`derbent-email-queue`), and custom domain settings, then generate Worker binding types:

```bash
pnpm run cf-typegen
```

Apply the initial D1 schema migration locally:

```bash
npx wrangler d1 migrations apply db-derbent --local
```

### 3. Environment Configuration

Create a `.dev.vars` file for local development (for production, configure secrets with `cf` / `wrangler secret`):

```env
APP_ENV=development
LOG_LEVEL=debug
APP_NAME=Derbent
COOKIE_DOMAIN=localhost
BASE_URL=http://localhost:7777
RESEND_API_KEY=re_your_api_key_here
RESEND_DOMAIN=your-verified-domain.com
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
DERBENT_API_KEY=your_generated_hex_string_here
```

Generate `DERBENT_API_KEY` (used for `/api/admin/*` Bearer authentication and, via domain-separated key derivation, AES-GCM encryption of secret settings in D1 and cached dynamic settings in KV):

```bash
openssl rand -hex 32
```

Notes:

- **OAuth Callback URLs:** Configure GitHub and Google OAuth apps with `/auth/github/callback` and `/auth/google/callback` (e.g., `http://localhost:7777/auth/github/callback` locally and `https://derbent.zerdalu.com/auth/github/callback` in production).
- **PBKDF2 Limit:** `PBKDF2_ITERATIONS` supports `10000` to `100000` (Cloudflare Workers Web Crypto cap).
- **Dynamic Apps & Settings:** Applications are stored in the D1 `apps` table (seeded with `sso` by `migrations/0001_init.sql`) and managed via `/api/admin/apps`. Dynamic settings updates require `USE_DYNAMIC_CONFIG=true`; `APP_ENV` is deploy-time only and cannot be changed at runtime.

### 4. Development & Verification

Run locally on port `7777` (configured in `vite.config.ts`):

```bash
pnpm run dev
```

Typecheck, build, lint, and format check:

```bash
pnpm run build
pnpm run lint
pnpm run fmt:check
```

Deploy:

```bash
pnpm run deploy
```

---

## Integration for Consuming Apps (Worker RPC)

Derbent exports `DerbentWorker` (extending `WorkerEntrypoint`) from `worker/index.ts`, exposing typed RPC methods that are unreachable from public HTTP traffic.

### 1. Service Binding Configuration

Bind to the `derbent` Worker in your consuming app's Cloudflare config (`wrangler.jsonc` or `cloudflare.config.ts`):

```jsonc
{
  "services": [
    {
      "binding": "DERBENT_SERVICE",
      "service": "derbent",
    },
  ],
}
```

### 2. Verification Helper

Pass the user's raw `Cookie` header, target `appId`, `cf-connecting-ip`, and `user-agent` to `DERBENT_SERVICE.verifySession(...)`. Consuming apps can optionally cache verified sessions in `caches.default` using a SHA-256 hash of the `Cookie` header (Cloudflare Cache API ignores `Vary: Cookie`):

```typescript
import type { Context } from "hono";
import type { RpcVerifyResult } from "@shared/schemas/auth";

export async function verifyWithDerbent(c: Context, appId: string) {
  const cookie = c.req.header("Cookie") || "";
  if (!cookie) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const clientIp = c.req.header("cf-connecting-ip") || "127.0.0.1";
  const clientUa = c.req.header("user-agent") || "";
  if (!clientUa) {
    return c.json({ error: "Missing User-Agent" }, 400);
  }

  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(cookie));
  const cookieHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const currentUrl = new URL(c.req.url);
  const cacheUrl = new URL(`${currentUrl.origin}/_internal_auth_cache`);
  cacheUrl.searchParams.set("app_id", appId);
  cacheUrl.searchParams.set("cookie_hash", cookieHash);
  const cacheKey = new Request(cacheUrl.toString());

  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) {
    return cached;
  }

  const result: RpcVerifyResult = await c.env.DERBENT_SERVICE.verifySession(cookie, appId, clientIp, clientUa);

  if (!result.ok) {
    return c.json({ error: result.message, code: result.code }, result.status);
  }

  const response = new Response(JSON.stringify(result.session), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "private, max-age=60",
    },
  });

  await cache.put(cacheKey, response.clone());
  return response;
}
```

### 3. RPC Reference

#### `verifySession(cookieHeader, appId, clientIp, clientUserAgent)`

Verifies the session cookie (`session_<appId>`, falling back to `session_sso` when `appId !== "sso"`).

Returns a discriminated union `RpcVerifyResult`:

- Success:

```json
{
  "ok": true,
  "session": {
    "userId": "018f3a5b-7b2a-7c81-9d4f-123456789abc",
    "email": "user@example.com",
    "appId": "sso",
    "createdAt": 1709654321000,
    "ip": "203.0.113.42",
    "userAgent": "Mozilla/5.0...",
    "tokenVersion": 1,
    "data": {}
  }
}
```

- Failure: `{ "ok": false, "status": 400 | 401 | 403 | 500, "code": "...", "message": "..." }`

#### `logoutSession(cookieHeader, appId)`

Destroys the active session in KV (verifying application ownership) and logs the logout event. Returns `{ "ok": true }` or `{ "ok": false, "status": 400 | 401 | 403 | 500, "code": "...", "message": "..." }`.

---

## Auth & Public API Reference

All JSON API endpoints return the `ApiResponse<T>` envelope:

- Success: `{ "success": true, "data": ... }`
- Error: `{ "success": false, "error": { "code": "...", "message": "..." } }`

State-changing `/api/auth/*` endpoints enforce `application/json`, `Origin` / `Sec-Fetch-Site` CSRF validation, and IP rate limiting (`AUTH_LIMITER`).

| Endpoint                                | Method | Description                                                                          |
| :-------------------------------------- | :----- | :----------------------------------------------------------------------------------- |
| `/api/health`                           | `GET`  | Service health status                                                                |
| `/api/auth/dashboard`                   | `GET`  | Active session statuses across registered apps                                       |
| `/api/auth/context`                     | `GET`  | Target app context and OAuth provider flags                                          |
| `/api/auth/login`                       | `POST` | Password login (returns `authenticated`, `requires_2fa`, or `verification_required`) |
| `/api/auth/register`                    | `POST` | Register account and enqueue verification email                                      |
| `/api/auth/verify-email`                | `POST` | Verify account using email token                                                     |
| `/api/auth/logout`                      | `POST` | Revoke current app/SSO session                                                       |
| `/api/auth/logout-all`                  | `POST` | Revoke all sessions for the current user ID                                          |
| `/api/auth/logout-all-email`            | `POST` | Revoke all sessions across all accounts matching the active email                    |
| `/api/auth/forgot-password`             | `POST` | Request password reset email                                                         |
| `/api/auth/reset-password`              | `POST` | Complete password reset using token                                                  |
| `/api/auth/change-password`             | `POST` | Change password for authenticated session                                            |
| `/api/auth/magic-link/request`          | `POST` | Send one-time magic link email                                                       |
| `/api/auth/magic-link/verify`           | `POST` | Sign in with one-time magic link token                                               |
| `/api/auth/2fa/setup`                   | `GET`  | Check 2FA status or generate setup secret & `otpauthUrl`                             |
| `/api/auth/2fa/enable`                  | `POST` | Confirm TOTP code and enable 2FA                                                     |
| `/api/auth/2fa/disable`                 | `POST` | Confirm TOTP code and disable 2FA                                                    |
| `/api/auth/2fa/verify`                  | `POST` | Complete 2FA challenge during sign-in                                                |
| `/auth/github`, `/auth/github/callback` | `GET`  | GitHub OAuth flow                                                                    |
| `/auth/google`, `/auth/google/callback` | `GET`  | Google OAuth flow                                                                    |

---

## Admin API Reference

All `/api/admin/*` endpoints require `Authorization: Bearer <DERBENT_API_KEY>` (with isolated IP rate limiting on failed authentication attempts) and return `ApiResponse<T>`.

| Endpoint                          | Method   | Description                                                                                                              |
| :-------------------------------- | :------- | :----------------------------------------------------------------------------------------------------------------------- |
| `/api/admin/stats`                | `GET`    | Dashboard metrics and 30-day signup/login trends                                                                         |
| `/api/admin/settings`             | `GET`    | Read effective runtime settings with secret masking                                                                      |
| `/api/admin/settings`             | `PATCH`  | Update or clear dynamic settings in D1 + encrypted KV cache (requires `USE_DYNAMIC_CONFIG=true`; `APP_ENV` is read-only) |
| `/api/admin/apps`                 | `GET`    | List registered apps                                                                                                     |
| `/api/admin/apps/:id`             | `GET`    | Get app configuration                                                                                                    |
| `/api/admin/apps`                 | `POST`   | Register a new app                                                                                                       |
| `/api/admin/apps/:id`             | `PATCH`  | Update app configuration                                                                                                 |
| `/api/admin/apps/:id`             | `DELETE` | Delete an app (excluding `sso` or apps with existing users)                                                              |
| `/api/admin/users`                | `GET`    | Paginated user list (`?page=1&limit=20&search=email`)                                                                    |
| `/api/admin/users/:id`            | `GET`    | Get user profile (`AdminUserView`, omitting password hashes and 2FA secrets)                                             |
| `/api/admin/users/:id`            | `PATCH`  | Update user metadata, app assignment, or email verification status                                                       |
| `/api/admin/users/:id/password`   | `POST`   | Force reset a password-based user's password                                                                             |
| `/api/admin/users/:id/2fa`        | `DELETE` | Disable 2FA for a user                                                                                                   |
| `/api/admin/users/:id/sessions`   | `DELETE` | Revoke all active sessions for a user                                                                                    |
| `/api/admin/users/:id/lock`       | `POST`   | Lock or unlock a user account                                                                                            |
| `/api/admin/users/:id`            | `DELETE` | Delete user and anonymize historical audit logs                                                                          |
| `/api/admin/audit-logs`           | `GET`    | Paginated audit logs (`?page=1&limit=50&action=...`)                                                                     |
| `/api/admin/users/:id/audit-logs` | `GET`    | Paginated audit logs for a specific user                                                                                 |

---

## Security & Architecture

- **No JWTs:** Opaque session tokens stored in Cloudflare KV.
- **Scoped Cookies:** Session cookies use `COOKIE_DOMAIN` for cross-subdomain SSO, while OAuth state cookies are restricted to the Derbent host only.
- **SSO Priority:** Once an `sso` account exists for an email, app-specific accounts for that email cannot be created, and OAuth auto-provisioning and password resets will not violate SSO/app account uniqueness.
- **Version-Bound Tokens:** Email verification, password reset, and magic-link tokens are bound to `token_version` and paired with per-user email cooldowns so password overwrites or session revocations immediately invalidate older links.
- **Hijack Protection:** Sessions verify `User-Agent` consistency, active application login availability, and `token_version` revocation state, with debounced IP-change audit logging.
- **Abuse Controls:** Scoped IP rate limiting (`AUTH_LIMITER`), isolated failed-auth rate limiting on `/api/admin/*`, enforced per-email+IP and global per-email login attempt lockouts, single-use TOTP replay guards with per-user attempt limits, strict redirect sanitization, and allowlist-based SVG XSS validation with size caps.
- **Scheduled Maintenance:** Daily cron (`0 0 * * *`) prunes `audit_logs` older than `AUDIT_LOG_RETENTION_DAYS`.

---

## Library Stack

- React - https://react.dev/
- Base UI - https://base-ui.com/
- Tailwind CSS - https://tailwindcss.com/
- cn - https://github.com/shadcn-ui/cn
- Phosphor Icons - https://phosphoricons.com/
- Zustand - https://zustand.docs.pmnd.rs/
- Valibot - https://valibot.dev/
- Hono - https://hono.dev/
- Cloudflare CLI (`cf`) - https://developers.cloudflare.com/cf/get-started/
- Vite - https://vite.dev/
- Oxlint - https://oxc.rs/docs/guide/usage/linter.html
- Oxfmt - https://oxc.rs/docs/guide/usage/formatter.html
- Vitest - https://vitest.dev/
- Babel + React Compiler - https://babel.dev/
- TypeScript - https://www.typescriptlang.org/
