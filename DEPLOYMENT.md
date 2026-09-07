# SnapWorth deployment

This release is ready for staging validation, not an assertion that live hosting or policies are verified.

## Install and run
Use Node 24 LTS and `npm ci`; commit package-lock.json. Run `npm test` and `npm run check`. Production uses `npm ci --omit=dev` and `npm start`. Do not omit optional packages: Sharp requires its platform-specific binaries. `/health` checks database readiness.

## Environment
Copy `.env.example` for local development. Store real secrets in hosting configuration, never in Git.

- DATABASE_URL: PostgreSQL URL for accounts, items, sessions and usage counters. SQLite and local database files are not used.
- SESSION_SECRET: random, at least 32 characters. Production refuses missing/placeholder secrets. Rotation signs users out.
- DATABASE_CA_CERT: optional provider CA PEM (newlines or escaped \n). Production verifies certificates. URL SSL flags are stripped so they cannot override this policy. Confirm the database provider's CA configuration in staging; do not disable verification.
- OPENAI_API_KEY and optional OPENAI_MODEL: preserve the existing provider setup. Missing credentials return unavailable, not a fabricated demo result.
- EBAY_CLIENT_ID and EBAY_CLIENT_SECRET: tokens are cached and refreshed once after a 401.
- PUBLIC_ORIGIN: exact HTTPS origin, without trailing slash. Production trusts one reverse proxy; validate that topology before deployment.
- SITE_OPERATOR=Zycon Studios; SUPPORT_EMAIL=zyconstudios@protonmail.com.
- PUBLIC_SIGNUP_ENABLED=false in production by default. Existing users can log in. Public signup requires true, valid operator/contact settings and POLICIES_REVIEWED=true, after the operator reviews the actual deployment and policies.

Render supplies non-secret settings and a health check. Add DATABASE_URL, SESSION_SECRET and provider credentials in the dashboard. The blueprint does not create a database or backups. Docker uses Node 24 and the lockfile.

## Migration and rollback
Startup creates missing tables, makes item value nullable, adds users.auth_version (default zero), adds an owner/sort index and creates api_usage counters. Existing records/images are not rewritten or deleted. Legacy zero prices display as unknown; new unknown prices are NULL. Existing sessions default to auth version zero; changing a password revokes older sessions.

Back up first. Test startup/ALTER/INDEX permissions on a staging copy and schedule downtime where necessary for large tables. A code rollback must preserve NULL-aware price display: the old UI displays NULL as zero. Do not restore NOT NULL while unknown values exist.

## Limits
AI/pricing require login. Per UTC day: 20 identification attempts and 100 price searches per user; shared caps 500/2000 respectively. Failed/rejected attempts may count. Atomic PostgreSQL counters survive restarts and multiple instances; old counters are pruned on startup. IP limits and four concurrent expensive operations per process provide additional protection. Configure provider-side spending limits separately.

One JPEG/PNG/WebP upload is allowed: 8 MiB and 20 million pixels maximum. Stored data URLs have a smaller limit. Decoding, metadata stripping and resizing precede API use/storage. Inventory metadata is paginated (100/page), with owner-protected image requests. PostgreSQL image storage remains for compatibility; object storage is a later scaling option.

## Before public launch
1. Verify HTTPS cookies, proxy, verified database TLS and environment variables on staging.
2. Test two real accounts for cross-user item/image access, saving known/unknown prices, login, password changes, logout and deletion.
3. Run an authorized live identification/eBay check with test photos. Development used mocks only. Norwegian automatic pricing remains unavailable.
4. Restore a backup and document backup/log retention. Review the privacy notice against actual provider settings. Its retention section still requires operational details.
5. Confirm the support mailbox receives mail. Review terms, including the qualified liability clause. It is not a guarantee of legal enforceability.
6. Email verification and forgotten-password recovery remain to be implemented before broad signup. Do not bypass identity checks for manual recovery. Start with a limited beta and monitor errors and spend.

## Test scope
Tests use real Express/Multer/session middleware and Sharp, pg-mem SQL, and mocked external HTTP; frontend tests use JSDOM. This does not replace real PostgreSQL/TLS/session-store and backup tests. Full Smart Match v3 is not included: filtering is conservative and returns no estimate when product type/evidence is insufficient.
