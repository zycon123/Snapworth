# Contributing

Use Node 24 and `npm ci`. Copy `.env.example` to `.env` and supply development PostgreSQL and a session secret for manual use. Tests use pg-mem and mocked providers; no API key is needed.

Run `npm test` and `npm run check`. Preserve owner-scoped SQL, verified TLS, safe errors, upload limits and distinct currencies. Commit package-lock.json for dependency changes. Never commit secrets, user photos or database dumps.
