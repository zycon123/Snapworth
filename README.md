# SnapWorth

SnapWorth by Zycon Studios identifies items, compares marketplace asking prices and stores a personal collection. It is a supporting tool, not a definitive answer; errors may occur and sale prices are not guaranteed.

Support: [zyconstudios@protonmail.com](mailto:zyconstudios@protonmail.com).

Use Node 24. Copy `.env.example` to `.env`, configure development PostgreSQL and a session secret, then run `npm ci` and `npm start`. Open http://localhost:3000. Identification and price searches require sign-in and provider credentials. Norwegian automatic pricing is unavailable; FINN/Facebook links remain available.

`npm test` uses mocked external APIs and needs no API key. `npm run check` checks server syntax. See [DEPLOYMENT.md](DEPLOYMENT.md) for environment, migration and launch requirements.
