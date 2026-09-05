# Contributing to SnapWorth

## Local development

1. Copy `.env.example` to `.env`.
2. Set a development `SESSION_SECRET`.
3. Run `npm install`.
4. Run `npm run dev`.
5. Open `http://localhost:3000`.

The app can run without OpenAI/eBay credentials using its demo fallbacks.

## Before committing

Run:

```bash
node --check server.js
```

Do not commit `.env`, SQLite databases, session databases, API keys, or user data.
