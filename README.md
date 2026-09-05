# SnapWorth v1.0 — Deployment Ready Prototype

This release turns the prototype into something that can be deployed safely for early testing.

Added:
- Dockerfile
- Render deployment blueprint
- `/health` endpoint
- Helmet security headers
- API rate limiting
- tighter login/register rate limits
- persistent SQLite-backed session store
- production proxy/cookie handling
- environment validation warning
- deployment checklist
- image-storage abstraction point for future S3/R2/Supabase migration

Still included:
- AI image identification
- searchable detected items
- marketplace comparable listings
- valuation ranges
- generated sales listings
- accounts
- My Stuff cloud inventory
- saved item photos
- scan history
- item details and notes
- installable PWA

Important:
v1.0 is suitable for private/early beta deployment, not large-scale public production yet. Before broad launch, add email verification, password reset, production object storage for images, stronger observability, and a more scalable database/session strategy.
