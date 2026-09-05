# SnapWorth v1.0 Deployment Checklist

## Required before public launch
- Set NODE_ENV=production
- Use a strong SESSION_SECRET
- Add OPENAI_API_KEY
- Add EBAY_CLIENT_ID and EBAY_CLIENT_SECRET
- Deploy behind HTTPS
- Use persistent disk/database storage
- Configure backups
- Add a privacy policy and terms
- Add email verification + password reset before broad public signup
- Move item photos from SQLite data URLs to object storage before scale
- Add monitoring/logging and error reporting
- Review rate limits based on real traffic

## Render
A `render.yaml` is included. It provisions:
- Docker web service
- persistent 1 GB disk
- health check at `/health`
- production environment
- persistent SQLite + session files

## Docker
Build:
docker build -t snapworth .

Run:
docker run --env-file .env -p 3000:3000 snapworth
