# ThreatSentry — Deployment

Frontend on Vercel, API on Render (`render.yaml`), database and auth on Supabase. The original plan named Railway; the repository is configured for Render.

## Supabase

1. Apply `supabase/migrations/0001_initial_schema.sql` and `0002_idempotent_profile_trigger.sql`.
2. Authentication → URL Configuration: set **Site URL** to the dashboard domain and add `https://<domain>/reset-password` (and `http://localhost:3000/reset-password` for local work) to **Redirect URLs**.
3. Keep the service-role key out of the frontend.

## API (Render)

`render.yaml` builds with `pip install -r requirements.txt` and starts `uvicorn backend.main:app`. Set the secrets marked `sync: false`: `ALLOWED_ORIGINS`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`.

- `APP_ENV=production` forbids wildcard/localhost origins and `SCAN_ALLOW_LOCAL`.
- `render.yaml` starts uvicorn with `--proxy-headers --forwarded-allow-ips='*'` so rate limiting sees real client IPs. This trusts `X-Forwarded-For` from any peer, which is only safe because Render's load balancer is the sole way to reach the service; do not copy it to a setup where the API is directly exposed.
- The model `ml/models/web_ids_model_v1.0.0.joblib` is committed and loaded from `MODEL_PATH`.
- Check `GET /health` after deploy; it reports model readiness.

## Dashboard (Vercel)

Root directory `apps/dashboard`. `vercel.json` provides SPA routing. Set `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` and `VITE_API_URL` (the deployed API URL).

## Verification checklist

- [ ] `/health` returns `status: ok`.
- [ ] Register, login, logout and password reset work on the production domain.
- [ ] CORS accepts only the production dashboard origin.
- [ ] A scan of a controlled, verified target completes.
- [ ] A scan of an unverified target is rejected.

None of these production checks have been run by this repository's authors yet.

## Rollback

Vercel: promote the previous deployment. Render: redeploy the previous commit. Database migrations are forward-only; write a compensating migration rather than editing applied ones.

## Monitoring

Not yet prepared beyond Render/Vercel built-in logs and the `/health` endpoint.
