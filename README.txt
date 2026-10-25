TUITIONDESK CONTROL API — DEPLOYMENT STARTER

Files:
- main.py: account API for login, periodic status check, create/list clients, reset password, pause/activate, and delete.
- requirements.txt: Python dependencies.
- render.yaml: Render free web service settings and secret placeholders.

Supabase:
1. Run schema.sql in Supabase SQL Editor (the user already created this table manually; schema.sql documents it).
2. Keep Row Level Security enabled with no anon/authenticated policies.
3. Use only the service_role/secret key as a Render secret. Never put it in a desktop EXE or publish it in a Git repository.

Render environment variables:
SUPABASE_URL = Project URL from Supabase project settings.
SUPABASE_SERVICE_ROLE_KEY = service_role/secret API key from Supabase project settings.
ADMIN_API_KEY = long random secret used only by the Developer Console to call admin endpoints.

Endpoints:
GET    /health
POST   /v1/client/login              {"username":"...","password":"..."}
POST   /v1/client/check              {"username":"...","password":"..."}
GET    /v1/admin/clients             header X-Admin-Key
POST   /v1/admin/clients             header X-Admin-Key; {"org":"...","username":"...","phone":"","password":""}
PATCH  /v1/admin/clients/{id}        header X-Admin-Key; {"active":false}
POST   /v1/admin/clients/{id}/reset-password  header X-Admin-Key
DELETE /v1/admin/clients/{id}        header X-Admin-Key

Important:
This API is only the server starter. Existing V5 desktop apps are not connected to it yet. The next development step is updating the Developer Console and Client app so they use the deployed HTTPS address; do not issue API keys to clients. Free Render services sleep while idle, so first connection can be delayed.
