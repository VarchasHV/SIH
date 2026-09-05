# Database migrations

Schema for auth/billing/entitlements/usage is managed with Alembic. The
app itself only ever *reads* `DATABASE_URL` (see `config.py`) — Alembic reads
the same value (`migrations/env.py` imports `config.DATABASE_URL` directly),
so there is one source of truth for which database you're pointed at.

## Local dev

`npm run server` (or `AUTO_CREATE_DB=true`, the default) creates any missing
tables automatically on boot via `Base.metadata.create_all()` — convenient,
but it only ever *adds* tables/columns that don't exist yet; it never alters
or drops anything. That's fine for a fresh SQLite file, not a substitute for
migrations once the schema needs to change.

## Everywhere else (staging/production)

```bash
cd server
../.venv/bin/alembic upgrade head        # apply all pending migrations
```

Set `AUTO_CREATE_DB=false` in production so a schema drift can never be
silently papered over by the dev convenience path.

## Making a schema change

1. Edit `models.py`.
2. `../.venv/bin/alembic revision --autogenerate -m "describe the change"`
3. Read the generated file in `migrations/versions/` — autogenerate is a
   first draft, not ground truth (it won't detect every kind of change, e.g.
   column renames look like drop+add).
4. `../.venv/bin/alembic upgrade head` to apply it locally; verify
   `../.venv/bin/alembic downgrade -1` cleanly reverses it before committing.
