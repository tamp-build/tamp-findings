# Dev container compose

Run from the repo root:

```pwsh
docker compose -f docker/docker-compose.dev.yml up -d
```

Brings up Postgres 17 on `localhost:5432` with:

| Setting      | Value           |
|--------------|-----------------|
| Database     | `tamp_findings` |
| Username     | `tamp`          |
| Password     | `tamp`          |
| Volume path  | `docker/.data/postgres` (gitignored) |

The default API connection string in `appsettings.Development.json` points
here; nothing else to wire up.

To wipe state: `docker compose -f docker/docker-compose.dev.yml down -v`
and delete `docker/.data/`.
