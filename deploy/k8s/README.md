# deploy/k8s — tamp.findings cluster manifests

Example manifests for deploying `tamp.findings` to a Kubernetes cluster. Treat
them as a starting point and adapt the namespace, registry, secrets and ingress
to your own environment.

## What's here

| File | Owns |
|---|---|
| `api.yaml` | Deployment + Service for the API pod (which also serves the UI static files) |

## What you provide (out of band, per your cluster)

The manifests here deliberately do **not** hard-code your infrastructure. Supply
the following through your own cluster tooling:

- Namespace (default `tamp-findings`)
- A Postgres instance (StatefulSet + Service + PVC, a managed database, etc.)
- Secrets `tamp-findings-db` (Postgres password) and `tamp-findings-oauth`
  (GitHub OAuth client id / secret / bootstrap admin login)
- An Ingress or reverse proxy routing your public host → the
  `tamp-findings-api` Service on port 80, and the matching DNS record

## Image registry

Reference the image by whatever registry your cluster pulls from. The registry
is configurable via the `TAMP_FINDINGS_REGISTRY` environment variable for the
build (see `build/Build.cs`); the manifest's default image reference is a
placeholder you should replace with your own.

## Apply

Direct kubectl, on a workstation with your cluster's kubeconfig:

```bash
kubectl apply -f deploy/k8s/api.yaml
kubectl rollout status deploy/tamp-findings-api -n tamp-findings
```

Through the Nuke build (`KUBECONFIG` flows as an env var, not a flag):

```powershell
dotnet run --project build -- Deploy
```

## OAuth callback URL

The production GitHub OAuth app's callback URL **must** be
`https://<your-host>/auth/github/callback`. A local dev app
(`http://localhost:5173/auth/github/callback`) is registered separately.
