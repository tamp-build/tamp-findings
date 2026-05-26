# deploy/k8s — tamp.findings cluster manifests

Manifests for deploying `tamp.findings` to the lab MicroK8s cluster.

## What's here

| File | Owns |
|---|---|
| `api.yaml` | Deployment + Service for the API pod (which also serves the SPA static files) |

## What's NOT here (owned by the microk8s repo / agent)

- Namespace `tamp-findings`
- Postgres StatefulSet + Service + PVC
- Secrets `tamp-findings-db` (Postgres password) and `tamp-findings-oauth` (GitHub OAuth client id / secret / bootstrap admin login)
- Cloudflare tunnel ingress rule routing `tamp-findings.brewingcoder.com` → `tamp-findings-api.tamp-findings.svc.cluster.local:80`
- DNS CNAME `tamp-findings.brewingcoder.com → <tunnel-id>.cfargotunnel.com`

This split keeps cluster infra (long-lived, shared) under `microk8s` and app workload (per-deploy) under the app repo.

## Image registry

Always reference images as `registry.home.local/tamp-findings:<tag>`. Node-IP forms (`192.168.x.x:32000/...`) fail `ImagePullBackOff` because containerd's mirror is keyed on `localhost:32000`.

## Apply

Direct kubectl, on a workstation with the cluster's kubeconfig:

```bash
kubectl apply -f deploy/k8s/api.yaml
kubectl rollout status deploy/tamp-findings-api -n tamp-findings
```

Through the Nuke build (uses `Tamp.Kubectl` — KUBECONFIG flows as an env var, not a flag, per the wrapper's secret-handling posture):

```powershell
dotnet run --project build -- Deploy
```

## OAuth callback URL

The prod GitHub OAuth app's callback URL **must** be `https://tamp-findings.brewingcoder.com/auth/github/callback`. Dev (`http://localhost:5173/auth/github/callback`) is a separate app.
