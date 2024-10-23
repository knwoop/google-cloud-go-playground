# Google Workload Identity Federation

## set up

0. Set Env and ngrok

``` shell
$ cp .envrc.example .envrc
$ direnv allow
$ vi .envrc
```

Install ngrok and set up the authentication token

``` shell
$ ngrok config add-authtoken (token)
```

1. create a Service Account

``` shell
$ gcloud iam service-accounts create example-sa \
  --project="${GOOGLE_CLOUD_PROJECT}"
```

2. attach a role to the service account
``` shell
$ gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
  --member="serviceAccount:example-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
  --role="roles/owner"

$ gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
  --role="roles/storage.objectViewer" \
 --member="principal://iam.googleapis.com/${WORKLOAD_IDENTITY_FEDERATION_POOL_ID}/subject/example-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
```

3. create a workload identity pool and provider

``` shell
$ gcloud iam workload-identity-pools create "example-pool" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --location="global" \
  --display-name="example-service-pool" \
  --description="example service pool"

$ gcloud iam workload-identity-pools providers create-oidc "example-app-provider" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --location="global" \
  --workload-identity-pool="example-pool" \
  --display-name="example app provider" \
  --attribute-mapping="google.subject=assertion.sub" \
  --issuer-uri="${WORKLOAD_IDENTITY_FEDERATION_ISSUER_URL}"
```

4. store pool id

``` shell
$ gcloud iam workload-identity-pools describe "example-pool" \
  --project="${GOOGLE_CLOUD_PROJECT}" --location="global" \
  --format="value(name)"
```

set the pool id to WORKLOAD_IDENTITY_POOL_ID in [.envrc](.envrc)

5. set sa as impersonated user

``` shell
$ gcloud iam service-accounts add-iam-policy-binding "example-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/${WORKLOAD_IDENTITY_FEDERATION_POOL_ID}/subject/example-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
```

### Note
delete jwks

``` shell
gcloud iam workload-identity-pools providers update-oidc "example-app-provider"
 gcloud iam workload-identity-pools providers update-oidc \
    --project=PROJECT_ID \
    --location=LOCATION \
    --workload-identity-pool=POOL_ID \
    --jwk-json-path="empty/file/path"
```
