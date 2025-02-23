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
$ gcloud iam service-accounts create "${SERVICE_ACCOUNT_FOR_WORKLOAD_IDENTITY}" \
  --project="${GOOGLE_CLOUD_PROJECT}"
```

2. attach a role to the service account
``` shell
$ gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
  --member="serviceAccount:${SERVICE_ACCOUNT_FOR_WORKLOAD_IDENTITY}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
  --role="roles/owner"

$ gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
  --role="roles/storage.objectViewer" \
  --member="principal://iam.googleapis.com/${WORKLOAD_IDENTITY_FEDERATION_POOL_ID}/subject/${SERVICE_ACCOUNT_FOR_WORKLOAD_IDENTITY}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
```

3. create a workload identity pool and provider

``` shell
$ gcloud iam workload-identity-pools create "my-fed-pool" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --location="global" \
  --display-name="example-service-pool" \
  --description="example service pool"

$ gcloud iam workload-identity-pools providers create-oidc "my-fed-provider" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --location="global" \
  --workload-identity-pool="my-fed-pool" \
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
$ gcloud iam service-accounts add-iam-policy-binding "${SERVICE_ACCOUNT_FOR_WORKLOAD_IDENTITY}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/${WORKLOAD_IDENTITY_FEDERATION_POOL_ID}/subject/${SERVICE_ACCOUNT_FOR_WORKLOAD_IDENTITY}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
```

if you want to use Direct Workload Identity Federation, you can skip set sa as impersonated user
    run the below command instead
``` shell
$ gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
    --member="principal://iam.googleapis.com/${WORKLOAD_IDENTITY_FEDERATION_POOL_ID}/subject/${SERVICE_ACCOUNT_FOR_WORKLOAD_IDENTITY}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
    --role="roles/storage.objectViewer"
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
