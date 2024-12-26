now := $(shell date +%Y%m%d%H%M%S)

apply:
	gcloud deploy apply --file=clouddeploy.yaml --region=us-central1 --project=${GOOGLE_CLOUD_PROJECT}

release:
	gcloud deploy releases create test-release-${now} \
		--project=${GOOGLE_CLOUD_PROJECT} --region=us-central1 \
		--delivery-pipeline=my-run-demo-app-1 \
		--images=my-app-image=gcr.io/cloudrun/hello
