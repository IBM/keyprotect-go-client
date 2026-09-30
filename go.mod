module github.com/IBM/keyprotect-go-client

go 1.26.4

require (
	github.com/IBM/go-sdk-core/v5 v5.23.5
	github.com/ebitengine/purego v0.10.1
	github.com/go-openapi/strfmt v0.27.2
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-retryablehttp v0.7.8
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.43.0
	github.com/stretchr/testify v1.12.1
	gopkg.in/h2non/gock.v1 v1.1.2
)

require (
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.15 // indirect
	github.com/go-openapi/errors v0.22.8 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/h2non/parth v0.0.0-20190131123155-b4df798d6542 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/leodido/go-urn v1.5.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

retract (
	v0.17.4 // Contains major version breaking changes
	v0.12.3 // Contains only retractions
	v0.12.1 // Contains bugs that break create key
	v0.12.0 // Contains bugs that break create key
	v0.11.0 // Contains bugs that break create key
)
