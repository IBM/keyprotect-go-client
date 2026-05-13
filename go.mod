module github.com/IBM/keyprotect-go-client

go 1.25.0

require (
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-retryablehttp v0.7.8
	github.com/stretchr/testify v1.11.0
	gopkg.in/h2non/gock.v1 v1.1.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/h2non/parth v0.0.0-20190131123155-b4df798d6542 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract (
	v0.12.3 // Contains only retractions
	v0.12.1 // Contains bugs that break create key
	v0.12.0 // Contains bugs that break create key
	v0.11.0 // Contains bugs that break create key
)
