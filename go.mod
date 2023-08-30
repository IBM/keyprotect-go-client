module github.com/IBM/keyprotect-go-client

go 1.15

require (
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/stretchr/testify v1.7.0
	gopkg.in/h2non/gock.v1 v1.1.2
)

retract (
	v0.11.0 // Contains bugs that break create key
	v0.12.0 // Contains bugs that break create key
	v0.12.1 // Contains bugs that break create key
	v0.12.3 // Contains only retractions
)
