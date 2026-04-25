package authoritah

import "net/http"

// Type aliases so plugins import only authoritah, not net/http directly.
// This lets us swap the underlying types later without breaking plugin authors.
type (
	ResponseWriter = http.ResponseWriter
	Request        = http.Request
)
