package graphql

import (
	"github.com/threatcl/threatcl/internal/cache"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	Cache *cache.ThreatModelCache
}
