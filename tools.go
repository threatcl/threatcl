//go:build tools
// +build tools

package tools

// This file ensures that go mod tidy doesn't remove tool dependencies
// from go.mod. These dependencies are required for code generation and
// development but aren't directly imported by the application code yet.

import (
	_ "github.com/99designs/gqlgen"
	_ "github.com/99designs/gqlgen/graphql/introspection"
	_ "github.com/go-chi/chi/v5"
	_ "github.com/rs/cors"
)
