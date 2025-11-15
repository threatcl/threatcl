Implementation Plan: GraphQL API Server for threatcl
Overview
Based on my review of the codebase, I'll create a detailed plan to add a new threatcl server command that serves a GraphQL API exposing all data from HCL threat model files in memory.

📋 Architecture Analysis
Current State:

CLI Framework: Uses mitchellh/cli with command pattern
Data Parsing: External package github.com/threatcl/spec@v0.1.15 handles all HCL parsing
Existing Server: MCP (Model Context Protocol) server at /cmd/threatcl/mcp.go:1 serves as reference
Data Models: Comprehensive threat modeling structures including:
Threatmodel (name, author, description, timestamps, attributes)
Threat (description, impacts, STRIDE, controls, asset references)
InformationAsset (name, classification, source)
UseCase, Exclusion, ThirdPartyDependency
DataFlowDiagram (processes, data stores, flows, trust zones)
ExpandedControl (name, description, implemented status, risk reduction)
File Discovery Pattern:

findAllFiles(args) → recursive walk → parse .hcl and .json files
🎯 Implementation Plan
Phase 1: GraphQL Schema Design
Create GraphQL schema matching the spec data models:

type Query {
  # List all threat models
  threatModels(filter: ThreatModelFilter): [ThreatModel!]!
  
  # Get single threat model by name
  threatModel(name: String!): ThreatModel
  
  # Search threats across all models
  threats(filter: ThreatFilter): [Threat!]!
  
  # Get all information assets
  informationAssets(classification: String): [InformationAsset!]!
  
  # Get statistics
  stats: Statistics!
}

type ThreatModel {
  name: String!
  author: String!
  description: String
  link: String
  diagramLink: String
  createdAt: Int
  updatedAt: Int
  attributes: Attributes
  additionalAttributes: [AdditionalAttribute!]
  informationAssets: [InformationAsset!]!
  threats: [Threat!]!
  useCases: [UseCase!]!
  exclusions: [Exclusion!]!
  thirdPartyDependencies: [ThirdPartyDependency!]!
  dataFlowDiagrams: [DataFlowDiagram!]!
  sourceFile: String!
}

type Attributes {
  newInitiative: Boolean
  internetFacing: Boolean
  initiativeSize: String
}

type AdditionalAttribute {
  key: String!
  value: String!
}

type Threat {
  description: String!
  impacts: [String!]
  stride: [String!]
  controls: [Control!]!
  informationAssetRefs: [String!]
  threatModel: ThreatModel!
}

type Control {
  name: String!
  description: String!
  implemented: Boolean!
  implementationNotes: String
  riskReduction: Int
  attributes: [ControlAttribute!]
}

type ControlAttribute {
  name: String!
  value: String!
}

type InformationAsset {
  name: String!
  description: String
  informationClassification: String!
  source: String
  threatModel: ThreatModel!
}

type UseCase {
  description: String!
}

type Exclusion {
  description: String!
}

type ThirdPartyDependency {
  name: String!
  description: String!
  saas: Boolean
  payingCustomer: Boolean
  openSource: Boolean
  infrastructure: Boolean
  uptimeDependency: String!
  uptimeNotes: String
}

type DataFlowDiagram {
  name: String!
  processes: [Process!]!
  dataStores: [DataStore!]!
  externalElements: [ExternalElement!]!
  flows: [Flow!]!
  trustZones: [TrustZone!]!
}

type Process {
  name: String!
  trustZone: String
}

type DataStore {
  name: String!
  trustZone: String
  informationAsset: String
}

type ExternalElement {
  name: String!
  trustZone: String
}

type Flow {
  name: String!
  from: String!
  to: String!
}

type TrustZone {
  name: String!
}

type Statistics {
  totalThreatModels: Int!
  totalThreats: Int!
  totalInformationAssets: Int!
  totalControls: Int!
  implementedControls: Int!
  averageRiskReduction: Float
}

input ThreatModelFilter {
  author: String
  internetFacing: Boolean
  newInitiative: Boolean
  initiativeSize: String
}

input ThreatFilter {
  impacts: [String!]
  stride: [String!]
  hasImplementedControls: Boolean
}
Phase 2: Project Structure
Create new files:

cmd/threatcl/
└── server.go           # Main server command (similar to mcp.go)

internal/
├── graphql/
│   ├── schema.graphql  # GraphQL schema definition
│   ├── resolver.go     # Root resolver
│   ├── generated.go    # Generated code (from gqlgen)
│   ├── models.go       # GraphQL model types
│   └── loaders.go      # DataLoader for N+1 prevention
└── cache/
    └── cache.go        # In-memory cache for parsed threat models

Note: Using internal/ instead of pkg/ to keep these as private implementation details
of the threatcl application, preventing external packages from importing them.
Phase 3: Technology Stack
Recommended Libraries:

require (
    github.com/99designs/gqlgen v0.17.x        // GraphQL code generator
    github.com/go-chi/chi/v5 v5.x             // HTTP router
    github.com/rs/cors v1.x                   // CORS support
    github.com/fsnotify/fsnotify v1.7.x       // File watching (optional)
)
Why gqlgen?

Code-first approach
Type-safe resolvers
Built-in DataLoader support
Excellent performance
Active maintenance
Phase 4: Core Implementation
1. Server Command (cmd/threatcl/server.go)

import (
    "github.com/threatcl/threatcl/internal/cache"
    "github.com/threatcl/threatcl/internal/graphql"
)

type ServerCommand struct {
    *GlobalCmdOptions
    specCfg     *spec.ThreatmodelSpecConfig
    flagDir     string
    flagPort    int
    flagWatch   bool
    cache       *cache.ThreatModelCache
}

func (c *ServerCommand) Run(args []string) int {
    // Parse flags: -dir, -port (default 8080), -watch
    // Validate directory path
    // Initialize cache
    // Load all threat models into memory
    // Setup GraphQL server
    // Start HTTP server
    // If -watch enabled, start file watcher
}
2. Cache Implementation (internal/cache/cache.go)

type ThreatModelCache struct {
    mu          sync.RWMutex
    models      map[string]*spec.Threatmodel  // key: threatmodel name
    fileToModel map[string][]string           // key: filepath, value: model names
    specCfg     *spec.ThreatmodelSpecConfig
    rootDir     string
}

func (c *ThreatModelCache) LoadAll() error
func (c *ThreatModelCache) Get(name string) (*spec.Threatmodel, error)
func (c *ThreatModelCache) GetAll() []*spec.Threatmodel
func (c *ThreatModelCache) Reload(filepath string) error
func (c *ThreatModelCache) GetByFilter(filter ThreatModelFilter) []*spec.Threatmodel
3. GraphQL Resolvers (internal/graphql/resolver.go)

import "github.com/threatcl/threatcl/internal/cache"

type Resolver struct {
    cache *cache.ThreatModelCache
}

// Query resolvers
func (r *queryResolver) ThreatModels(ctx context.Context, filter *ThreatModelFilter) ([]*ThreatModel, error)
func (r *queryResolver) ThreatModel(ctx context.Context, name string) (*ThreatModel, error)
func (r *queryResolver) Threats(ctx context.Context, filter *ThreatFilter) ([]*Threat, error)
func (r *queryResolver) InformationAssets(ctx context.Context, classification *string) ([]*InformationAsset, error)
func (r *queryResolver) Stats(ctx context.Context) (*Statistics, error)

// Field resolvers
func (r *threatResolver) ThreatModel(ctx context.Context, obj *Threat) (*ThreatModel, error)
func (r *informationAssetResolver) ThreatModel(ctx context.Context, obj *InformationAsset) (*ThreatModel, error)
4. Model Mapping (internal/graphql/models.go)

Convert spec.Threatmodel → GraphQL types:

Map nested structures (threats, assets, controls)
Handle optional fields appropriately
Add computed fields (e.g., sourceFile)
Implement bidirectional references (threat → threatModel)
5. HTTP Server Setup (in cmd/threatcl/server.go)

import (
    "github.com/threatcl/threatcl/internal/cache"
    "github.com/threatcl/threatcl/internal/graphql"
)

func setupServer(cache *cache.ThreatModelCache, port int) *http.Server {
    router := chi.NewRouter()

    // Middleware
    router.Use(cors.Default().Handler)
    router.Use(middleware.Logger)
    router.Use(middleware.Recoverer)

    // GraphQL handler
    srv := handler.NewDefaultServer(
        graphql.NewExecutableSchema(
            graphql.Config{Resolvers: &graphql.Resolver{Cache: cache}}
        )
    )

    // Routes
    router.Handle("/graphql", srv)
    router.Handle("/", playground.Handler("threatcl GraphQL", "/graphql"))

    return &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: router,
    }
}
Phase 5: Advanced Features
1. File Watching (Optional)

func (c *ServerCommand) watchFiles() {
    watcher, _ := fsnotify.NewWatcher()
    go func() {
        for {
            select {
            case event := <-watcher.Events:
                if event.Op&fsnotify.Write == fsnotify.Write {
                    c.cache.Reload(event.Name)
                }
            }
        }
    }()
}
2. GraphQL Subscriptions (Future Enhancement)

Real-time updates when threat models change
WebSocket support
3. Filtering & Search

Full-text search across threat descriptions
Complex filtering by multiple attributes
Sorting capabilities
4. Pagination

Cursor-based pagination for large datasets
Relay-style connections
Phase 6: CLI Integration
Update cmd/threatcl/threatcl.go:30-100:

Commands := map[string]cli.CommandFactory{
    // ... existing commands ...
    "server": func() (cli.Command, error) {
        return &ServerCommand{
            GlobalCmdOptions: globalCmdOptions,
            specCfg:          cfg,
        }, nil
    },
}
Phase 7: Documentation & Help
func (c *ServerCommand) Help() string {
    return `
Usage: threatcl server [options]

  Start a GraphQL API server that exposes threat model data

  The server will load all HCL files from the specified directory
  into memory and serve them via a GraphQL API.

Options:

 -config=<file>
   Optional config file

 -dir=<path>
   Directory path containing HCL threat model files (required)

 -port=<number>
   Port to listen on (default: 8080)

 -watch
   Watch for file changes and reload automatically (default: false)

Examples:

  # Start server on default port
  threatcl server -dir ./examples

  # Start with custom port and file watching
  threatcl server -dir ./threatmodels -port 3000 -watch

  # Access GraphQL playground at http://localhost:8080
`
}
🔍 Example GraphQL Queries
Get all threat models:

query {
  threatModels {
    name
    author
    description
    attributes {
      internetFacing
      initiativeSize
    }
    threats {
      description
      impacts
      controls {
        name
        implemented
        riskReduction
      }
    }
  }
}
Get specific threat model:

query {
  threatModel(name: "Tower of London") {
    name
    informationAssets {
      name
      informationClassification
    }
    threats {
      description
      controls {
        name
        implemented
      }
    }
  }
}
Search threats by STRIDE:

query {
  threats(filter: { stride: ["Spoofing", "Tampering"] }) {
    description
    threatModel {
      name
      author
    }
    controls {
      name
      riskReduction
    }
  }
}
Get statistics:

query {
  stats {
    totalThreatModels
    totalThreats
    implementedControls
    averageRiskReduction
  }
}
📦 Implementation Steps
Setup (1-2 hours)

Add GraphQL dependencies to go.mod
Initialize gqlgen configuration
Create internal/ directory structure (internal/graphql, internal/cache)
Schema (2-3 hours)

Define complete GraphQL schema
Generate code with gqlgen
Create model mappers
Cache Layer (2-3 hours)

Implement thread-safe cache
File discovery and parsing logic
Reload mechanisms
Resolvers (3-4 hours)

Implement all query resolvers
Add filtering logic
Compute statistics
Server Command (2 hours)

Create ServerCommand struct
Flag parsing and validation
HTTP server setup
Testing (2-3 hours)

Unit tests for cache
Integration tests for resolvers
End-to-end GraphQL query tests
Documentation (1 hour)

Update README
Add GraphQL examples
Document API endpoints
Total Estimated Time: 13-18 hours

✅ Key Benefits
In-Memory Performance: All data loaded once, fast query responses
Powerful Querying: GraphQL allows clients to request exactly what they need
Type Safety: gqlgen provides compile-time type checking
Introspection: Built-in schema documentation via GraphQL playground
Familiar Pattern: Follows existing MCP server implementation
Extensible: Easy to add mutations, subscriptions, or new fields
🚀 Future Enhancements
Mutations: Create/update/delete threat models via API
Authentication: JWT or API key authentication
Rate Limiting: Prevent API abuse
Caching: Redis for distributed deployments
Metrics: Prometheus metrics endpoint
Export: Direct export to JSON/OTM via GraphQL mutations
This plan provides a complete roadmap for implementing a production-ready GraphQL API server for threatcl, leveraging the existing architecture and following Go best practices.

## 📝 Technical Debt

### File Discovery Code Duplication
**Issue:** File discovery logic (`findAllFiles`, `findHclFiles`, `findJsonFiles`) is duplicated between:
- `cmd/threatcl/util.go` (original implementation)
- `internal/cache/cache.go` (duplicated for cache)

**Why it exists:**
- Proper Go architecture: `internal/` packages should not import from `cmd/` packages
- Kept PR #3 focused on cache implementation without refactoring existing commands

**Recommended fix:**
1. Create `internal/fileutil/discover.go` with file discovery functions
2. Update `cmd/threatcl/util.go` to import and use `internal/fileutil`
3. Update `internal/cache/cache.go` to import and use `internal/fileutil`
4. Remove duplicated code from both locations

**Benefits:**
- Single source of truth for file discovery
- Easier maintenance (changes only needed in one place)
- Better testability
- Follows DRY principle

**Estimated effort:** 30 minutes - 1 hour
