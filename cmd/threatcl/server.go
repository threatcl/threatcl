package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/fsnotify/fsnotify"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/cache"
	"github.com/threatcl/threatcl/internal/graphql"
)

type ServerCommand struct {
	*GlobalCmdOptions
	specCfg   *spec.ThreatmodelSpecConfig
	flagDir   string
	flagPort  int
	flagWatch bool
}

func (c *ServerCommand) Help() string {
	helpText := `
Usage: threatcl server [options]

  Start a GraphQL API server that exposes threat model data

  The server will load all HCL and JSON files from the specified directory
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

  # Start with custom port
  threatcl server -dir ./threatmodels -port 3000

  # Access GraphQL playground at http://localhost:8080
  # GraphQL API endpoint at http://localhost:8080/graphql
`
	return strings.TrimSpace(helpText)
}

func (c *ServerCommand) Synopsis() string {
	return "Start a GraphQL API server for threat models"
}

func (c *ServerCommand) Run(args []string) int {
	flagSet := c.GetFlagset("server")
	flagSet.StringVar(&c.flagDir, "dir", "", "Directory containing threat model files (required)")
	flagSet.IntVar(&c.flagPort, "port", 8080, "Port to listen on")
	flagSet.BoolVar(&c.flagWatch, "watch", false, "Watch for file changes and reload (not yet implemented)")
	flagSet.Parse(args)

	// Load spec config if provided
	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
		if err != nil {
			fmt.Printf("Error loading config file: %s\n", err)
			return 1
		}
	}

	// Validate required flags
	if c.flagDir == "" {
		fmt.Println("Error: -dir flag is required")
		fmt.Println()
		fmt.Println(c.Help())
		return 1
	}

	// Verify directory exists
	info, err := os.Stat(c.flagDir)
	if os.IsNotExist(err) {
		fmt.Printf("Error: Directory '%s' does not exist\n", c.flagDir)
		return 1
	}
	if !info.IsDir() {
		fmt.Printf("Error: '%s' is not a directory\n", c.flagDir)
		return 1
	}

	// Initialize cache
	fmt.Printf("Loading threat models from '%s'...\n", c.flagDir)
	tmCache := cache.NewThreatModelCache(c.specCfg, c.flagDir)
	err = tmCache.LoadAll()
	if err != nil {
		fmt.Printf("Error loading threat models: %s\n", err)
		return 1
	}

	count := tmCache.Count()
	fmt.Printf("Loaded %d threat model(s)\n", count)

	// Set up file watcher if requested
	var watcher *fsnotify.Watcher
	var err2 error
	if c.flagWatch {
		watcher, err2 = c.setupFileWatcher(tmCache, c.flagDir)
		if err2 != nil {
			fmt.Printf("Error setting up file watcher: %s\n", err2)
			return 1
		}
		fmt.Println("File watching enabled - changes will be automatically reloaded")
	}

	// Set up HTTP server
	srv := c.setupServer(tmCache, c.flagPort)

	// Start server in a goroutine
	go func() {
		fmt.Printf("Starting GraphQL server on http://localhost:%d\n", c.flagPort)
		fmt.Printf("GraphQL Playground: http://localhost:%d\n", c.flagPort)
		fmt.Printf("GraphQL API: http://localhost:%d/graphql\n", c.flagPort)
		fmt.Println("Press Ctrl+C to stop")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down server...")

	// Close file watcher if it was created
	if watcher != nil {
		watcher.Close()
	}

	// Graceful shutdown with 5 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("Server forced to shutdown: %s\n", err)
		return 1
	}

	fmt.Println("Server stopped")
	return 0
}

func (c *ServerCommand) setupServer(tmCache *cache.ThreatModelCache, port int) *http.Server {
	router := chi.NewRouter()

	// Middleware
	router.Use(cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}).Handler)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)

	// Create GraphQL server
	resolver := &graphql.Resolver{
		Cache: tmCache,
	}

	srv := handler.NewDefaultServer(
		graphql.NewExecutableSchema(
			graphql.Config{Resolvers: resolver},
		),
	)

	// Routes
	router.Handle("/graphql", srv)
	router.Handle("/", playground.Handler("threatcl GraphQL Playground", "/graphql"))

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - %d threat models loaded\n", tmCache.Count())
	})

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func (c *ServerCommand) setupFileWatcher(tmCache *cache.ThreatModelCache, rootDir string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Watch the root directory recursively
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			err = watcher.Add(path)
			if err != nil {
				return fmt.Errorf("failed to watch directory %s: %w", path, err)
			}
		}
		return nil
	})
	if err != nil {
		watcher.Close()
		return nil, err
	}

	// Start watching for events in a goroutine
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only process .hcl and .json files
				ext := filepath.Ext(event.Name)
				if ext != ".hcl" && ext != ".json" {
					continue
				}

				switch {
				case event.Op&fsnotify.Write == fsnotify.Write:
					// File was modified
					fmt.Printf("File modified: %s - reloading...\n", event.Name)
					if err := tmCache.Reload(event.Name); err != nil {
						fmt.Printf("Error reloading file %s: %s\n", event.Name, err)
					} else {
						fmt.Printf("Successfully reloaded %s (%d threat models loaded)\n", event.Name, tmCache.Count())
					}

				case event.Op&fsnotify.Create == fsnotify.Create:
					// File was created
					fmt.Printf("File created: %s - loading...\n", event.Name)
					if err := tmCache.Reload(event.Name); err != nil {
						fmt.Printf("Error loading file %s: %s\n", event.Name, err)
					} else {
						fmt.Printf("Successfully loaded %s (%d threat models loaded)\n", event.Name, tmCache.Count())
					}

				case event.Op&fsnotify.Remove == fsnotify.Remove:
					// File was deleted
					fmt.Printf("File removed: %s - removing from cache...\n", event.Name)
					tmCache.RemoveFile(event.Name)
					fmt.Printf("Successfully removed %s (%d threat models remaining)\n", event.Name, tmCache.Count())

				case event.Op&fsnotify.Rename == fsnotify.Rename:
					// File was renamed (treat as deletion of old name)
					fmt.Printf("File renamed: %s - removing from cache...\n", event.Name)
					tmCache.RemoveFile(event.Name)
					fmt.Printf("Successfully removed %s (%d threat models remaining)\n", event.Name, tmCache.Count())
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("File watcher error: %s\n", err)
			}
		}
	}()

	return watcher, nil
}
