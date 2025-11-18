package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"

	gqlgen "github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/cache"
	"github.com/threatcl/threatcl/internal/graphql"
)

type QueryCommand struct {
	*GlobalCmdOptions
	specCfg      *spec.ThreatmodelSpecConfig
	flagDir      string
	flagQuery    string
	flagFile     string
	flagVars     string
	flagOutput   string
	flagExamples bool
}

func (c *QueryCommand) Examples() string {
	exampleText := `
Examples:

  # Basic inline query
  threatcl query -dir ./examples -query '{ stats { totalThreats } }'

  # Query from file
  threatcl query -dir ./examples -file query.graphql

  # Query from STDIN
  echo '{ stats { totalThreats } }' | threatcl query -dir ./examples

  # Query from STDIN with heredoc
  threatcl query -dir ./examples <<EOF
  {
    stats {
      totalThreats
      totalControls
    }
  }
  EOF

  # Query with variables
  threatcl query -dir ./examples \
    -query 'query($author: String) { threatModels(filter: {author: $author}) { name } }' \
    -vars '{"author": "John Doe"}'

  # Compact output for scripting
  threatcl query -dir ./examples \
    -query '{ stats { totalThreats } }' \
    -output compact

  # Pipe to jq for processing
  echo '{ stats { totalThreats } }' | \
    threatcl query -dir ./examples | \
    jq '.data.stats.totalThreats'

  # Use in shell script
  THREAT_COUNT=$(echo '{ stats { totalThreats } }' | \
    threatcl query -dir ./examples -output compact | \
    jq -r '.data.stats.totalThreats')
  echo "Found $THREAT_COUNT threats"
`
	return strings.TrimSpace(exampleText)
}

func (c *QueryCommand) Help() string {
	helpText := `
Usage: threatcl query [options]

  Execute GraphQL queries against threat model data without starting a server

  The command will load all HCL and JSON files from the specified directory
  into memory and execute the GraphQL query directly, outputting results to stdout.

  Query Input (in order of precedence):
    1. -query flag: Inline GraphQL query string
    2. -file flag: Read query from file
    3. STDIN: Read query from standard input (if neither -query nor -file is set)

Options:

 -config=<file>
   Optional config file

 -dir=<path>
   Directory path containing HCL threat model files (required)

 -examples
   Print out example queries

 -query=<string>
   GraphQL query string (mutually exclusive with -file)

 -file=<path>
   Path to file containing GraphQL query (mutually exclusive with -query)

 -vars=<json>
   JSON-encoded variables for the query (optional)

 -output=<format>
   Output format: json, pretty, compact (default: pretty)

`
	return strings.TrimSpace(helpText)
}

func (c *QueryCommand) Synopsis() string {
	return "Execute GraphQL queries against threat model data"
}

func (c *QueryCommand) Run(args []string) int {
	// 1. Parse and validate flags
	flagSet := c.GetFlagset("query")
	flagSet.StringVar(&c.flagDir, "dir", "", "Directory containing threat model files (required)")
	flagSet.StringVar(&c.flagQuery, "query", "", "GraphQL query string")
	flagSet.StringVar(&c.flagFile, "file", "", "Path to file containing GraphQL query")
	flagSet.StringVar(&c.flagVars, "vars", "", "JSON-encoded variables")
	flagSet.StringVar(&c.flagOutput, "output", "pretty", "Output format: json, pretty, compact")
	flagSet.BoolVar(&c.flagExamples, "examples", false, "If set, will print out examples")
	flagSet.Parse(args)

	// Load spec config if provided
	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %s\n", err)
			return 1
		}
	}

	if c.flagExamples {
		fmt.Println(c.Examples())
		return 0
	}

	// 2. Validate inputs
	if c.flagDir == "" {
		fmt.Fprintln(os.Stderr, "Error: -dir flag is required")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, c.Help())
		return 1
	}

	if c.flagQuery != "" && c.flagFile != "" {
		fmt.Fprintln(os.Stderr, "Error: -query and -file are mutually exclusive")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, c.Help())
		return 1
	}

	// Verify directory exists
	info, err := os.Stat(c.flagDir)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Directory '%s' does not exist\n", c.flagDir)
		return 1
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a directory\n", c.flagDir)
		return 1
	}

	// 3. Read query from flag, file, or stdin
	var queryString string
	if c.flagQuery != "" {
		// Use inline query
		queryString = c.flagQuery
	} else if c.flagFile != "" {
		// Read from file
		content, err := os.ReadFile(c.flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading query file: %s\n", err)
			return 1
		}
		queryString = string(content)
	} else {
		// Try to read from stdin
		info, err := os.Stdin.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing STDIN: %s\n", err)
			return 1
		}

		if info.Mode()&os.ModeCharDevice != 0 || info.Size() <= 0 {
			fmt.Fprintln(os.Stderr, "Error: either -query, -file, or STDIN must be provided")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, c.Help())
			return 1
		}

		reader := bufio.NewReader(os.Stdin)
		var output []rune
		for {
			input, _, err := reader.ReadRune()
			if err != nil && err == io.EOF {
				break
			}
			output = append(output, input)
		}

		queryString = string(output)
	}

	// 4. Initialize cache and load threat models
	tmCache := cache.NewThreatModelCache(c.specCfg, c.flagDir)
	err = tmCache.LoadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading threat models: %s\n", err)
		return 1
	}

	// 5. Create resolver and executable schema
	resolver := &graphql.Resolver{
		Cache: tmCache,
	}

	schema := graphql.NewExecutableSchema(
		graphql.Config{Resolvers: resolver},
	)

	// 6. Parse variables if provided
	var variables map[string]interface{}
	if c.flagVars != "" {
		err := json.Unmarshal([]byte(c.flagVars), &variables)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing variables: %s\n", err)
			return 1
		}
	}

	// 7. Execute query directly using the handler
	graphqlResponse, err := executeQuery(schema, queryString, variables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing query: %s\n", err)
		return 1
	}

	// 8. Format and output results
	var output []byte
	switch c.flagOutput {
	case "pretty", "json":
		output, err = json.MarshalIndent(graphqlResponse, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting output: %s\n", err)
			return 1
		}
	case "compact":
		output, err = json.Marshal(graphqlResponse)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting output: %s\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid output format '%s' (must be: json, pretty, or compact)\n", c.flagOutput)
		return 1
	}

	fmt.Println(string(output))

	// Return error code if GraphQL query had errors
	if len(graphqlResponse.Errors) > 0 {
		return 1
	}

	return 0
}

// executeQuery executes a GraphQL query directly using the handler without starting an HTTP server.
// This uses httptest to create a request/response pair, which is the standard way to use
// gqlgen handlers programmatically. No actual network I/O occurs.
func executeQuery(schema gqlgen.ExecutableSchema, query string, variables map[string]interface{}) (*graphqlResponse, error) {
	// Create a GraphQL handler
	srv := handler.NewDefaultServer(schema)

	// Create GraphQL request payload
	requestPayload := map[string]interface{}{
		"query": query,
	}
	if variables != nil {
		requestPayload["variables"] = variables
	}

	requestBody, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Execute query using httptest (no actual server is started - this is just using
	// the HTTP handler interface programmatically)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Parse response
	var graphqlResp graphqlResponse
	err = json.Unmarshal(responseBody, &graphqlResp)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &graphqlResp, nil
}

type graphqlResponse struct {
	Data   interface{}              `json:"data"`
	Errors []map[string]interface{} `json:"errors"`
}
