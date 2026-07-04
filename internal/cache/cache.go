package cache

import (
	"fmt"
	"sync"

	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/tmloader"
)

// ThreatModelCache provides thread-safe in-memory storage for parsed threat models
type ThreatModelCache struct {
	mu          sync.RWMutex
	models      map[string]*spec.Threatmodel // key: threatmodel name
	fileToModel map[string][]string          // key: filepath, value: model names
	modelToFile map[string]string            // key: threatmodel name, value: filepath
	specCfg     *spec.ThreatmodelSpecConfig
	rootDir     string
}

// NewThreatModelCache creates a new cache instance
func NewThreatModelCache(specCfg *spec.ThreatmodelSpecConfig, rootDir string) *ThreatModelCache {
	return &ThreatModelCache{
		models:      make(map[string]*spec.Threatmodel),
		fileToModel: make(map[string][]string),
		modelToFile: make(map[string]string),
		specCfg:     specCfg,
		rootDir:     rootDir,
	}
}

// LoadAll loads all HCL and JSON files from the root directory into memory
func (c *ThreatModelCache) LoadAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear existing cache
	c.models = make(map[string]*spec.Threatmodel)
	c.fileToModel = make(map[string][]string)
	c.modelToFile = make(map[string]string)

	// Find all HCL and JSON files via the shared loader seam
	files := tmloader.FindFiles([]string{c.rootDir})

	// Parse each file
	for _, file := range files {
		if err := c.loadFile(file); err != nil {
			return fmt.Errorf("error loading %s: %w", file, err)
		}
	}

	return nil
}

// loadFile parses a single file and adds its threat models to the cache
// Note: This method is NOT thread-safe and should only be called from within locked sections
func (c *ThreatModelCache) loadFile(filepath string) error {
	wrapped, err := tmloader.ParseFile(c.specCfg, filepath)
	if err != nil {
		return err
	}

	modelNames := []string{}
	for i := range wrapped.Threatmodels {
		tm := &wrapped.Threatmodels[i]
		c.models[tm.Name] = tm
		c.modelToFile[tm.Name] = filepath
		modelNames = append(modelNames, tm.Name)
	}

	c.fileToModel[filepath] = modelNames

	return nil
}

// Get retrieves a single threat model by name
func (c *ThreatModelCache) Get(name string) (*spec.Threatmodel, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tm, exists := c.models[name]
	if !exists {
		return nil, fmt.Errorf("threat model '%s' not found", name)
	}

	return tm, nil
}

// GetAll retrieves all threat models
func (c *ThreatModelCache) GetAll() []*spec.Threatmodel {
	c.mu.RLock()
	defer c.mu.RUnlock()

	models := make([]*spec.Threatmodel, 0, len(c.models))
	for _, tm := range c.models {
		models = append(models, tm)
	}

	return models
}

// Reload reloads a specific file and updates the cache
func (c *ThreatModelCache) Reload(filepath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove old models from this file
	if modelNames, exists := c.fileToModel[filepath]; exists {
		for _, name := range modelNames {
			delete(c.models, name)
			delete(c.modelToFile, name)
		}
	}

	// Reload the file
	return c.loadFile(filepath)
}

// RemoveFile removes all threat models associated with a file from the cache
func (c *ThreatModelCache) RemoveFile(filepath string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove all models from this file
	if modelNames, exists := c.fileToModel[filepath]; exists {
		for _, name := range modelNames {
			delete(c.models, name)
			delete(c.modelToFile, name)
		}
		delete(c.fileToModel, filepath)
	}
}

// GetSourceFile returns the source file path for a given threat model name
func (c *ThreatModelCache) GetSourceFile(modelName string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	filepath, exists := c.modelToFile[modelName]
	return filepath, exists
}

// GetFileToModelMapping returns a copy of the file-to-model mapping for debugging
func (c *ThreatModelCache) GetFileToModelMapping() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	mapping := make(map[string][]string)
	for file, models := range c.fileToModel {
		modelsCopy := make([]string, len(models))
		copy(modelsCopy, models)
		mapping[file] = modelsCopy
	}

	return mapping
}

// Count returns the number of threat models in the cache
func (c *ThreatModelCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.models)
}
