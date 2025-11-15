package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/threatcl/spec"
)

func TestNewThreatModelCache(t *testing.T) {
	cfg := &spec.ThreatmodelSpecConfig{}
	cache := NewThreatModelCache(cfg, "/test/dir")

	if cache == nil {
		t.Fatal("Expected cache to be created")
	}

	if cache.rootDir != "/test/dir" {
		t.Errorf("Expected rootDir to be '/test/dir', got '%s'", cache.rootDir)
	}

	if cache.models == nil {
		t.Error("Expected models map to be initialized")
	}

	if cache.fileToModel == nil {
		t.Error("Expected fileToModel map to be initialized")
	}
}

func TestLoadAll(t *testing.T) {
	// Get the examples directory
	examplesDir := filepath.Join("..", "..", "examples")

	// Skip test if examples directory doesn't exist
	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("Failed to load default spec config: %v", err)
	}

	cache := NewThreatModelCache(cfg, examplesDir)

	err = cache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load all files: %v", err)
	}

	count := cache.Count()
	if count == 0 {
		t.Error("Expected at least one threat model to be loaded")
	}

	t.Logf("Loaded %d threat models", count)
}

func TestGetAndGetAll(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("Failed to load default spec config: %v", err)
	}

	cache := NewThreatModelCache(cfg, examplesDir)
	err = cache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load all files: %v", err)
	}

	// Test GetAll
	allModels := cache.GetAll()
	if len(allModels) == 0 {
		t.Fatal("Expected GetAll to return at least one model")
	}

	// Test Get with first model name
	firstModel := allModels[0]
	retrievedModel, err := cache.Get(firstModel.Name)
	if err != nil {
		t.Fatalf("Failed to get model by name: %v", err)
	}

	if retrievedModel.Name != firstModel.Name {
		t.Errorf("Expected model name '%s', got '%s'", firstModel.Name, retrievedModel.Name)
	}

	// Test Get with non-existent name
	_, err = cache.Get("NonExistentThreatModel")
	if err == nil {
		t.Error("Expected error when getting non-existent model")
	}
}

func TestGetSourceFile(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("Failed to load default spec config: %v", err)
	}

	cache := NewThreatModelCache(cfg, examplesDir)
	err = cache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load all files: %v", err)
	}

	allModels := cache.GetAll()
	if len(allModels) == 0 {
		t.Fatal("Expected at least one model to be loaded")
	}

	// Test getting source file for existing model
	modelName := allModels[0].Name
	sourceFile, exists := cache.GetSourceFile(modelName)
	if !exists {
		t.Errorf("Expected to find source file for model '%s'", modelName)
	}
	if sourceFile == "" {
		t.Error("Expected non-empty source file path")
	}

	t.Logf("Model '%s' is from file '%s'", modelName, sourceFile)

	// Test getting source file for non-existent model
	_, exists = cache.GetSourceFile("NonExistentModel")
	if exists {
		t.Error("Expected false for non-existent model")
	}
}

func TestCount(t *testing.T) {
	cfg := &spec.ThreatmodelSpecConfig{}
	cache := NewThreatModelCache(cfg, "/test/dir")

	if cache.Count() != 0 {
		t.Error("Expected empty cache to have count of 0")
	}
}

func TestGetFileToModelMapping(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("Failed to load default spec config: %v", err)
	}

	cache := NewThreatModelCache(cfg, examplesDir)
	err = cache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load all files: %v", err)
	}

	mapping := cache.GetFileToModelMapping()
	if len(mapping) == 0 {
		t.Error("Expected file-to-model mapping to have at least one entry")
	}

	t.Logf("Found %d files with threat models", len(mapping))
	for file, models := range mapping {
		t.Logf("File %s contains %d models: %v", file, len(models), models)
	}
}

func TestFindHclFiles(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cfg := &spec.ThreatmodelSpecConfig{}
	cache := NewThreatModelCache(cfg, examplesDir)

	files := cache.findHclFiles([]string{examplesDir})
	if len(files) == 0 {
		t.Error("Expected to find at least one HCL file")
	}

	for _, file := range files {
		if filepath.Ext(file) != ".hcl" {
			t.Errorf("Expected only .hcl files, got %s", file)
		}
	}

	t.Logf("Found %d HCL files", len(files))
}

func TestConcurrentAccess(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")

	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("Failed to load default spec config: %v", err)
	}

	cache := NewThreatModelCache(cfg, examplesDir)
	err = cache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load all files: %v", err)
	}

	// Test concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = cache.GetAll()
			_ = cache.Count()
			_, _ = cache.GetSourceFile("TestModel")
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
