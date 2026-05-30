package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/99designs/keyring"
)

// Interfaces for dependency injection (testing)

// HTTPClient interface for HTTP operations
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

// KeyringService interface for keyring operations
type KeyringService interface {
	Get(key string) (string, error)
	GetRaw(key string) ([]byte, error)
	Set(key string, data map[string]interface{}) error
	SetRaw(key string, data []byte) error
	Delete(key string) error
}

// FileSystemService interface for file system operations
type FileSystemService interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Stat(path string) (os.FileInfo, error)
	Getenv(key string) string
}

// Default implementations

// defaultHTTPClient wraps http.Client to implement HTTPClient interface
type defaultHTTPClient struct {
	client *http.Client
}

func (d *defaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return d.client.Do(req)
}

func (d *defaultHTTPClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return http.Post(url, contentType, body)
}

// defaultKeyringService wraps keyring to implement KeyringService interface
type defaultKeyringService struct{}

func (d *defaultKeyringService) openKeyring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName: "threatcl",
	})
}

func (d *defaultKeyringService) Get(key string) (string, error) {
	ring, err := d.openKeyring()
	if err != nil {
		return "", fmt.Errorf("failed to open keyring: %w", err)
	}

	item, err := ring.Get(key)
	if err != nil {
		return "", fmt.Errorf("failed to get token from keyring: %w", err)
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(item.Data, &tokenData); err != nil {
		return "", fmt.Errorf("failed to parse token data: %w", err)
	}

	accessToken, ok := tokenData["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format in keyring")
	}

	return accessToken, nil
}

func (d *defaultKeyringService) GetRaw(key string) ([]byte, error) {
	ring, err := d.openKeyring()
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	item, err := ring.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from keyring: %w", err)
	}

	return item.Data, nil
}

func (d *defaultKeyringService) Set(key string, data map[string]interface{}) error {
	tokenJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	return d.SetRaw(key, tokenJSON)
}

func (d *defaultKeyringService) SetRaw(key string, data []byte) error {
	ring, err := d.openKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	err = ring.Set(keyring.Item{
		Key:         key,
		Label:       "ThreatCL Cloud Credentials",
		Description: "ThreatCL Cloud API tokens",
		Data:        data,
	})
	if err != nil {
		return fmt.Errorf("failed to save to keyring: %w", err)
	}

	return nil
}

func (d *defaultKeyringService) Delete(key string) error {
	ring, err := d.openKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	err = ring.Remove(key)
	if err != nil {
		return fmt.Errorf("failed to delete from keyring: %w", err)
	}

	return nil
}

// defaultFileSystemService wraps os operations to implement FileSystemService interface
type defaultFileSystemService struct{}

func (d *defaultFileSystemService) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (d *defaultFileSystemService) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (d *defaultFileSystemService) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (d *defaultFileSystemService) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (d *defaultFileSystemService) Getenv(key string) string {
	return os.Getenv(key)
}
