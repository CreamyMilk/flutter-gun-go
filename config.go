// config.go - Configuration management for reFlutter Go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config represents the main configuration structure
type Config struct {
	Version string       `json:"version"`
	Engine  EngineConfig `json:"engine"`
	Proxy   ProxyConfig  `json:"proxy"`
	Output  OutputConfig `json:"output"`
	Logging LogConfig    `json:"logging"`
	Patches PatchConfig  `json:"patches"`
}

// EngineConfig holds Flutter engine configuration
type EngineConfig struct {
	HashURL        string            `json:"hash_url"`
	ReleaseBaseURL string            `json:"release_base_url"`
	Architectures  []string          `json:"architectures"`
	Platforms      []string          `json:"platforms"`
	Modes          []string          `json:"modes"`
	CustomEngines  map[string]string `json:"custom_engines"`
}

// ProxyConfig holds proxy configuration
type ProxyConfig struct {
	DefaultIP     string `json:"default_ip"`
	DefaultPort   int    `json:"default_port"`
	EnableSSL     bool   `json:"enable_ssl"`
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
	LogTraffic    bool   `json:"log_traffic"`
	TrafficLogDir string `json:"traffic_log_dir"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	DefaultSuffix  string `json:"default_suffix"`
	BackupOriginal bool   `json:"backup_original"`
	SignAPK        bool   `json:"sign_apk"`
	SignerPath     string `json:"signer_path"`
	AlignAPK       bool   `json:"align_apk"`
	AlignerPath    string `json:"aligner_path"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level      string `json:"level"`
	OutputFile string `json:"output_file"`
	EnableFile bool   `json:"enable_file"`
	MaxSize    int    `json:"max_size"`
	MaxBackups int    `json:"max_backups"`
}

// PatchConfig holds patch configuration
type PatchConfig struct {
	EnableSocket     bool     `json:"enable_socket"`
	EnableDart       bool     `json:"enable_dart"`
	EnableSSL        bool     `json:"enable_ssl"`
	EnableHTTP       bool     `json:"enable_http"`
	CustomPatches    []string `json:"custom_patches"`
	PatchesDirectory string   `json:"patches_directory"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Version: VERSION,
		Engine: EngineConfig{
			HashURL:        "https://raw.githubusercontent.com/Impact-I/reFlutter/main/enginehash.csv",
			ReleaseBaseURL: "https://github.com/Impact-I/reFlutter/releases/download",
			Architectures:  []string{"arm64", "arm32", "x64"},
			Platforms:      []string{"android", "ios"},
			Modes:          []string{"release", "debug"},
			CustomEngines:  make(map[string]string),
		},
		Proxy: ProxyConfig{
			DefaultIP:     "127.0.0.1",
			DefaultPort:   8083,
			EnableSSL:     false,
			LogTraffic:    true,
			TrafficLogDir: "./traffic_logs",
		},
		Output: OutputConfig{
			DefaultSuffix:  ".RE",
			BackupOriginal: true,
			SignAPK:        false,
			AlignAPK:       false,
		},
		Logging: LogConfig{
			Level:      "info",
			OutputFile: "reflutter.log",
			EnableFile: true,
			MaxSize:    10,
			MaxBackups: 3,
		},
		Patches: PatchConfig{
			EnableSocket:     true,
			EnableDart:       true,
			EnableSSL:        true,
			EnableHTTP:       true,
			CustomPatches:    []string{},
			PatchesDirectory: "./patches",
		},
	}
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) (*Config, error) {
	// If config file doesn't exist, create default
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config := DefaultConfig()
		if err := SaveConfig(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
		return config, nil
	}

	// Load existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, configPath string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetConfigPath returns the default configuration path
func GetConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./reflutter.json"
	}
	return filepath.Join(homeDir, ".reflutter", "config.json")
}

// Logger provides logging functionality
type Logger struct {
	level      string
	outputFile string
	enableFile bool
}

// NewLogger creates a new logger instance
func NewLogger(config LogConfig) *Logger {
	return &Logger{
		level:      config.Level,
		outputFile: config.OutputFile,
		enableFile: config.EnableFile,
	}
}

// Log logs a message with the specified level
func (l *Logger) Log(level, message string) {
	timestamp := fmt.Sprintf("[%s]", time.Now().Format("2006-01-02 15:04:05"))
	logMessage := fmt.Sprintf("%s [%s] %s", timestamp, level, message)

	// Always print to console
	fmt.Println(logMessage)

	// Write to file if enabled
	if l.enableFile {
		l.writeToFile(logMessage)
	}
}

// Info logs an info message
func (l *Logger) Info(message string) {
	l.Log("INFO", message)
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.Log("WARN", message)
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.Log("ERROR", message)
}

// Debug logs a debug message
func (l *Logger) Debug(message string) {
	if l.level == "debug" {
		l.Log("DEBUG", message)
	}
}

// writeToFile writes log message to file
func (l *Logger) writeToFile(message string) {
	file, err := os.OpenFile(l.outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(message + "\n")
}
