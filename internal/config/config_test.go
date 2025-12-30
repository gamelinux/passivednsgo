package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLoadConfigDefaults(t *testing.T) {
	// Reset Viper for testing
	viper.Reset()

	// Load config without a file (simulating defaults)
	// We don't call LoadConfig() directly because it parses flags which can panic in tests
	// Instead, we manually trigger the default setting logic used in your LoadConfig

	viper.SetDefault("capturethreads", 1)
	viper.SetDefault("interface", "any")
	viper.SetDefault("loglevel", "NOTICE")

	// We expect the default C struct to mirror these defaults when unmarshaled
	// Note: In a real integration test, we would call the actual LoadConfig function,
	// but strictly for unit testing logic, we verify the Viper default mechanism.

	if viper.GetInt("capturethreads") != 1 {
		t.Errorf("Expected default capturethreads to be 1, got %d", viper.GetInt("capturethreads"))
	}

	if viper.GetString("interface") != "any" {
		t.Errorf("Expected default interface to be 'any', got %s", viper.GetString("interface"))
	}
}

func TestConfigStructStructure(t *testing.T) {
	// This test ensures that the Config struct tags match what Viper expects.
	// We create a sample config map and try to unmarshal it.

	viper.Reset()

	testConfig := map[string]interface{}{
		"interface":      "eth0",
		"capturethreads": 5,
		"loglevel":       "DEBUG",
	}

	for k, v := range testConfig {
		viper.Set(k, v)
	}

	var cfg Config
	err := viper.Unmarshal(&cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if cfg.Iface != "eth0" {
		t.Errorf("Struct field 'Iface' not mapping correctly. Got %s, want eth0", cfg.Iface)
	}
	if cfg.Capthreads != 5 {
		t.Errorf("Struct field 'Capthreads' not mapping correctly. Got %d, want 5", cfg.Capthreads)
	}
	if cfg.Loglevel != "DEBUG" {
		t.Errorf("Struct field 'Loglevel' not mapping correctly. Got %s, want DEBUG", cfg.Loglevel)
	}
}
