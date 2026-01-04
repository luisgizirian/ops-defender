package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	Port                 string
	AnalysisThreshold    int
	BlockDuration        time.Duration
	MaxTrackedIPs        int
	EvictionBatchPct     float64
	EvictionThresholdPct float64
	SimulationMode       bool
	RedisURL             string

	// Reporting
	MaxReportAgeDays    int
	AzureStorageEnabled bool
	AzureConnString     string
	AzureContainer      string

	// Email
	EmailEnabled bool
	EmailTo      string
	EmailFrom    string
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
}

// LoadConfig reads configuration from environment variables
func LoadConfig() *Config {
	c := &Config{}

	c.Port = getEnv("PORT", "8080")

	c.AnalysisThreshold, _ = strconv.Atoi(getEnv("ANALYSIS_THRESHOLD", "5"))

	blockDurationMin, _ := strconv.Atoi(getEnv("BLOCK_DURATION", "60"))
	c.BlockDuration = time.Duration(blockDurationMin) * time.Minute

	c.MaxTrackedIPs, _ = strconv.Atoi(getEnv("MAX_TRACKED_IPS", "10000"))

	c.SimulationMode = getEnv("SIMULATION_MODE", "false") == "true"

	c.RedisURL = os.Getenv("REDIS_URL")

	// Eviction settings
	c.EvictionBatchPct = 0.10
	if pctStr := getEnv("EVICTION_BATCH_PERCENT", ""); pctStr != "" {
		if pct, err := strconv.ParseFloat(pctStr, 64); err == nil && pct > 0.0 && pct <= 1.0 {
			c.EvictionBatchPct = pct
		} else {
			log.Printf("Invalid EVICTION_BATCH_PERCENT value '%s', using default 0.10", pctStr)
		}
	}

	// Use 93% as the optimal eviction threshold (7% buffer)
	c.EvictionThresholdPct = 0.93

	// Reporting settings
	c.MaxReportAgeDays = 30
	if maxAgeStr := os.Getenv("MAX_REPORT_AGE_DAYS"); maxAgeStr != "" {
		if age, err := strconv.Atoi(maxAgeStr); err == nil && age > 0 {
			c.MaxReportAgeDays = age
		} else {
			log.Printf("Invalid MAX_REPORT_AGE_DAYS value '%s', using default: 30", maxAgeStr)
		}
	}

	c.AzureStorageEnabled = os.Getenv("AZURE_STORAGE_ENABLED") == "true"
	c.AzureConnString = os.Getenv("AZURE_STORAGE_CONNECTION_STRING")
	c.AzureContainer = os.Getenv("AZURE_STORAGE_CONTAINER")
	if c.AzureContainer == "" {
		c.AzureContainer = "ops-defender-reports"
	}

	// Email settings
	c.EmailEnabled = os.Getenv("EMAIL_ENABLED") == "true"
	c.EmailTo = os.Getenv("EMAIL_TO")
	c.EmailFrom = os.Getenv("EMAIL_FROM")
	c.SMTPHost = os.Getenv("SMTP_HOST")
	c.SMTPPort = os.Getenv("SMTP_PORT")
	c.SMTPUser = os.Getenv("SMTP_USER")
	c.SMTPPassword = os.Getenv("SMTP_PASSWORD")

	return c
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
