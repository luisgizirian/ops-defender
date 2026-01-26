package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ops/defender/pkg/extensions"
)

// SQLInjectionDetector is an example PatternAnalyzer that detects SQL injection attempts
// in request URIs using pattern matching.
//
// This demonstrates how to implement a custom analyzer for deferred analysis.
type SQLInjectionDetector struct {
	patterns []*regexp.Regexp
	name     string
	priority int
}

// NewSQLInjectionDetector creates a new SQL injection pattern analyzer
func NewSQLInjectionDetector() *SQLInjectionDetector {
	return &SQLInjectionDetector{
		name:     "sql-injection-detector",
		priority: 10, // High priority - runs early
		patterns: []*regexp.Regexp{
			// UNION-based injection
			regexp.MustCompile(`(?i)(union\s+select|union\s+all\s+select)`),

			// Basic SQL keywords in suspicious contexts
			regexp.MustCompile(`(?i)(select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)`),

			// Stored procedure execution
			regexp.MustCompile(`(?i)(exec\s+sp_|execute\s+sp_|xp_cmdshell)`),

			// SQL comments (often used to bypass filters)
			regexp.MustCompile(`(--|#|\/\*|\*\/)`),

			// Quote-based injection patterns
			regexp.MustCompile(`('|")(.*)(or|and)(\s+)('|")?('|")`),

			// Always-true conditions
			regexp.MustCompile(`(?i)(1=1|'='|"\s*=\s*")`),

			// Common SQL injection test strings
			regexp.MustCompile(`(?i)(admin'--|' or 1=1--|' or 'a'='a)`),
		},
	}
}

// AnalyzePattern examines request history for SQL injection patterns
func (d *SQLInjectionDetector) AnalyzePattern(ctx extensions.AnalysisContext) (extensions.AnalysisResult, error) {
	// Track highest confidence and first suspicious URI
	var highestConfidence float64
	var suspiciousURI string
	var matchedPattern string

	// Check each request for SQL injection patterns
	for _, log := range ctx.RequestLogs {
		// URL-decode the URI for better pattern matching
		decodedURI, err := url.QueryUnescape(log.URI)
		if err != nil {
			// If decode fails, use original URI
			decodedURI = log.URI
		}

		// Check against all patterns
		for i, pattern := range d.patterns {
			if pattern.MatchString(decodedURI) {
				// Calculate confidence based on pattern specificity
				// More specific patterns (union, exec) get higher confidence
				confidence := d.calculateConfidence(i, decodedURI)

				if confidence > highestConfidence {
					highestConfidence = confidence
					suspiciousURI = log.URI
					matchedPattern = d.patternDescription(i)
				}

				// If we find a high-confidence match, we can stop early
				if confidence >= 0.95 {
					break
				}
			}
		}

		// Early exit if we found a very suspicious pattern
		if highestConfidence >= 0.95 {
			break
		}
	}

	// Block if confidence threshold exceeded
	if highestConfidence >= 0.75 {
		return extensions.AnalysisResult{
			IsSuspicious:  true,
			Reason:        fmt.Sprintf("SQL injection pattern detected: %s", matchedPattern),
			SuspiciousURI: suspiciousURI,
			Confidence:    highestConfidence,
		}, nil
	}

	return extensions.AnalysisResult{
		IsSuspicious: false,
		Confidence:   highestConfidence,
	}, nil
}

// calculateConfidence returns a confidence score based on pattern type and context
func (d *SQLInjectionDetector) calculateConfidence(patternIndex int, uri string) float64 {
	// Pattern-specific base confidence scores
	baseConfidence := map[int]float64{
		0: 0.95, // UNION-based injection (very specific)
		1: 0.85, // Basic SQL keywords (medium-high)
		2: 0.95, // Stored procedures (very specific)
		3: 0.70, // SQL comments (can be legitimate in some contexts)
		4: 0.90, // Quote-based injection (high)
		5: 0.85, // Always-true conditions (high)
		6: 0.98, // Known test strings (very high)
	}

	confidence := baseConfidence[patternIndex]
	if confidence == 0 {
		confidence = 0.75 // Default for unknown patterns
	}

	// Boost confidence if multiple suspicious indicators present
	lowerURI := strings.ToLower(uri)
	suspiciousIndicators := 0

	if strings.Contains(lowerURI, "union") {
		suspiciousIndicators++
	}
	if strings.Contains(lowerURI, "select") {
		suspiciousIndicators++
	}
	if strings.Contains(lowerURI, "or 1=1") {
		suspiciousIndicators++
	}
	if strings.Contains(lowerURI, "--") {
		suspiciousIndicators++
	}

	// Increase confidence if multiple indicators present
	if suspiciousIndicators >= 2 {
		confidence = confidence + (0.05 * float64(suspiciousIndicators-1))
		if confidence > 0.99 {
			confidence = 0.99
		}
	}

	return confidence
}

// patternDescription returns human-readable description of matched pattern
func (d *SQLInjectionDetector) patternDescription(patternIndex int) string {
	descriptions := []string{
		"UNION-based injection",
		"SQL keywords in suspicious context",
		"Stored procedure execution attempt",
		"SQL comment characters",
		"Quote-based injection",
		"Always-true condition",
		"Known SQL injection test string",
	}

	if patternIndex >= 0 && patternIndex < len(descriptions) {
		return descriptions[patternIndex]
	}
	return "SQL injection pattern"
}

func (d *SQLInjectionDetector) Name() string {
	return d.name
}

func (d *SQLInjectionDetector) Priority() int {
	return d.priority
}
