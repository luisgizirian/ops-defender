package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/ops/defender/internal/defender"
	"github.com/ops/defender/pkg/config"
)

type ReportScheduler struct {
	defender           *defender.Defender
	emailEnabled       bool
	emailTo            string
	emailFrom          string
	smtpHost           string
	smtpPort           string
	smtpUser           string
	smtpPassword       string
	maxReportAgeDays   int
	azureEnabled       bool
	azureConnectionStr string
	azureContainer     string
	azureBlobClient    *azblob.Client
}

func NewReportScheduler(defender *defender.Defender, config *config.Config) *ReportScheduler {
	// Parse max report age (default: 30 days)
	maxReportAgeDays := config.MaxReportAgeDays

	// Azure Blob Storage configuration
	azureEnabled := config.AzureStorageEnabled
	azureConnectionStr := config.AzureConnString
	azureContainer := config.AzureContainer

	var azureBlobClient *azblob.Client
	if azureEnabled && azureConnectionStr != "" {
		client, err := azblob.NewClientFromConnectionString(azureConnectionStr, nil)
		if err != nil {
			log.Printf("Failed to initialize Azure Blob Storage client: %v, Azure upload disabled", err)
			azureEnabled = false
		} else {
			azureBlobClient = client
			log.Printf("Azure Blob Storage enabled: container=%s", azureContainer)
		}
	} else if azureEnabled {
		log.Printf("Azure Blob Storage enabled but AZURE_STORAGE_CONNECTION_STRING not set, disabling")
		azureEnabled = false
	}

	rs := &ReportScheduler{
		defender:           defender,
		emailEnabled:       config.EmailEnabled,
		emailTo:            config.EmailTo,
		emailFrom:          config.EmailFrom,
		smtpHost:           config.SMTPHost,
		smtpPort:           config.SMTPPort,
		smtpUser:           config.SMTPUser,
		smtpPassword:       config.SMTPPassword,
		maxReportAgeDays:   maxReportAgeDays,
		azureEnabled:       azureEnabled,
		azureConnectionStr: azureConnectionStr,
		azureContainer:     azureContainer,
		azureBlobClient:    azureBlobClient,
	}

	log.Printf("Report retention: %d days for local reports", maxReportAgeDays)

	return rs
}

func (rs *ReportScheduler) Start() {
	// Daily report at 9 AM
	go rs.scheduleDaily()
	
	// Weekly report on Monday at 9 AM
	go rs.scheduleWeekly()
	
	// Cleanup old reports daily at 3 AM
	go rs.scheduleCleanup()
}

func (rs *ReportScheduler) scheduleDaily() {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, now.Location())
		if now.After(next) {
			next = next.Add(24 * time.Hour)
		}
		
		duration := next.Sub(now)
		log.Printf("Next daily report scheduled in: %v", duration)
		
		time.Sleep(duration)
		rs.generateAndSendReport(24, "Daily")
	}
}

func (rs *ReportScheduler) scheduleWeekly() {
	for {
		now := time.Now()
		daysUntilMonday := (8 - int(now.Weekday())) % 7
		if daysUntilMonday == 0 && now.Hour() >= 9 {
			daysUntilMonday = 7
		}
		
		next := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, now.Location())
		next = next.Add(time.Duration(daysUntilMonday) * 24 * time.Hour)
		
		duration := next.Sub(now)
		log.Printf("Next weekly report scheduled in: %v", duration)
		
		time.Sleep(duration)
		rs.generateAndSendReport(168, "Weekly")
	}
}

func (rs *ReportScheduler) scheduleCleanup() {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
		if now.After(next) {
			next = next.Add(24 * time.Hour)
		}
		
		duration := next.Sub(now)
		log.Printf("Next report cleanup scheduled in: %v", duration)
		
		time.Sleep(duration)
		rs.cleanupOldReports()
	}
}

func (rs *ReportScheduler) generateAndSendReport(periodHours int, reportType string) {
	report := rs.defender.GenerateReport(periodHours)
	
	// Log to file
	filename := fmt.Sprintf("reports/defender_%s_%s.json", 
		reportType, 
		time.Now().Format("2006-01-02"))
	
	if err := os.MkdirAll("reports", 0755); err != nil {
		log.Printf("Failed to create reports directory: %v", err)
		return
	}
	
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal report: %v", err)
		return
	}
	
	if err := os.WriteFile(filename, reportJSON, 0644); err != nil {
		log.Printf("Failed to write report: %v", err)
	} else {
		log.Printf("%s report saved to: %s", reportType, filename)
	}
	
	// Upload to Azure Blob Storage if enabled
	if rs.azureEnabled {
		if err := rs.uploadToAzureWithRetry(filename, reportJSON, 3); err != nil {
			log.Printf("ERROR: Failed to upload report to Azure Blob Storage after retries: %v", err)
			log.Printf("Report saved locally at: %s (Azure upload failed, may need manual upload)", filename)
		} else {
			log.Printf("%s report uploaded to Azure Blob Storage: %s/%s", reportType, rs.azureContainer, filepath.Base(filename))
		}
	}
	
	// Generate summary
	summary := rs.formatReportSummary(report, reportType)
	log.Printf("\n%s", summary)
	
	// Send email if enabled
	if rs.emailEnabled && rs.emailTo != "" {
		if err := rs.sendEmail(reportType, summary, report); err != nil {
			log.Printf("Failed to send email report: %v", err)
		} else {
			log.Printf("%s report emailed to: %s", reportType, rs.emailTo)
		}
	}
}

func (rs *ReportScheduler) formatReportSummary(report defender.Report, reportType string) string {
	var buf bytes.Buffer
	
	tmpl := `
╔════════════════════════════════════════════════════════════════╗
║         Ops DEFENDER - {{.ReportType}} REPORT                
╚════════════════════════════════════════════════════════════════╝

Generated: {{.Report.GeneratedAt}}
Period: {{.Report.Period}}

📊 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total Requests:       {{.Report.TotalRequests}}
  Blocked Requests:     {{.Report.BlockedRequests}}
  Unique IPs:           {{.Report.UniqueIPs}}
  Blocked IPs:          {{.Report.BlockedIPs}}
  Block Rate:           {{.BlockRate}}%

🚫 BLOCK EVENTS ({{.EventCount}})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{range .Report.BlockEvents}}  • {{.BlockedAt}} - {{.IP}}
    Reason: {{.Reason}}
    URI: {{.SuspiciousURI}}
{{end}}
⚠️  TOP SUSPICIOUS IPs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{range .Report.TopSuspiciousIPs}}  • {{.IP}} - {{.Requests}} requests (Blocked: {{.BlockedAt}})
{{end}}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`
	
	blockRate := 0.0
	if report.TotalRequests > 0 {
		blockRate = float64(report.BlockedRequests) / float64(report.TotalRequests) * 100
	}
	
	data := map[string]interface{}{
		"ReportType": reportType,
		"Report":     report,
		"EventCount": len(report.BlockEvents),
		"BlockRate":  fmt.Sprintf("%.2f", blockRate),
	}
	
	t := template.Must(template.New("report").Parse(tmpl))
	t.Execute(&buf, data)
	
	return buf.String()
}

func (rs *ReportScheduler) sendEmail(reportType string, summary string, report defender.Report) error {
	if rs.smtpHost == "" || rs.emailTo == "" {
		return fmt.Errorf("email not configured")
	}
	
	subject := fmt.Sprintf("Ops Defender %s Report - %s", reportType, time.Now().Format("2006-01-02"))
	
	body := fmt.Sprintf("Subject: %s\r\n", subject)
	body += fmt.Sprintf("From: %s\r\n", rs.emailFrom)
	body += fmt.Sprintf("To: %s\r\n", rs.emailTo)
	body += "MIME-version: 1.0;\r\n"
	body += "Content-Type: text/plain; charset=\"UTF-8\";\r\n\r\n"
	body += summary
	
	auth := smtp.PlainAuth("", rs.smtpUser, rs.smtpPassword, rs.smtpHost)
	addr := fmt.Sprintf("%s:%s", rs.smtpHost, rs.smtpPort)
	
	return smtp.SendMail(addr, auth, rs.emailFrom, []string{rs.emailTo}, []byte(body))
}

// cleanupOldReports removes local report files older than maxReportAgeDays
func (rs *ReportScheduler) cleanupOldReports() {
	if rs.maxReportAgeDays <= 0 {
		log.Printf("Report cleanup disabled (maxReportAgeDays <= 0)")
		return
	}

	reportsDir := "reports"
	if _, err := os.Stat(reportsDir); os.IsNotExist(err) {
		// Reports directory doesn't exist yet, nothing to clean
		return
	}

	cutoffTime := time.Now().Add(-time.Duration(rs.maxReportAgeDays) * 24 * time.Hour)
	deletedCount := 0
	var deletedSize int64

	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		log.Printf("Failed to read reports directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := filepath.Join(reportsDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			log.Printf("Failed to get file info for %s: %v", filename, err)
			continue
		}

		// Delete files older than cutoff time
		if info.ModTime().Before(cutoffTime) {
			size := info.Size()
			if err := os.Remove(filename); err != nil {
				log.Printf("Failed to delete old report %s: %v", filename, err)
			} else {
				deletedCount++
				deletedSize += size
				log.Printf("Deleted old report: %s (age: %.1f days)", filename, time.Since(info.ModTime()).Hours()/24)
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("Cleanup completed: deleted %d reports, freed %.2f MB (retention: %d days)", 
			deletedCount, float64(deletedSize)/(1024*1024), rs.maxReportAgeDays)
	} else {
		log.Printf("Cleanup completed: no reports older than %d days found", rs.maxReportAgeDays)
	}
}

// uploadToAzureWithRetry uploads a report to Azure Blob Storage with retry logic
func (rs *ReportScheduler) uploadToAzureWithRetry(filename string, data []byte, maxRetries int) error {
	var lastErr error
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := rs.uploadToAzure(filename, data)
		if err == nil {
			if attempt > 1 {
				log.Printf("Azure upload succeeded on attempt %d/%d", attempt, maxRetries)
			}
			return nil
		}
		
		lastErr = err
		
		if attempt < maxRetries {
			// Exponential backoff: 2s, 4s, 8s, etc.
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			log.Printf("Azure upload attempt %d/%d failed: %v (retrying in %v)", attempt, maxRetries, err, backoff)
			time.Sleep(backoff)
		}
	}
	
	return fmt.Errorf("all %d upload attempts failed, last error: %w", maxRetries, lastErr)
}

// uploadToAzure uploads a report to Azure Blob Storage
func (rs *ReportScheduler) uploadToAzure(filename string, data []byte) error {
	if rs.azureBlobClient == nil {
		return fmt.Errorf("Azure Blob Storage client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use the base filename as the blob name
	blobName := filepath.Base(filename)

	// Upload the blob
	_, err := rs.azureBlobClient.UploadBuffer(
		ctx,
		rs.azureContainer,
		blobName,
		data,
		nil,
	)

	if err != nil {
		// Provide more context about the failure
		return fmt.Errorf("failed to upload blob '%s' to container '%s': %w", blobName, rs.azureContainer, err)
	}

	return nil
}
