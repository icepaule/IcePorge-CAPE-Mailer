#!/bin/bash
# =============================================================================
# Log Cleanup Script for cape-mailer
# Compresses logs older than 1 day, deletes logs older than 180 days
# Created: 2026-01-18
# =============================================================================

LOG_DIR="/opt/cape-mailer/logs"
RETENTION_DAYS=180

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting log cleanup..."

# Compress uncompressed log files older than 1 day
find "$LOG_DIR" -name "cape_mailer_*.log" -type f -mtime +1 ! -name "*.gz" -exec gzip -9 {} \; 2>/dev/null
COMPRESSED=$(find "$LOG_DIR" -name "cape_mailer_*.log.gz" -type f -mtime -1 | wc -l)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Compressed $COMPRESSED log file(s)"

# Delete logs older than retention period
DELETED=$(find "$LOG_DIR" -name "cape_mailer_*.log.gz" -type f -mtime +$RETENTION_DAYS -delete -print | wc -l)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Deleted $DELETED old log file(s) (>$RETENTION_DAYS days)"

# Also compress/cleanup Splunk JSON logs
find "$LOG_DIR/splunk" -name "*.json" -type f -mtime +1 ! -name "*.gz" -exec gzip -9 {} \; 2>/dev/null
find "$LOG_DIR/splunk" -name "*.json.gz" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null

# Cleanup CAPEv2 dated log files
CAPE_LOG_DIR="/opt/CAPEv2/log"
find "$CAPE_LOG_DIR" -name "cuckoo.log.*" -type f -mtime +1 ! -name "*.gz" -exec gzip -9 {} \; 2>/dev/null
find "$CAPE_LOG_DIR" -name "process.log.*" -type f -mtime +1 ! -name "*.gz" -exec gzip -9 {} \; 2>/dev/null
find "$CAPE_LOG_DIR" -name "*.log.*" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null

# Cleanup old process-*.log files (task-specific logs)
find "$CAPE_LOG_DIR" -name "process-*.log" -type f -mtime +30 -delete 2>/dev/null

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Log cleanup completed"
