#!/bin/bash
set -e
echo "=== Unicorn CRM Full Deploy ==="

# 1. Stop app
echo "[1/6] Stopping app..."
pkill -f "node app.js" 2>/dev/null || true
sleep 2

# 2. Remove old DB (will be recreated with new seed)
echo "[2/6] Resetting database..."
rm -f /opt/security-training-lab/data/crm.db
echo "  Database removed"

# 3. Verify all files exist
echo "[3/6] Verifying files..."
REQUIRED="routes/auth.js routes/admin.js routes/api.js routes/customers.js routes/orders.js routes/tickets.js routes/index.js routes/reports.js routes/profile.js routes/errors.js routes/debug.js routes/files.js config/database.js config/seed.js app.js views/index.ejs views/customers.ejs views/customer-detail.ejs views/orders.ejs views/order-detail.ejs views/tickets.ejs views/ticket-detail.ejs views/reports.ejs views/search.ejs views/login.ejs views/register.ejs views/forgot-password.ejs views/profile.ejs"
for f in $REQUIRED; do
  if [ ! -f "/opt/security-training-lab/$f" ]; then
    echo "  MISSING: $f"
    exit 1
  fi
done
echo "  All files present"

# 4. Start app
echo "[4/6] Starting app..."
su -s /bin/bash -c "cd /opt/security-training-lab && PORT=3001 nohup /usr/local/bin/node app.js > /var/log/lab.log 2>&1 &" unicorn
sleep 4

# 5. Verify
echo "[5/6] Checking app health..."
PID=$(pgrep -f "node app.js" | head -1)
if [ -z "$PID" ]; then
  echo "  FAIL: App not running!"
  tail -20 /var/log/lab.log
  exit 1
fi
echo "  App running (PID $PID)"

# 6. Quick test
echo "[6/6] Quick test..."
sleep 1
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost/)
USER_COUNT=$(sqlite3 /opt/security-training-lab/data/crm.db "SELECT COUNT(*) FROM users;")
ORDER_COUNT=$(sqlite3 /opt/security-training-lab/data/crm.db "SELECT COUNT(*) FROM orders;")
TICKET_COUNT=$(sqlite3 /opt/security-training-lab/data/crm.db "SELECT COUNT(*) FROM tickets;")
SESS_COUNT=$(sqlite3 /opt/security-training-lab/data/crm.db "SELECT COUNT(*) FROM sessions;")
MANAGER_COUNT=$(sqlite3 /opt/security-training-lab/data/crm.db "SELECT COUNT(*) FROM users WHERE role='manager';")

echo "  HTTP: $HTTP_CODE"
echo "  Users: $USER_COUNT (managers: $MANAGER_COUNT)"
echo "  Orders: $ORDER_COUNT"
echo "  Tickets: $TICKET_COUNT"
echo "  Sessions: $SESS_COUNT (should be 0)"

echo ""
echo "=== Deploy Complete ==="
