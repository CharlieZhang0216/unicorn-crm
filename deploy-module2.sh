#!/bin/bash
# Module 2 Deployment Script for Unicorn CRM
# Deploys: Email system, OAuth, JWT API tokens, Rich text notes
#
# Usage: Copy this script to /tmp on server and run as root:
#   scp deploy-module2.sh root@101.133.149.12:/tmp/
#   ssh root@101.133.149.12 "bash /tmp/deploy-module2.sh"
#
# Or run directly on the server:
#   cd /opt/security-training-lab && bash /tmp/deploy-module2.sh

set -e

APP_DIR="/opt/security-training-lab"
BACKUP_DIR="/opt/security-training-lab-backup-module2-$(date +%Y%m%d_%H%M%S)"

echo "============================================"
echo " Unicorn CRM — Module 2 Deployment"
echo "============================================"
echo ""

# Step 0: Check prerequisites
echo "[1/7] Checking prerequisites..."
if [ ! -d "$APP_DIR" ]; then
  echo "ERROR: Application directory $APP_DIR not found!"
  exit 1
fi

cd "$APP_DIR"
echo "  ✓ Working directory: $APP_DIR"

# Step 1: Backup
echo "[2/7] Creating backup..."
cp -r "$APP_DIR" "$BACKUP_DIR" 2>/dev/null || true
echo "  ✓ Backup at: $BACKUP_DIR"

# Step 2: Install new npm dependencies
echo "[3/7] Installing new npm dependencies..."
npm install nodemailer jsonwebtoken isomorphic-dompurify jsdom 2>&1 | tail -3
echo "  ✓ Dependencies installed"

# Step 3: Create directory structure
echo "[4/7] Creating directory structure..."
mkdir -p services
mkdir -p views/notes
mkdir -p views/api-tokens
echo "  ✓ Directories created"

# Step 4: Deploy all new/modified files
echo "[5/7] Deploying files..."

# --- Services ---
cat > services/mail.js << 'MAILJS_EOF'
$(cat services/mail.js)
MAILJS_EOF

# --- Config ---
cat > config/database.js << 'DBJS_EOF'
$(cat config/database.js)
DBJS_EOF

# --- Routes ---
# auth.js is updated with email verification and password reset
cat > routes/auth.js << 'AUTHJS_EOF'
$(cat routes/auth.js)
AUTHJS_EOF

# New routes
cat > routes/oauth.js << 'OAUTHJS_EOF'
$(cat routes/oauth.js)
OAUTHJS_EOF

cat > routes/api-tokens.js << 'APITOKENS_EOF'
$(cat routes/api-tokens.js)
APITOKENS_EOF

cat > routes/notes.js << 'NOTESJS_EOF'
$(cat routes/notes.js)
NOTESJS_EOF

# --- Middleware ---
cat > middleware/api-auth.js << 'APIAUTH_EOF'
$(cat middleware/api-auth.js)
APIAUTH_EOF

# --- App ---
cat > app.js << 'APPJS_EOF'
$(cat app.js)
APPJS_EOF

# --- Views ---
cat > views/oauth-mock.ejs << 'OAUTHMOCK_EOF'
$(cat views/oauth-mock.ejs)
OAUTHMOCK_EOF

cat > views/verify-email.ejs << 'VERIFY_EOF'
$(cat views/verify-email.ejs)
VERIFY_EOF

cat > views/reset-password.ejs << 'RESET_EOF'
$(cat views/reset-password.ejs)
RESET_EOF

cat > views/login.ejs << 'LOGIN_EOF'
$(cat views/login.ejs)
LOGIN_EOF

cat > views/register.ejs << 'REGISTER_EOF'
$(cat views/register.ejs)
REGISTER_EOF

cat > views/forgot-password.ejs << 'FORGOT_EOF'
$(cat views/forgot-password.ejs)
FORGOT_EOF

cat > views/partials/nav.ejs << 'NAV_EOF'
$(cat views/partials/nav.ejs)
NAV_EOF

cat > views/notes/index.ejs << 'NOTESINDEX_EOF'
$(cat views/notes/index.ejs)
NOTESINDEX_EOF

cat > views/notes/edit.ejs << 'NOTESEDIT_EOF'
$(cat views/notes/edit.ejs)
NOTESEDIT_EOF

cat > views/notes/view.ejs << 'NOTESVIEW_EOF'
$(cat views/notes/view.ejs)
NOTESVIEW_EOF

cat > views/api-tokens/index.ejs << 'TOKENINDEX_EOF'
$(cat views/api-tokens/index.ejs)
TOKENINDEX_EOF

echo "  ✓ All files deployed"

# Step 6: Stop existing app
echo "[6/7] Stopping existing application..."
pkill -f "node.*app.js" 2>/dev/null || true
sleep 2
echo "  ✓ App stopped"

# Step 7: Start application
echo "[7/7] Starting application..."
NODE_ENV=production node app.js > /tmp/unicorn-crm.log 2>&1 &
sleep 3

# Verify
if pgrep -f "node.*app.js" > /dev/null; then
  echo ""
  echo "============================================"
  echo " ✓ Module 2 Deployment Complete!"
  echo "============================================"
  echo ""
  echo " New features:"
  echo "  - Email verification (check console for emails)"
  echo "  - Password reset with token links"
  echo "  - OAuth 2.0 (Google/mock provider)"
  echo "  - JWT API Token management"
  echo "  - Rich text notes with Quill editor"
  echo ""
  echo " View logs: tail -f /tmp/unicorn-crm.log"
  echo " Backup at: $BACKUP_DIR"
  echo ""
  cat /tmp/unicorn-crm.log | tail -5
else
  echo "ERROR: Application failed to start!"
  echo "Check logs: cat /tmp/unicorn-crm.log"
  cat /tmp/unicorn-crm.log | tail -20
  exit 1
fi
