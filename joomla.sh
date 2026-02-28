#!/bin/bash
# =============================================================================
# Joomla Install Script for LXC Container (HTTP only, behind reverse proxy)
# Debian (latest) / Ubuntu 22.04+
# Safe to re-run — generic, no hardcoded client names
# WAFControl runs in a SEPARATE container
#
# Covers:
#   1.  Variables & helpers
#   2.  Package installation
#   3.  User prompts (proxy IP, template name)
#   4.  Re-run detection
#   5.  Database setup
#   6.  Joomla download & install
#   7.  Apache configuration
#   8.  PHP hardening + Joomla-required settings
#   9.  Joomla filesystem permissions (FULL — includes media/templates/site/)
#   10. Firewall (UFW) & Fail2Ban
#   11. Logwatch (HTML)
#   12. Joomla integrity check cron
#   13. AIDE file integrity
#   14. Joomla core auto-update cron
#   15. Unattended OS upgrades
# =============================================================================

set -euo pipefail

###########################
# 1. Variables
###########################

INSTALL_DIR="/var/www/html/joomla"
DB_NAME="joomla"
DB_USER="joomlauser"
DB_PASS=""
PROXY_IP=""
TEMPLATE_NAME=""           # Set by prompt — e.g. "mytemplate" (lowercase, no spaces)
APACHE_CONF="/etc/apache2/sites-available/joomla.conf"
LOGWATCH_DIR="/var/www/html/logwatch"
PHP_TMP_DIR="/var/lib/php/tmp"

###########################
# 2. Helper Functions
###########################

error_exit() {
    echo "[-] ERROR: $1"
    exit 1
}

apply_php_setting() {
    local key="$1"
    local val="$2"
    local file="$3"
    if grep -qE "^;?[[:space:]]*${key}[[:space:]]*=" "$file"; then
        sed -i "s|^;*[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$file"
    else
        echo "${key} = ${val}" >> "$file"
    fi
    echo "    [php] ${key} = ${val}"
}

generate_db_password() {
    DB_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
    echo "[+] Database password generated."
}

###########################
# 3. User Prompts
#    All prompts collected upfront before any changes are made
###########################

collect_prompts() {
    echo ""

    # Reverse proxy IP
    read -p "Enter REVERSE PROXY IP: " PROXY_IP
    [[ "$PROXY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
        error_exit "Invalid IP address: $PROXY_IP"

    # Template name
    echo ""
    echo "Enter your Joomla template name."
    echo "  - Must match the folder name inside your template ZIP exactly"
    echo "  - Lowercase letters, numbers, and underscores only (no spaces)"
    echo "  - Example: mycompany  or  acme_theme"
    echo "  - Leave blank to skip pre-creating the template media directory"
    echo "    (you can always run this manually later)"
    read -p "Template name [leave blank to skip]: " TEMPLATE_NAME

    # Strip any accidental spaces and force lowercase
    TEMPLATE_NAME=$(echo "$TEMPLATE_NAME" | tr '[:upper:]' '[:lower:]' | tr -d ' ')

    if [ -n "$TEMPLATE_NAME" ]; then
        echo "[+] Template name set to: ${TEMPLATE_NAME}"
    else
        echo "[!] No template name entered — skipping template media directory creation."
    fi
}

###########################
# 4. Re-run Detection
###########################

REINSTALL=false

check_existing_install() {
    local db_exists=false
    local files_exist=false

    if mysql -uroot -e "SHOW DATABASES LIKE '${DB_NAME}';" 2>/dev/null | grep -q "${DB_NAME}"; then
        db_exists=true
    fi

    if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/index.php" ]; then
        files_exist=true
    fi

    if $db_exists || $files_exist; then
        echo ""
        echo "[!] Existing installation detected:"
        $db_exists   && echo "    - Database '${DB_NAME}' exists"
        $files_exist && echo "    - Joomla files exist at ${INSTALL_DIR}"
        echo ""
        echo "  1) Delete everything and reinstall fresh"
        echo "     (drops DB, drops user, deletes files, generates new password)"
        echo "  2) Skip — leave existing install untouched and exit"
        echo ""
        read -p "Choose [1-2]: " choice
        case "$choice" in
            1) REINSTALL=true ;;
            2) echo "[+] Existing install left untouched. Exiting."; exit 0 ;;
            *) error_exit "Invalid choice" ;;
        esac
    fi
}

###########################
# 5. Package Installation
###########################

install_packages() {
    echo "[+] Installing system packages..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 mariadb-server mariadb-client \
        php php-cli php-common php-mysql php-xml php-curl php-gd \
        php-mbstring php-intl php-zip php-json php-fileinfo \
        unzip curl jq ufw fail2ban unattended-upgrades logwatch aide apache2-utils
}

###########################
# 6. Database Setup
###########################

setup_database() {
    echo "[+] Configuring database..."

    if $REINSTALL; then
        echo "[+] Dropping existing database and user..."
        mysql -uroot <<EOF
DROP DATABASE IF EXISTS ${DB_NAME};
DROP USER IF EXISTS '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
    fi

    mysql -uroot <<EOF
CREATE DATABASE ${DB_NAME}
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '${DB_USER}'@'localhost'
  IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF

    mysql -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "SELECT 1;" >/dev/null 2>&1 \
        || error_exit "DB credential verification failed. Aborting."

    echo "[+] Database configured and credentials verified."
}

###########################
# 7. Joomla Download & Install
###########################

install_joomla() {
    echo "[+] Detecting latest Joomla release from GitHub..."

    release_json=$(curl -fsSL https://api.github.com/repos/joomla/joomla-cms/releases/latest)
    latest_tag=$(echo "$release_json" | jq -r '.tag_name')

    download_url=$(echo "$release_json" | jq -r '
        .assets[]
        | select(.name | test("^Joomla_[0-9]+\\.[0-9]+\\.[0-9]+-Stable-Full_Package\\.zip$"))
        | .browser_download_url' | head -n1)

    [ -n "$download_url" ] || error_exit "Failed to detect Joomla download URL"

    if $REINSTALL && [ -d "$INSTALL_DIR" ]; then
        echo "[+] Removing existing Joomla files..."
        rm -rf "$INSTALL_DIR"
    fi

    DL_TMP=$(mktemp -d)
    cd "$DL_TMP"
    echo "[+] Downloading Joomla $latest_tag ..."
    curl -fL -o joomla.zip "$download_url"
    mkdir -p "$INSTALL_DIR"
    unzip -oq joomla.zip -d "$INSTALL_DIR"
    cd /
    rm -rf "$DL_TMP"

    echo "[+] Joomla $latest_tag extracted to $INSTALL_DIR"
}

###########################
# 8. Apache Configuration
###########################

configure_apache() {
    echo "[+] Configuring Apache for reverse proxy..."

    a2dissite 000-default.conf >/dev/null 2>&1 || true
    # rewrite  — Joomla SEF URLs
    # remoteip — real client IPs from X-Forwarded-For (makes Fail2Ban work correctly)
    # headers  — security response headers
    a2enmod rewrite remoteip headers

    # ServerTokens/ServerSignature are global directives — must NOT be inside
    # a <VirtualHost> block or Apache throws a syntax error.
    cat <<EOF > /etc/apache2/conf-available/security-hardening.conf
ServerTokens Prod
ServerSignature Off
EOF
    a2enconf security-hardening

    cat <<EOF > "$APACHE_CONF"
<VirtualHost *:80>
    DocumentRoot ${INSTALL_DIR}

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    <Directory ${INSTALL_DIR}>
        AllowOverride All
        Require all granted
        <FilesMatch "\.(bak|config|dist|fla|inc|ini|log|psd|sh|sql|swp)$">
            Require all denied
        </FilesMatch>
    </Directory>

    Alias /logwatch ${LOGWATCH_DIR}

    <Directory ${LOGWATCH_DIR}>
        Options -Indexes
        AllowOverride None
        Require ip 127.0.0.1 ${PROXY_IP}
    </Directory>

    # Trust X-Forwarded-For from the reverse proxy so Apache logs real client IPs.
    # This also makes Fail2Ban ban real attacker IPs, not the proxy IP.
    RemoteIPHeader X-Forwarded-For
    RemoteIPTrustedProxy 127.0.0.1
    RemoteIPTrustedProxy ${PROXY_IP}

    ErrorLog \${APACHE_LOG_DIR}/joomla_error.log
    CustomLog \${APACHE_LOG_DIR}/joomla_access.log combined
</VirtualHost>
EOF

    a2ensite joomla.conf
    apache2ctl configtest || error_exit "Apache config test failed — check syntax above"
    systemctl reload apache2
}

###########################
# 9. PHP Configuration
###########################

configure_php() {
    echo "[+] Configuring PHP (hardening + Joomla requirements)..."

    PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    PHP_INI_APACHE="/etc/php/${PHP_VER}/apache2/php.ini"
    PHP_INI_CLI="/etc/php/${PHP_VER}/cli/php.ini"

    [ -f "$PHP_INI_APACHE" ] || error_exit "php.ini not found at $PHP_INI_APACHE"

    # Dedicated PHP upload tmp dir — fixes "PHP temporary folder not set" warning
    echo "[+] Creating PHP tmp directory: $PHP_TMP_DIR"
    mkdir -p "$PHP_TMP_DIR"
    chown www-data:www-data "$PHP_TMP_DIR"
    chmod 700 "$PHP_TMP_DIR"

    echo "[+] Applying PHP settings to $PHP_INI_APACHE ..."

    # Security hardening
    apply_php_setting "expose_php"           "Off"           "$PHP_INI_APACHE"
    apply_php_setting "display_errors"       "Off"           "$PHP_INI_APACHE"
    apply_php_setting "output_buffering"     "Off"           "$PHP_INI_APACHE"
    apply_php_setting "allow_url_fopen"      "Off"           "$PHP_INI_APACHE"
    apply_php_setting "allow_url_include"    "Off"           "$PHP_INI_APACHE"

    # Joomla functional requirements
    apply_php_setting "upload_tmp_dir"       "$PHP_TMP_DIR"  "$PHP_INI_APACHE"
    apply_php_setting "upload_max_filesize"  "64M"           "$PHP_INI_APACHE"
    apply_php_setting "post_max_size"        "64M"           "$PHP_INI_APACHE"
    apply_php_setting "memory_limit"         "128M"          "$PHP_INI_APACHE"
    apply_php_setting "max_execution_time"   "120"           "$PHP_INI_APACHE"
    apply_php_setting "max_input_vars"       "3000"          "$PHP_INI_APACHE"

    # Apply matching settings to CLI php.ini — cron jobs (core:update etc.) use CLI PHP
    if [ -f "$PHP_INI_CLI" ]; then
        echo "[+] Applying settings to CLI php.ini: $PHP_INI_CLI"
        apply_php_setting "upload_tmp_dir"      "$PHP_TMP_DIR"  "$PHP_INI_CLI"
        apply_php_setting "upload_max_filesize" "64M"           "$PHP_INI_CLI"
        apply_php_setting "post_max_size"       "64M"           "$PHP_INI_CLI"
        apply_php_setting "memory_limit"        "128M"          "$PHP_INI_CLI"
        apply_php_setting "max_execution_time"  "120"           "$PHP_INI_CLI"
        apply_php_setting "max_input_vars"      "3000"          "$PHP_INI_CLI"
    fi

    systemctl reload apache2
}

###########################
# 10. Joomla Filesystem Permissions
#
# WHY TWO LOCATIONS?
# Joomla 4.1+ splits templates into two locations:
#   /templates/<name>/               — PHP files (index.php, error.php, etc.)
#   /media/templates/site/<name>/    — CSS, JS, images (writable media dir)
#
# The "template folder is not writable" warning fires when
# /media/templates/site/<name>/ does not exist or is not writable by www-data.
# This function creates AND correctly permissions both locations.
#
# PERMISSION RATIONALE:
#   755 — base for all dirs (owner rwx, group r-x, other r-x)
#   775 — dirs Joomla must write to (owner rwx, group rwx, other r-x)
#         www-data owns AND is in the group — group write = Joomla can write
#   644 — all files (owner rw-, group r--, other r--) — never executable
#   444 — configuration.php at rest (Joomla temporarily unlocks to 644 when
#          saving Global Configuration, then re-locks automatically)
#   700 — PHP upload tmp dir (only www-data should access it)
###########################

configure_permissions() {
    echo "[+] Setting Joomla filesystem permissions..."

    [ -d "$INSTALL_DIR" ] || error_exit "Joomla directory not found at $INSTALL_DIR"

    # ── Step 1: Base ownership — everything to www-data ──────────────────────
    chown -R www-data:www-data "$INSTALL_DIR"

    # ── Step 2: Secure defaults across the entire install ────────────────────
    find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
    find "$INSTALL_DIR" -type f -exec chmod 644 {} \;

    # ── Step 3: Directories Joomla must write into (775) ─────────────────────
    # Required for: installer, updater, media manager, plugin system,
    # cache engine, and the Joomla admin template file editor.
    # NOTE: Joomla 4+ removed the root /logs dir — it is now administrator/logs
    WRITABLE_DIRS=(
        "cache"
        "administrator/cache"
        "administrator/logs"
        "tmp"
        "images"
        "media"
        "templates"
        "modules"
        "plugins"
        "components"
        "libraries"
        "administrator/templates"
        "administrator/manifests"
    )

    for dir in "${WRITABLE_DIRS[@]}"; do
        full="${INSTALL_DIR}/${dir}"
        if [ -d "$full" ]; then
            chown -R www-data:www-data "$full"
            chmod 775 "$full"
            echo "    [775 writable] $full"
        fi
    done

    # ── Step 4: Create Joomla 4.1+ template media directory structure ─────────
    # Joomla 4.1+ moved all template media (css/js/images) out of /templates/
    # and into /media/templates/site/<templatename>/.
    # Joomla's template editor checks THIS location for writability.
    # Without it: "The template folder is not writable. Some features may not work."
    #
    # When the template ZIP is installed via System → Install → Extensions,
    # Joomla reads the <media> block in templateDetails.xml and copies files
    # here automatically. We pre-create it so permissions are correct from
    # the very start, even before the template ZIP is installed.

    TEMPLATE_MEDIA_DIR="${INSTALL_DIR}/media/templates/site"

    if [ -n "$TEMPLATE_NAME" ]; then
        echo "[+] Creating template media directory for: ${TEMPLATE_NAME}"
        mkdir -p "${TEMPLATE_MEDIA_DIR}/${TEMPLATE_NAME}/css"
        mkdir -p "${TEMPLATE_MEDIA_DIR}/${TEMPLATE_NAME}/js"
        mkdir -p "${TEMPLATE_MEDIA_DIR}/${TEMPLATE_NAME}/images"
        chown -R www-data:www-data "${TEMPLATE_MEDIA_DIR}"
        chmod -R 775 "${TEMPLATE_MEDIA_DIR}"
        echo "    [775 writable] ${TEMPLATE_MEDIA_DIR}/${TEMPLATE_NAME}/css"
        echo "    [775 writable] ${TEMPLATE_MEDIA_DIR}/${TEMPLATE_NAME}/js"
        echo "    [775 writable] ${TEMPLATE_MEDIA_DIR}/${TEMPLATE_NAME}/images"
    else
        # Still permission the parent media/templates/site dir if it exists
        if [ -d "${TEMPLATE_MEDIA_DIR}" ]; then
            chown -R www-data:www-data "${TEMPLATE_MEDIA_DIR}"
            chmod -R 775 "${TEMPLATE_MEDIA_DIR}"
            echo "    [775 writable] ${TEMPLATE_MEDIA_DIR} (no template name — subdirs not created)"
        fi
    fi

    # ── Step 5: Lock down configuration.php ──────────────────────────────────
    if [ -f "${INSTALL_DIR}/configuration.php" ]; then
        chown www-data:www-data "${INSTALL_DIR}/configuration.php"
        chmod 444 "${INSTALL_DIR}/configuration.php"
        echo "    [444 read-only] configuration.php"
    fi

    # ── Step 6: PHP upload tmp dir ────────────────────────────────────────────
    if [ -d "$PHP_TMP_DIR" ]; then
        chown www-data:www-data "$PHP_TMP_DIR"
        chmod 700 "$PHP_TMP_DIR"
        echo "    [700] $PHP_TMP_DIR"
    fi

    echo "[+] Permissions applied."
}

###########################
# 11. Firewall & Fail2Ban
###########################

configure_security() {
    echo "[+] Configuring UFW firewall..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw deny 135/tcp      # Microsoft RPC
    ufw deny 445/tcp      # Microsoft DS
    ufw deny 137:139/udp  # NetBIOS
    ufw --force enable
    ufw logging on

    echo "[+] Configuring Fail2Ban..."
    # ignoreip includes the proxy IP — banning it would take the entire site offline
    cat <<EOF > /etc/fail2ban/jail.d/apache-joomla.local
[DEFAULT]
ignoreip = 127.0.0.1/8 $PROXY_IP
bantime  = 3600
findtime = 600
maxretry = 5

[apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/joomla_error.log
maxretry = 5

[apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache2/joomla_error.log
maxretry = 6

[apache-overflows]
enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache2/joomla_error.log
maxretry = 2

[apache-badbots]
enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache2/joomla_access.log
maxretry = 1
bantime  = 86400

[joomla-admin]
enabled  = true
port     = http,https
filter   = joomla-admin
logpath  = /var/log/apache2/joomla_access.log
maxretry = 5
bantime  = 7200
EOF

    cat <<'EOF' > /etc/fail2ban/filter.d/joomla-admin.conf
[INCLUDES]
before = common.conf

[Definition]
failregex = ^<HOST> .* "POST /administrator/index\.php.*" (200|303) .*$
ignoreregex =
EOF

    systemctl restart fail2ban
}

###########################
# 12. Logwatch (HTML)
###########################

configure_logwatch() {
    echo "[+] Configuring Logwatch..."
    mkdir -p "$LOGWATCH_DIR"
    chown root:www-data "$LOGWATCH_DIR"
    chmod 750 "$LOGWATCH_DIR"

    cat <<EOF > /etc/cron.daily/logwatch-html
#!/bin/bash
/usr/sbin/logwatch --output html --filename ${LOGWATCH_DIR}/logwatch.html --range today --detail med
chmod 640 ${LOGWATCH_DIR}/logwatch.html
chown root:www-data ${LOGWATCH_DIR}/logwatch.html
EOF
    chmod +x /etc/cron.daily/logwatch-html
}

###########################
# 13. Joomla Integrity Check Cron
###########################

configure_joomla_integrity() {
    [ -f "$INSTALL_DIR/cli/joomla.php" ] || {
        echo "[!] Joomla CLI not found — skipping integrity cron setup"
        return
    }

    cat <<EOF > /etc/cron.daily/joomla-integrity
#!/bin/bash
cd ${INSTALL_DIR}
sudo -u www-data /usr/bin/php ${INSTALL_DIR}/cli/joomla.php core:check-updates >> /var/log/joomla-integrity.log 2>&1
EOF
    chmod +x /etc/cron.daily/joomla-integrity
    touch /var/log/joomla-integrity.log
    chown www-data:www-data /var/log/joomla-integrity.log
}

###########################
# 14. AIDE File Integrity
###########################

configure_aide() {
    echo "[+] Initializing AIDE..."
    aideinit -y -f || true

    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    elif [ -f /var/lib/aide/aide.db.new.gz ]; then
        mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi

    cat <<EOF > /etc/cron.daily/aide-check
#!/bin/bash
/usr/bin/aide --check >> /var/log/aide.log 2>&1
EOF
    chmod +x /etc/cron.daily/aide-check
    touch /var/log/aide.log
}

###########################
# 15. Joomla Core Auto-Update Cron
###########################

configure_joomla_updates() {
    [ -f "$INSTALL_DIR/cli/joomla.php" ] || {
        echo "[!] Joomla CLI not found — skipping update cron setup"
        return
    }

    # core:update updates Joomla core only.
    # Extension updates are NOT available via stock Joomla CLI.
    cat <<EOF > /etc/cron.weekly/joomla-update
#!/bin/bash
cd ${INSTALL_DIR}
sudo -u www-data /usr/bin/php ${INSTALL_DIR}/cli/joomla.php core:update --no-interaction >> /var/log/joomla-update.log 2>&1
EOF
    chmod +x /etc/cron.weekly/joomla-update
    touch /var/log/joomla-update.log
    chown www-data:www-data /var/log/joomla-update.log
}

###########################
# 16. Unattended OS Upgrades
###########################

configure_unattended_upgrades() {
    echo "[+] Enabling unattended OS security upgrades..."
    cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
}

###########################
# MAIN
###########################

echo "============================================="
echo "  Joomla Installer (Reverse Proxy Aware)"
echo "============================================="

generate_db_password
collect_prompts          # proxy IP + template name — all prompts upfront
check_existing_install

install_packages
setup_database
install_joomla
configure_apache
configure_php
configure_permissions    # runs AFTER php so PHP_TMP_DIR exists
configure_security
configure_logwatch
configure_joomla_integrity
configure_aide
configure_joomla_updates
configure_unattended_upgrades

# ── Final verification ────────────────────────────────────────────────────────
echo ""
echo "=== PHP Settings Verification ==="
php -r "
\$checks = [
    'upload_tmp_dir'      => ini_get('upload_tmp_dir'),
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'post_max_size'       => ini_get('post_max_size'),
    'memory_limit'        => ini_get('memory_limit'),
    'max_execution_time'  => ini_get('max_execution_time'),
    'max_input_vars'      => ini_get('max_input_vars'),
];
foreach (\$checks as \$k => \$v) {
    echo '  ' . str_pad(\$k, 25) . \$v . PHP_EOL;
}
"

echo ""
echo "=== Writable Directory Verification ==="
VERIFY_DIRS=(
    "cache"
    "administrator/cache"
    "administrator/logs"
    "tmp"
    "images"
    "media"
    "templates"
)
if [ -n "$TEMPLATE_NAME" ]; then
    VERIFY_DIRS+=(
        "media/templates/site/${TEMPLATE_NAME}/css"
        "media/templates/site/${TEMPLATE_NAME}/js"
        "media/templates/site/${TEMPLATE_NAME}/images"
    )
fi
for dir in "${VERIFY_DIRS[@]}"; do
    full="${INSTALL_DIR}/${dir}"
    if [ -d "$full" ]; then
        perm=$(stat -c "%a" "$full")
        owner=$(stat -c "%U" "$full")
        echo "  [${perm}] ${owner} — ${full}"
    fi
done

echo ""
echo "============================================="
echo "  INSTALL COMPLETE"
echo "============================================="
echo "  Joomla URL:        http(s)://your-domain/"
echo "  Logwatch:          /logwatch/logwatch.html"
echo "  Integrity log:     /var/log/joomla-integrity.log"
echo "  Update log:        /var/log/joomla-update.log"
echo "  AIDE log:          /var/log/aide.log"
echo ""
echo "  DATABASE CREDENTIALS (save these now):"
echo "  DB Name:     ${DB_NAME}"
echo "  DB User:     ${DB_USER}"
echo "  DB Password: ${DB_PASS}"
echo ""
if [ -n "$TEMPLATE_NAME" ]; then
    echo "  TEMPLATE:    ${TEMPLATE_NAME}"
    echo "  Media dir:   ${INSTALL_DIR}/media/templates/site/${TEMPLATE_NAME}/"
    echo ""
fi
echo "  POST-INSTALL CHECKLIST:"
echo "  1. Complete Joomla web installer at /installation/"
echo "  2. Remove /installation/ directory after setup"
echo "  3. Set a strong Joomla admin password"
if [ -n "$TEMPLATE_NAME" ]; then
    echo "  4. Install your template ZIP via Admin → System → Install → Extensions"
    echo "     (Ensure templateDetails.xml has a <media> block pointing to media/)"
    echo "     (Ensure index.php uses HTTP_HOST not \$this->baseurl for \$tmplBase)"
fi
echo "  5. Review /etc/fail2ban/jail.d/apache-joomla.local"
echo "  6. Consider .htpasswd protection on /administrator/"
echo "  7. Verify System → System Information shows no warnings"
echo "============================================="
