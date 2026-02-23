#!/bin/bash
# =============================================================================
# Joomla Install Script for LXC Container (HTTP only, behind reverse proxy)
# Debian (latest) / Ubuntu 22.04+
# Safe to re-run
# WAFControl runs in a SEPARATE container
#
# Covers:
#   1.  Variables & helpers
#   2.  Package installation
#   3.  Database setup
#   4.  Joomla download & install
#   5.  Apache configuration
#   6.  PHP hardening + Joomla-required settings
#   7.  Joomla filesystem permissions (FULL — includes media/templates/site/)
#   8.  Firewall (UFW) & Fail2Ban
#   9.  Logwatch (HTML)
#   10. Joomla integrity check cron
#   11. AIDE file integrity
#   12. Joomla core auto-update cron
#   13. Unattended OS upgrades
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
    DB_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9')
    echo "[+] Database password generated."
}

prompt_reverse_proxy_ip() {
    read -p "Enter REVERSE PROXY IP: " PROXY_IP
    [[ "$PROXY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
        error_exit "Invalid IP address: $PROXY_IP"
}

###########################
# 3. Package Installation
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
# 5. Database Setup
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
# 6. Joomla Download & Install
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
# 7. Apache Configuration
###########################

configure_apache() {
    echo "[+] Configuring Apache for reverse proxy..."

    a2dissite 000-default.conf >/dev/null 2>&1 || true
    a2enmod rewrite remoteip headers

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

    RemoteIPHeader X-Forwarded-For
    RemoteIPTrustedProxy 127.0.0.1
    RemoteIPTrustedProxy ${PROXY_IP}

    ErrorLog \${APACHE_LOG_DIR}/joomla_error.log
    CustomLog \${APACHE_LOG_DIR}/joomla_access.log combined
</VirtualHost>
EOF

    a2ensite joomla.conf
    apache2ctl configtest || error_exit "Apache config test failed"
    systemctl reload apache2
}

###########################
# 8. PHP Configuration
###########################

configure_php() {
    echo "[+] Configuring PHP (hardening + Joomla requirements)..."

    PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    PHP_INI_APACHE="/etc/php/${PHP_VER}/apache2/php.ini"
    PHP_INI_CLI="/etc/php/${PHP_VER}/cli/php.ini"

    [ -f "$PHP_INI_APACHE" ] || error_exit "php.ini not found at $PHP_INI_APACHE"

    echo "[+] Creating PHP tmp directory: $PHP_TMP_DIR"
    mkdir -p "$PHP_TMP_DIR"
    chown www-data:www-data "$PHP_TMP_DIR"
    chmod 700 "$PHP_TMP_DIR"

    echo "[+] Applying PHP settings to $PHP_INI_APACHE ..."

    apply_php_setting "expose_php"           "Off"           "$PHP_INI_APACHE"
    apply_php_setting "display_errors"       "Off"           "$PHP_INI_APACHE"
    apply_php_setting "output_buffering"     "Off"           "$PHP_INI_APACHE"
    apply_php_setting "allow_url_fopen"      "Off"           "$PHP_INI_APACHE"
    apply_php_setting "allow_url_include"    "Off"           "$PHP_INI_APACHE"
    apply_php_setting "upload_tmp_dir"       "$PHP_TMP_DIR"  "$PHP_INI_APACHE"
    apply_php_setting "upload_max_filesize"  "64M"           "$PHP_INI_APACHE"
    apply_php_setting "post_max_size"        "64M"           "$PHP_INI_APACHE"
    apply_php_setting "memory_limit"         "128M"          "$PHP_INI_APACHE"
    apply_php_setting "max_execution_time"   "120"           "$PHP_INI_APACHE"
    apply_php_setting "max_input_vars"       "3000"          "$PHP_INI_APACHE"

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
# 9. Joomla Filesystem Permissions
#
# WHY TWO LOCATIONS?
# Joomla 4.1+ splits templates into two locations:
#   /templates/keithtechco/         — PHP files (index.php, error.php, etc.)
#   /media/templates/site/keithtechco/ — CSS, JS, images (writable media dir)
#
# The "template folder is not writable" warning in Joomla System Information
# fires when /media/templates/site/<templatename>/ does not exist or is not
# writable by www-data. This section creates AND correctly permissions both.
#
# PERMISSION RATIONALE:
#   755 — base for all dirs (owner rwx, group r-x, other r-x)
#   775 — dirs Joomla must write to (owner rwx, group rwx, other r-x)
#         www-data owns AND is in the group, so group write = Joomla can write
#   644 — all files (owner rw, group r, other r) — never executable for files
#   configuration.php — 444 at rest (read-only), Joomla makes it 644 temporarily
#                       when saving Global Configuration, then locks it back
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
    # These are required for: installer, updater, media manager, plugin system,
    # cache engine, and the template file editor in the Joomla admin panel.
    WRITABLE_DIRS=(
        "cache"
        "administrator/cache"
        "tmp"
        "logs"
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
            chmod 775 "$full"   # 775 = group-writable; www-data owns + is in group
            echo "    [775 writable] $full"
        fi
    done

    # ── Step 4: Create the Joomla 4.1+ media/templates/site/ structure ───────
    # This is the ROOT CAUSE of "template folder is not writable":
    # Joomla 4.1+ moved all template media (css/js/images) out of /templates/
    # and into /media/templates/site/<templatename>/.
    # Joomla's template editor and file manager check THIS location for writability.
    # Without it: "The template folder is not writable. Some features may not work."
    #
    # NOTE: When the keithtechco template is installed via the Joomla installer
    # (System → Install → Extensions), the installer reads the <media> block in
    # templateDetails.xml and copies files here automatically. But we pre-create
    # the directory structure here so it exists with correct permissions from the
    # start, even before the template ZIP is installed.

    TEMPLATE_MEDIA_DIR="${INSTALL_DIR}/media/templates/site"

    echo "[+] Creating Joomla 4.1+ template media directory structure..."
    mkdir -p "${TEMPLATE_MEDIA_DIR}/keithtechco/css"
    mkdir -p "${TEMPLATE_MEDIA_DIR}/keithtechco/js"
    mkdir -p "${TEMPLATE_MEDIA_DIR}/keithtechco/images"

    # Full ownership + 775 so www-data can write (needed for template editor)
    chown -R www-data:www-data "${TEMPLATE_MEDIA_DIR}"
    chmod -R 775 "${TEMPLATE_MEDIA_DIR}"

    echo "    [775 writable] ${TEMPLATE_MEDIA_DIR}/keithtechco/css"
    echo "    [775 writable] ${TEMPLATE_MEDIA_DIR}/keithtechco/js"
    echo "    [775 writable] ${TEMPLATE_MEDIA_DIR}/keithtechco/images"

    # ── Step 5: Lock down configuration.php ──────────────────────────────────
    # Joomla temporarily makes this 644 when saving Global Configuration,
    # then locks it back. At rest it should be read-only (444).
    if [ -f "${INSTALL_DIR}/configuration.php" ]; then
        chown www-data:www-data "${INSTALL_DIR}/configuration.php"
        chmod 444 "${INSTALL_DIR}/configuration.php"
        echo "    [444 read-only] configuration.php"
    fi

    # ── Step 6: Verify the PHP tmp dir ───────────────────────────────────────
    if [ -d "$PHP_TMP_DIR" ]; then
        chown www-data:www-data "$PHP_TMP_DIR"
        chmod 700 "$PHP_TMP_DIR"
        echo "    [700] $PHP_TMP_DIR"
    fi

    echo "[+] Permissions applied."
}

###########################
# 10. Firewall & Fail2Ban
###########################

configure_security() {
    echo "[+] Configuring UFW firewall..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow OpenSSH
    ufw allow from "$PROXY_IP" to any port 80
    ufw deny 135/tcp
    ufw deny 445/tcp
    ufw deny 137:139/udp
    ufw --force enable
    ufw logging on

    echo "[+] Configuring Fail2Ban..."
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
# 11. Logwatch (HTML)
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
# 12. Joomla Integrity Check Cron
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
# 13. AIDE File Integrity
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
# 14. Joomla Core Auto-Update Cron
###########################

configure_joomla_updates() {
    [ -f "$INSTALL_DIR/cli/joomla.php" ] || {
        echo "[!] Joomla CLI not found — skipping update cron setup"
        return
    }

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
# 15. Unattended OS Upgrades
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
check_existing_install
prompt_reverse_proxy_ip

install_packages
setup_database
install_joomla
configure_apache
configure_php
configure_permissions   # runs AFTER php so PHP_TMP_DIR exists
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
for dir in cache administrator/cache tmp logs images media templates \
           media/templates/site/keithtechco/css \
           media/templates/site/keithtechco/js \
           media/templates/site/keithtechco/images; do
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
echo "  POST-INSTALL CHECKLIST:"
echo "  1. Complete Joomla web installer at /installation/"
echo "  2. Remove /installation/ directory after setup"
echo "  3. Set a strong Joomla admin password"
echo "  4. Install keithtechco-template-v1.1.zip via Admin → Extensions"
echo "     (v1.1 uses correct Joomla 4.1+ media/ folder structure)"
echo "  5. Review /etc/fail2ban/jail.d/apache-joomla.local"
echo "  6. Consider .htpasswd protection on /administrator/"
echo "  7. Verify System → System Information shows no warnings"
echo "============================================="
