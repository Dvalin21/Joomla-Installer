#!/bin/bash
# Joomla Install Script for LXC Container (HTTP only, behind reverse proxy)
# Debian (latest) / Ubuntu 22.04+
# Safe to re-run
# WAFControl runs in a SEPARATE container

set -euo pipefail

###########################
# 1. Variables
###########################

INSTALL_DIR="/var/www/html/joomla"
DB_NAME="joomla"
DB_USER="joomlauser"
DB_PASS=""
APACHE_CONF="/etc/apache2/sites-available/joomla.conf"
LOGWATCH_DIR="/var/www/html/logwatch"

###########################
# 2. Helper Functions
###########################

error_exit() {
    echo "[-] ERROR: $1"
    exit 1
}

prompt_db_password() {
    while [ -z "$DB_PASS" ]; do
        read -s -p "Enter password for Joomla DB user '${DB_USER}': " DB_PASS
        echo
        read -s -p "Confirm password: " DB_PASS2
        echo
        [ "$DB_PASS" = "$DB_PASS2" ] || DB_PASS=""
    done
}

prompt_reverse_proxy_ip() {
    read -p "Enter REVERSE PROXY IP (Zoraxy): " PROXY_IP
    [[ "$PROXY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
        error_exit "Invalid IP address"
}

###########################
# 3. Package Installation
###########################

install_packages() {
    echo "[+] Installing system packages..."
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y \
        apache2 mariadb-server mariadb-client \
        php php-cli php-common php-mysql php-xml php-curl php-gd \
        php-mbstring php-intl php-zip php-json php-fileinfo \
        unzip curl jq ufw fail2ban logwatch aide apache2-utils
}

###########################
# 4. Database Setup
###########################

setup_database() {
    echo "[+] Configuring database..."

    mysql -uroot <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME}
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost'
  IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
}

###########################
# 5. Joomla Download & Install
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

    if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/index.php" ]; then
        echo "[!] Existing Joomla detected at $INSTALL_DIR"
        echo "1) Overwrite (DELETE and reinstall)"
        echo "2) Skip Joomla install"
        read -p "Choose [1-2]: " choice

        case "$choice" in
            1) rm -rf "$INSTALL_DIR" ;;
            2) echo "[+] Skipping Joomla install"; return ;;
            *) error_exit "Invalid choice" ;;
        esac
    fi

    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    curl -fL -o joomla.zip "$download_url"
    mkdir -p "$INSTALL_DIR"
    unzip -oq joomla.zip -d "$INSTALL_DIR"

    chown -R www-data:www-data "$INSTALL_DIR"
    find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
    find "$INSTALL_DIR" -type f -exec chmod 644 {} \;

    cd /
    rm -rf "$TMPDIR"

    echo "[+] Joomla $latest_tag installed"
}

###########################
# 6. Apache Configuration
###########################

configure_apache() {
    echo "[+] Configuring Apache for reverse proxy..."

    a2dissite 000-default.conf >/dev/null 2>&1 || true
    a2enmod rewrite remoteip

    cat <<EOF > "$APACHE_CONF"
<VirtualHost *:80>
    DocumentRoot /var/www/html/joomla

    <Directory /var/www/html/joomla>
        AllowOverride All
        Require all granted
    </Directory>

    Alias /logwatch /var/www/html/logwatch

    <Directory /var/www/html/logwatch>
        Options -Indexes
        AllowOverride None
        Require ip 127.0.0.1
    </Directory>

    RemoteIPHeader X-Forwarded-For
    RemoteIPTrustedProxy 127.0.0.1
    RemoteIPTrustedProxy $PROXY_IP

    ErrorLog ${APACHE_LOG_DIR}/joomla_error.log
    CustomLog ${APACHE_LOG_DIR}/joomla_access.log combined
</VirtualHost>
EOF

    a2ensite joomla.conf
    systemctl reload apache2
}

###########################
# 7. PHP Hardening
###########################

configure_php() {
    echo "[+] Hardening PHP..."
    PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    php_ini="/etc/php/${PHP_VER}/apache2/php.ini"

    sed -i 's/^expose_php.*/expose_php = Off/' "$php_ini"
    sed -i 's/^display_errors.*/display_errors = Off/' "$php_ini"
    sed -i 's/^output_buffering.*/output_buffering = Off/' "$php_ini"

    systemctl reload apache2
}

###########################
# 8. Firewall & Fail2Ban
###########################

configure_security() {
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw --force enable

    cat <<EOF > /etc/fail2ban/jail.d/apache-joomla.local
[apache-auth]
enabled = true
EOF

    systemctl restart fail2ban
}

###########################
# 9. Logwatch (HTML)
###########################

configure_logwatch() {
    mkdir -p "$LOGWATCH_DIR"
    chown root:www-data "$LOGWATCH_DIR"
    chmod 750 "$LOGWATCH_DIR"

    cat <<EOF > /etc/cron.daily/logwatch-html
#!/bin/bash
/usr/sbin/logwatch --output html --filename $LOGWATCH_DIR/logwatch.html
EOF
    chmod +x /etc/cron.daily/logwatch-html
}

###########################
# 10. Joomla Integrity Checks
###########################

configure_joomla_integrity() {
    [ -f "$INSTALL_DIR/cli/joomla.php" ] || return
    cat <<EOF > /etc/cron.daily/joomla-integrity
#!/bin/bash
php $INSTALL_DIR/cli/joomla.php core:check-integrity >> /var/log/joomla-integrity.log
EOF
    chmod +x /etc/cron.daily/joomla-integrity
}

###########################
# 11. AIDE
###########################

configure_aide() {
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

    cat <<EOF > /etc/cron.daily/aide-check
#!/bin/bash
/usr/bin/aide --check >> /var/log/aide.log
EOF
    chmod +x /etc/cron.daily/aide-check
}

###########################
# 12. Joomla Auto Updates
###########################

configure_joomla_updates() {
    [ -f "$INSTALL_DIR/cli/joomla.php" ] || return
    cat <<EOF > /etc/cron.weekly/joomla-update
#!/bin/bash
php $INSTALL_DIR/cli/joomla.php update:extensions --core-only >> /var/log/joomla-update.log
EOF
    chmod +x /etc/cron.weekly/joomla-update
}

###########################
# MAIN
###########################

echo "=== Joomla Installer (Reverse Proxy Aware) ==="

prompt_db_password
prompt_reverse_proxy_ip
install_packages
setup_database
install_joomla
configure_apache
configure_php
configure_security
configure_logwatch
configure_joomla_integrity
configure_aide
configure_joomla_updates

echo ""
echo "=== INSTALL COMPLETE ==="
echo "Joomla URL: http(s)://your-domain/"
echo "Logwatch:   /logwatch/logwatch.html"
echo "Integrity logs: /var/log/joomla-integrity.log"
