# Joomla LXC Container Installer

## Overview

This Bash script automates the deployment of Joomla CMS in an LXC container configured to run behind a reverse proxy (HTTP-only setup). Designed for Debian/Ubuntu systems, it includes security hardening, monitoring, and maintenance features in a production-ready configuration.

**Architecture Note**: This setup assumes WAF (Web Application Firewall) runs in a SEPARATE container.

## Features

- **Automated Joomla Installation**: Latest stable release from GitHub
- **Reverse Proxy Ready**: Configured for proxy-based deployments
- **Security Hardening**: Multiple layers of protection
- **Monitoring & Maintenance**: Automated checks and updates
- **Idempotent Design**: Safe to re-run without breaking existing setup

## Requirements

- **OS**: Debian (latest) or Ubuntu 22.04+
- **Environment**: LXC/LXD container
- **Reverse Proxy**: External proxy (e.g., Zoraxy, Nginx, Traefik)
- **Network**: Container must be reachable by reverse proxy
- **Privileges**: Root or sudo access

## Quick Start

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/joomla-lxc-installer.git
cd joomla-lxc-installer
```

2. **Make script executable**:
```bash
chmod +x install-joomla.sh
```

3. **Run the installer**:
```bash
./install-joomla.sh
```

## Script Breakdown

### 1. Configuration Section
```bash
INSTALL_DIR="/var/www/html/joomla"
DB_NAME="joomla"
DB_USER="joomlauser"
DB_PASS=""  # Prompted during installation
APACHE_CONF="/etc/apache2/sites-available/joomla.conf"
LOGWATCH_DIR="/var/www/html/logwatch"
```
- **Install Directory**: Standard Apache web root
- **Database**: Pre-defined credentials with secure password prompt
- **Logwatch**: Web-accessible security reports

### 2. Package Installation
Installs required stack:
- **Web Server**: Apache2
- **Database**: MariaDB
- **PHP**: Core + Joomla extensions
- **Security**: UFW, fail2ban, AIDE, logwatch
- **Utilities**: curl, jq, unzip

### 3. Database Setup
Creates MySQL/MariaDB database with:
- UTF8mb4 character set (full Unicode support)
- Dedicated user with restricted privileges
- Localhost-only access

### 4. Joomla Installation
1. Fetches latest stable release from GitHub API
2. Validates existing installation (offers overwrite/skip)
3. Sets secure file permissions (755 directories, 644 files)
4. Configures proper ownership for Apache

### 5. Apache Configuration
```apache
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 127.0.0.1
RemoteIPTrustedProxy $PROXY_IP
```
- Configures reverse proxy IP trust
- Enables .htaccess overrides
- Creates secured `/logwatch` directory
- Sets up proper logging

### 6. PHP Hardening
Modifies `php.ini`:
- `expose_php = Off` (hides PHP version)
- `display_errors = Off` (prevents info leakage)
- `output_buffering = Off` (security best practice)

### 7. Security Configuration
- **Firewall**: UFW with SSH (22) and HTTP (80) only
- **Fail2Ban**: Apache authentication protection
- **AIDE**: File integrity monitoring with daily checks
- **Logwatch**: Daily HTML security reports

### 8. Automated Maintenance
- **Daily**: Joomla integrity checks
- **Daily**: AIDE file integrity verification
- **Weekly**: Joomla core updates
- **Daily**: Logwatch HTML reports

## Installation Process

### Interactive Prompts
The script will prompt for:
1. **Database Password**: Secure password for Joomla DB user
2. **Reverse Proxy IP**: IP address of your proxy server

### Automated Steps
1. Package installation and system update
2. Database creation and user setup
3. Joomla download and extraction
4. Web server configuration
5. Security hardening
6. Monitoring setup
7. Cron job creation

## Security Architecture

```
┌─────────────────┐    HTTPS     ┌─────────────────┐    HTTP     ┌─────────────────┐
│                 │ ────────────► │   Reverse      │ ──────────► │   Joomla LXC    │
│   Internet      │              │     Proxy       │            │    Container    │
│                 │ ◄──────────── │   (External)   │ ◄───────── │  (This Script)  │
└─────────────────┘              └─────────────────┘            └─────────────────┘
                                   TLS Termination               HTTP Only + Security
```

### Defense in Depth
- **Network Layer**: UFW firewall
- **Application Layer**: Fail2Ban + Apache hardening
- **File Layer**: AIDE integrity monitoring
- **CMS Layer**: Joomla security checks

## Post-Installation

### Access Points
- **Joomla Admin**: `http://your-container-ip/administrator`
- **Logwatch Reports**: `http://your-container-ip/logwatch/logwatch.html` (localhost only)
- **Log Files**:
  - Integrity checks: `/var/log/joomla-integrity.log`
  - Updates: `/var/log/joomla-update.log`
  - AIDE: `/var/log/aide.log`

### Reverse Proxy Configuration
Configure your reverse proxy to:
1. Point to container IP on port 80
2. Forward `X-Forwarded-For` headers
3. Handle SSL/TLS termination
4. Set appropriate security headers

### First Time Setup
1. Complete Joomla web installer
2. Configure site settings
3. Set up administrator account
4. Review security extensions

## Maintenance

### Automated Tasks
- **Daily**: Security log reports (Logwatch)
- **Daily**: File integrity checks (AIDE)
- **Daily**: Joomla integrity verification
- **Weekly**: Joomla core updates

### Manual Checks
```bash
# Check integrity logs
tail -f /var/log/joomla-integrity.log

# Check update logs
tail -f /var/log/joomla-update.log

# Check AIDE reports
tail -f /var/log/aide.log

# Check fail2ban status
fail2ban-client status
```

### Backup Recommendations
```bash
# Database backup
mysqldump -u joomlauser -p joomla > joomla_backup_$(date +%F).sql

# Files backup
tar -czf joomla_files_$(date +%F).tar.gz /var/www/html/joomla
```

## Troubleshooting

### Common Issues

1. **Reverse Proxy Connection Issues**
   - Verify container IP is correct
   - Check UFW allows port 80
   - Confirm proxy IP is correctly configured in Apache

2. **Database Connection Problems**
   - Verify MariaDB is running: `systemctl status mariadb`
   - Check user privileges: `mysql -uroot -e "SHOW GRANTS FOR 'joomlauser'@'localhost';"`

3. **Permission Errors**
   - Reset permissions: `chown -R www-data:www-data /var/www/html/joomla`
   - Check directory permissions: `ls -la /var/www/html/`

### Log Locations
- Apache error log: `/var/log/apache2/joomla_error.log`
- Apache access log: `/var/log/apache2/joomla_access.log`
- Fail2Ban: `/var/log/fail2ban.log`
- Cron jobs: Check `/var/log/syslog` for cron output

## Security Notes

### Assumptions
1. **Container Isolation**: LXC provides network isolation
2. **Reverse Proxy Security**: External proxy handles DDoS protection
3. **WAF Separation**: Web Application Firewall runs separately
4. **Internal Network**: Container not directly exposed to internet

### Required Configuration
1. **Reverse Proxy**: Must be configured before installation
2. **Firewall Rules**: Only SSH and HTTP ports open
3. **Regular Updates**: Monitor cron job logs for update failures
4. **Backup Strategy**: Implement separate backup solution

## Official Documentation

- **Joomla**: [https://downloads.joomla.org/](https://downloads.joomla.org/)
- **Apache mod_remoteip**: [Apache Docs](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
- **MariaDB**: [Knowledge Base](https://mariadb.com/kb/en/)
- **AIDE**: [GitHub](https://aide.github.io/)
- **Fail2Ban**: [Official Site](https://www.fail2ban.org/)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with clear commit messages
4. Test thoroughly in a staging environment
5. Submit pull request with description of changes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

> **Important**: This script is designed for specific deployment architecture (LXC + reverse proxy). 
> 
> **Not recommended for**:
> - Direct internet exposure without additional security
> - Production without proper testing
> - Environments with specific compliance requirements
> 
> Always test in a staging environment before production deployment.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

## Support

For issues, questions, or contributions:
1. Check existing issues on GitHub
2. Review troubleshooting section
3. Create new issue with detailed description
4. Include relevant logs and configuration details

---

**Note**: This setup assumes HTTPS/TLS termination at the reverse proxy level. The container itself runs HTTP only.
