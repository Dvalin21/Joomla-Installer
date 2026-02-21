# 🛡️ Joomla LXC Installer — Reverse Proxy Aware

> **A battle-hardened, single-script Joomla deployment for LXC containers sitting behind a reverse proxy.**  
> One run. Fully configured. Production-ready security out of the box.

---

## 📋 Overview

This script automates a complete, security-hardened Joomla installation inside an **unprivileged LXC container** on Proxmox (or any LXC host). It is designed for environments where a **WAF/reverse proxy runs in a separate container** — the Joomla container never faces the public internet directly.

No client names are hardcoded. Drop it on any server, answer two prompts, and walk away.

---

## ✅ What It Does

| Step | What Happens |
|------|-------------|
| 🔐 **Prompts** | Collects reverse proxy IP and template name upfront — no mid-install surprises |
| 🔁 **Re-run safe** | Detects existing installs and offers a clean wipe or graceful exit |
| 📦 **Packages** | Installs Apache, MariaDB, PHP + all required extensions, UFW, Fail2Ban, AIDE, Logwatch |
| 🗄️ **Database** | Creates the Joomla DB and user with a randomly generated password, verifies credentials |
| 🌐 **Joomla** | Auto-detects and downloads the latest stable Joomla release from GitHub |
| ⚙️ **Apache** | Configures VirtualHost with security headers, `mod_remoteip` for real client IPs, and SEF URL support |
| 🐘 **PHP** | Hardens `php.ini` for both Apache and CLI — upload limits, memory, tmp dir, security flags |
| 📁 **Permissions** | Sets correct `755`/`775`/`644`/`444` permissions including the Joomla 4.1+ `media/templates/site/` structure |
| 🔥 **Firewall** | UFW configured to allow port 80 from the proxy IP only — port 22 open, Windows ports denied |
| 🚫 **Fail2Ban** | Five active jails: apache-auth, badbots, noscript, overflows, and a custom Joomla admin brute-force jail |
| 📊 **Logwatch** | Daily HTML security report restricted to proxy IP — accessible via browser |
| 🔍 **Integrity** | Daily Joomla core update check cron + AIDE file integrity monitoring |
| 🔄 **Auto-update** | Weekly Joomla core auto-update cron via Joomla CLI |
| 🛡️ **OS Security** | Unattended security upgrades enabled for the host OS |

---

## 🖥️ Requirements

- **Host:** Proxmox or any LXC-capable hypervisor
- **Container OS:** Debian (latest) or Ubuntu 22.04+
- **Container type:** Unprivileged LXC (privileged also works)
- **Architecture:** The WAF/reverse proxy **must** run in a separate container
- **Run as:** `root` inside the Joomla LXC container

---

## 🚀 Quick Start

```bash
# 1. Copy the script to your Joomla LXC container
scp joomla-install.sh root@<container-ip>:/root/

# 2. Make it executable
chmod +x joomla-install.sh

# 3. Run it
./joomla-install.sh
```

The script will prompt you for two things before touching anything:

```
Enter REVERSE PROXY IP: 192.168.1.10

Enter your Joomla template name.
  - Must match the folder name inside your template ZIP exactly
  - Lowercase letters, numbers, and underscores only (no spaces)
  - Example: mycompany  or  acme_theme
  - Leave blank to skip pre-creating the template media directory
Template name [leave blank to skip]: mytemplate
```

That's it. Everything else is automated.

---

## 📁 What Gets Installed Where

```
/var/www/html/joomla/               ← Joomla root (755, www-data)
├── cache/                          ← (775) Joomla cache engine
├── tmp/                            ← (775) Joomla temp files
├── templates/                      ← (775) Template PHP files
├── media/
│   └── templates/
│       └── site/
│           └── <your-template>/    ← (775) CSS, JS, images (Joomla 4.1+)
│               ├── css/
│               ├── js/
│               └── images/
├── administrator/
│   ├── cache/                      ← (775)
│   ├── logs/                       ← (775) Joomla 4+ log location
│   ├── templates/                  ← (775)
│   └── manifests/                  ← (775)
└── configuration.php               ← (444) Locked at rest

/var/lib/php/tmp/                   ← (700) PHP upload tmp dir
/var/www/html/logwatch/             ← (750) Daily HTML security report
```

---

## 🔒 Security Architecture

```
Internet
   │
   ▼
[Reverse Proxy / WAF Container]   ← SSL termination, WAF rules
   │  (port 80, proxy IP only)
   ▼
[Joomla LXC Container]
   ├── UFW: port 80 from proxy IP only
   ├── Fail2Ban: 5 active jails
   ├── AIDE: file integrity baseline
   ├── Apache: mod_remoteip (real IPs logged, not proxy)
   └── PHP: hardened ini, no exposed version info
```

### Fail2Ban Jails

| Jail | Log | Trigger | Ban Time |
|------|-----|---------|----------|
| `apache-auth` | error log | HTTP auth failures | 1 hour |
| `apache-noscript` | error log | Script probing (wp-login, etc.) | 1 hour |
| `apache-overflows` | error log | Buffer overflow attempts | 1 hour |
| `apache-badbots` | access log | Known malicious user agents | 24 hours |
| `joomla-admin` | access log | POST brute-force on `/administrator/` | 2 hours |

> The reverse proxy IP is automatically added to `ignoreip` — it can never be banned.

### PHP Hardening Applied

| Setting | Value | Reason |
|---------|-------|--------|
| `expose_php` | Off | Hides PHP version from headers |
| `display_errors` | Off | No error info leaked to visitors |
| `allow_url_fopen` | Off | Prevents remote file inclusion |
| `allow_url_include` | Off | Blocks remote include attacks |
| `upload_max_filesize` | 64M | Supports extension installs |
| `memory_limit` | 128M | Joomla minimum recommendation |
| `max_execution_time` | 120 | Allows large imports/updates |
| `max_input_vars` | 3000 | Required for complex admin forms |

---

## 🗓️ Cron Jobs Installed

| Schedule | Job | Log |
|----------|-----|-----|
| Daily | Joomla core update check (`core:check-updates`) | `/var/log/joomla-integrity.log` |
| Daily | AIDE file integrity check | `/var/log/aide.log` |
| Daily | Logwatch HTML report generation | `/var/www/html/logwatch/logwatch.html` |
| Weekly | Joomla core auto-update (`core:update`) | `/var/log/joomla-update.log` |
| Auto | Unattended OS security upgrades | system journal |

---

## 📦 Template Requirements (Joomla 4.1+)

This script pre-creates the correct Joomla 4.1+ template media directory structure. Your template ZIP **must** follow the modern layout to install cleanly and avoid the *"template folder is not writable"* warning.

### Required `templateDetails.xml` structure

```xml
<?xml version="1.0" encoding="utf-8"?>
<extension version="3.1" type="template" client="site">
    <n>yourtemplatename</n>
    ...

    <!-- PHP files only in <files> -->
    <files>
        <filename>templateDetails.xml</filename>
        <filename>index.php</filename>
        <filename>error.php</filename>
        <filename>component.php</filename>
    </files>

    <!-- CSS/JS/images declared in <media>, NOT in <files> -->
    <media destination="templates/site/yourtemplatename" folder="media">
        <folder>css</folder>
        <folder>js</folder>
        <folder>images</folder>
    </media>

    <positions>
        <position>nav</position>
        ...
    </positions>
</extension>
```

### Required ZIP structure

```
yourtemplatename/
├── templateDetails.xml
├── index.php
├── error.php
├── component.php
└── media/
    ├── css/
    │   └── template.css
    ├── js/
    │   └── template.js
    └── images/
        └── logo.jpg
```

> ⚠️ **Do not** put `css/`, `js/`, or `images/` directly in the template root — that is the Joomla 3 layout and will trigger the *"template folder is not writable"* warning in Joomla 4/5/6.

---

## 🔧 Post-Install Checklist

After the script completes, do the following:

- [ ] Open `http://<server-ip>/joomla/installation/` and complete the Joomla web installer
- [ ] Enter the database credentials printed at the end of the script
- [ ] Delete the `/installation/` directory when prompted (or manually)
- [ ] Set a strong Joomla admin password
- [ ] Install your template ZIP via **System → Install → Extensions**
- [ ] Set your template as default via **System → Site Templates → ★**
- [ ] Configure SMTP mail via **System → Global Configuration → Server**
- [ ] Point your domain DNS to the reverse proxy's public IP
- [ ] Install SSL on the reverse proxy with Certbot
- [ ] Enable HTTPS in Joomla: **System → Global Configuration → Force HTTPS: Entire Site**
- [ ] Verify **System → System Information** shows no warnings
- [ ] Consider adding `.htpasswd` protection on `/administrator/`

---

## 🔁 Re-running the Script

The script is safe to re-run. If an existing install is detected, it will ask:

```
[!] Existing installation detected:
    - Database 'joomla' exists
    - Joomla files exist at /var/www/html/joomla

  1) Delete everything and reinstall fresh
  2) Skip — leave existing install untouched and exit
```

Option `1` drops the database, deletes all files, and generates a new random password. Option `2` exits with no changes made.

---

## 📋 Key File Locations

| Item | Path |
|------|------|
| Joomla root | `/var/www/html/joomla/` |
| Apache vhost config | `/etc/apache2/sites-available/joomla.conf` |
| PHP config (Apache) | `/etc/php/<version>/apache2/php.ini` |
| PHP config (CLI) | `/etc/php/<version>/cli/php.ini` |
| PHP upload tmp | `/var/lib/php/tmp/` |
| Fail2Ban jails | `/etc/fail2ban/jail.d/apache-joomla.local` |
| Joomla admin filter | `/etc/fail2ban/filter.d/joomla-admin.conf` |
| Logwatch report | `/var/www/html/logwatch/logwatch.html` |
| Integrity log | `/var/log/joomla-integrity.log` |
| Update log | `/var/log/joomla-update.log` |
| AIDE log | `/var/log/aide.log` |

---

## ⚠️ Important Notes

- **Extension updates** are not handled by this script. The Joomla CLI `core:update` command only updates Joomla core. Use [Akeeba Panopticon](https://www.akeeba.com/products/panopticon.html) or similar for automated extension management.
- **SSL** is handled on the reverse proxy container, not here. Do not install Certbot on the Joomla container.
- **Logwatch** is restricted to `127.0.0.1` and your proxy IP. It will return `403 Forbidden` from any other IP — this is intentional.
- **`configuration.php`** is locked to `444` (read-only) at rest. Joomla temporarily unlocks it to `644` when saving Global Configuration, then re-locks it automatically.

---

## 📄 License

MIT — use freely, modify freely, deploy for any client.

---

*Built for system administrators who believe security shouldn't be optional.*
