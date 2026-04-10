# Xophz Magic Shield (Mirror Shield)

> **Category:** Castle Walls · **Version:** 0.0.1

Stand protected and reflect attacks back to your attackers!

## Description

**Mirror Shield** is a proactive security and honeypot plugin for the COMPASS ecosystem. It acts as a defensive layer that catches malicious actors, bots, and vulnerability scanners before they can cause harm by deploying invisible honeypot traps. When triggered, it identifies and automatically blocks attackers while legitimate users remain completely unaffected.

### Core Capabilities

- **Honeypot Traps** – Three types of traps to catch automated scanners and malicious behavior:
  - `decoy_endpoint`: Fake URLs that attackers probe (e.g., `/wp-admin/backup.php`)
  - `honeypot_field`: Hidden form fields bots fill out but humans don't see
  - `fake_login`: Decoy login pages that capture credentials
- **Auto-Blocking Engine** – IPs are automatically blocked for 24 hours after triggering 3+ trap events within 1 hour.
- **Attack Logging** – Detailed records of attacks including IP, trap triggered, User-Agent, and target URI.
- **IP Blacklisting** – Support for manual time-limited and permanent IP blocking.
- **Security Dashboard** – Real-time timeline, stats cards, and top attacker visualizations.

### Default Traps Seeded on Activation

1. **Fake Backup File** - `/wp-admin/backup.php`
2. **Fake Config File** - `/wp-config.bak`
3. **Fake Admin Panel** - `/administrator/`
4. **Login Form Honeypot** - Hidden `website_url` field

## Requirements

- **Xophz COMPASS** parent plugin (active)
- WordPress 5.8+, PHP 7.4+

## Installation

1. Ensure **Xophz COMPASS** is installed and active.
2. Upload `xophz-compass-mirror-shield` to `/wp-content/plugins/`.
3. Activate through the Plugins menu.
4. On activation, the plugin initializes its database tables (`logs`, `traps`, `blocked`) and seeds the default honeypot traps.
5. Access via the COMPASS dashboard → **Mirror Shield**.

## REST API Handlers

Base Path: `/wp-json/xophz-compass/v1/mirror-shield/`
* `/logs` (GET) - Paginated attack logs
* `/stats` (GET) - Dashboard statistics
* `/traps`, `/traps/:id` (GET/POST/PUT/DELETE) - Trap management
* `/block`, `/block/:ip` (GET/POST/DELETE) - IP Blacklist management

## Frontend Routes

| Route | View | Description |
|---|---|---|
| `/mirror-shield` | Dashboard | Attack timeline, stats, and top attackers |
| `/mirror-shield/traps` | Traps | CRUD management for honeypot traps |
| `/mirror-shield/logs` | Logs | Server-side paginated attack log browser |

## PHP Class Map

| Class | File | Purpose |
|---|---|---|
| `Xophz_Compass_Mirror_Shield` | `class-xophz-compass-mirror-shield.php` | Plugin lifecycle and loader |
| `Mirror_Shield_Honeypot` | `class-mirror-shield-honeypot.php` | The trap interceptor and auto-blocking logic |
| `Mirror_Shield_Rest` | `class-mirror-shield-rest.php` | REST API routes for Vue dashboard |
| `Xophz_Compass_Mirror_Shield_Activator` | `class-xophz-compass-mirror-shield-activator.php` | Database schema creation and default seeding |

## Changelog

### 0.0.1
- Initial release featuring Honeypot deployment, Attack Logging, Auto-blocking, and REST APIs.
