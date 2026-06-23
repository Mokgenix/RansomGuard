# RansomGuard v2 — Ransomware Prevention Tool

A 7-layer ransomware prevention tool with a full web dashboard,
AI assistant, multi-folder monitoring, password-protected backups,
and customizable honeypot files.

---

## Quick Start (3 steps)

**Step 1** — Install Python from https://www.python.org/downloads/
- During install, check **"Add Python to PATH"**

**Step 2** — Double-click `SETUP.bat`
- Installs all required packages automatically

**Step 3** — Double-click `START.bat`
- Opens the server, then go to **http://localhost:5000**

---

## Features

### 7 Protection Layers
| Layer | What it does |
|-------|-------------|
| File Watcher | Detects burst (20+ files/10s) AND slow-burn (50+ files/6h) attacks |
| Entropy Checker | Spots files that have been scrambled/encrypted |
| Honeypots | Realistic decoy files with AI-generated content |
| Process Monitor | Detects ransomware commands + living-off-the-land attacks |
| Auto Backup | Password-protected ZIP snapshots |
| Network Monitor | Blocks connections to known criminal servers |
| Emergency Lockdown | Kills process + children, cuts network, alerts you |

### New in v2
- **Multi-folder monitoring** — watch any number of folders across any drive
- **Multi-destination backups** — write backups to multiple locations (local + USB)
- **AI Assistant** — built-in chatbot using your Anthropic API key
- **Custom honeypot names** — name your decoys yourself
- **AI honeypot content** — AI generates realistic document content for decoys
- **Replace-mode backups** — old backup deleted before new one written (saves space)
- **Password-protected backups** — ZIP files require a password to open (default: 11223344)
- **Living-off-the-land detection** — detects ransomware hiding inside PowerShell, certutil, wmic, etc.
- **Slow-burn detection** — catches patient ransomware that encrypts slowly over hours
- **Child process kill** — when a ransomware process is killed, all its children are killed too

---

## Folder Structure

```
RansomGuard/
├── app.py                  ← Main server (run this)
├── SETUP.bat               ← Run first (installs packages)
├── START.bat               ← Run to launch
├── requirements.txt
├── config.json             ← Auto-created on first run
├── core/
│   ├── __init__.py
│   ├── file_monitor.py     ← Layer 1+2: File watcher + entropy
│   ├── honeypot.py         ← Layer 3: Honeypot manager
│   ├── process_monitor.py  ← Layer 4: Process + LotL detection
│   ├── backup.py           ← Layer 5: Password-protected backups
│   ├── network_monitor.py  ← Layer 6: Network blocker
│   └── folder_browser.py   ← Folder picker + config persistence
├── templates/
│   └── dashboard.html      ← Web UI
├── backups/                ← Default backup location
├── honeypots/              ← Honeypot metadata
└── threat_data/            ← Bad IP lists
```

---

## Password-Protected Backups

Backups are saved as password-protected ZIP files.

**Default password:** `11223344`

To open a backup:
1. Right-click the .zip → Extract All, or open with 7-Zip/WinRAR
2. Enter the password when prompted

To change the password: Settings → Backup Password

For best encryption, install either:
- **pyminizip** (installed by SETUP.bat automatically)
- **7-Zip** from https://www.7-zip.org/download.html

---

## AI Assistant

Add your Anthropic API key in **Settings → AI API Key**.

Get a key at: https://console.anthropic.com

The AI can:
- Explain any alert in plain language
- Answer questions about ransomware threats
- Suggest security improvements
- Generate realistic content for honeypot files

---

## Honeypot Customization

Go to **Honeypots** in the sidebar:

1. Add your own file names (e.g. `salary_slip_{m}_{y}.pdf`)
   - Use `{y}` for year, `{m}` for month, `{q}` for quarter
2. Click **AI Generate Content** to fill them with realistic document text
3. Click **Redeploy Now** to place them across your monitored folders

---

## Notes

- Run as Administrator for best process-killing and network-blocking capability
- The tool uses ~1-3% CPU while running
- Backup files are saved to all configured backup destinations simultaneously
- Honeypots rotate to new names every 30 days automatically