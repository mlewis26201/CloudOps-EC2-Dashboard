
# CloudOps EC2 Dashboard

A modern terminal and GUI dashboard for managing AWS EC2 instances using SSO profiles. Features include listing, starting/stopping, viewing/editing tags, instance lookup, and running shell commands via SSM.


## Features

### Terminal Dashboard
- List EC2 instances in a styled table
- Start/stop instances interactively
- View/edit instance tags
- Lookup instances by ID, name, or private IP
- Run shell commands on SSM-enabled instances
- Switch AWS SSO profiles and regions

### Graphical GUI (PyQt)
- All the above features in a modern desktop app
- Search/filter by Instance ID, Name, or Private IP
- Click to start/stop instances
- Run SSM commands from a dialog
- Automatic SSO login refresh


## Quick Start

### 1. Clone the Repository
```sh
git clone <your-repo-url>
cd ER-AWS-Dashboard
```

### 2. Set Up a Python Virtual Environment

#### **Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

#### **Linux/macOS (bash):**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Requirements
```sh
pip install -r requirements.txt
```

### 4. Configure AWS CLI with SSO
Make sure you have the AWS CLI v2 installed and configured with SSO:
```sh
aws configure sso
```


### 5. Run the Terminal Dashboard

#### **Windows (PowerShell):**
```powershell
& ".venv\Scripts\python.exe" aws_dashboard.py dashboard
```

#### **Linux/macOS (bash):**
```bash
python aws_dashboard.py dashboard
```

---

### 6. Run the Graphical GUI (PyQt)

#### **Windows (PowerShell):**
```powershell
& ".venv\Scripts\python.exe" gui\gui_main.py
```

#### **Linux/macOS (bash):**
```bash
python gui/gui_main.py
```

---


## Requirements
- Python 3.8+
- AWS CLI v2 with SSO configured
- Permissions to manage EC2 and SSM
- For GUI: PyQt5 (`pip install PyQt5`)


## Troubleshooting
- If you see SSO login errors, follow the prompt to log in via `aws sso login`.
- For SSM commands, ensure the instance is SSM-enabled and your IAM role has the correct permissions.
- If the GUI fails to list instances, make sure your SSO session is valid; the app will prompt you to log in if needed.

## License
MIT
