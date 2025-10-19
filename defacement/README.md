# Website Defacement Detection using DB Baseline

## Setup Instructions

### 1. Run DVWP (Damn Vulnerable WordPress)
- Start the DVWP container or local instance before running the detector.
- Example:
  ```bash
  docker-compose up -d
  ```

### 2. Install Python
- Make sure Python 3.8+ is installed.
- Check version:
  ```bash
  python --version
  ```

### Change directory to /defacement

### 3. Set up Virtual Environment
#### Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

#### Linux/Mac:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Run MailHog (for testing email alerts)
```bash
docker compose -f mailhog.yml up -d
```
- Access MailHog web UI at: http://localhost:8025

### 6. Fill out the .env (required)
Create a file named .env in the /defacement project root (same folder as scripts/). This file stores configuration values used by the detector (paths, site URL, SMTP settings, etc.). Do not commit .env to version control — add it to .gitignore.

### 7. Create Baseline Snapshot
- This will save the current clean state of your website to the baseline file.
```bash
python scripts/create_baseline.py
```

### 8. Run the Defacement Detector
- Start the detector to monitor for any changes from the baseline.
```bash
python scripts/detector.py
```

### 8. (Optional) Schedule the Detector
- You can run it periodically using `cron` (Linux/Mac) or Task Scheduler (Windows).
```bash
# Example cron job (runs every 5 minutes)
*/5 * * * * /path/to/venv/bin/python /path/to/scripts/detector.py
```
