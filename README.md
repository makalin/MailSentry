# MailSentry

MailSentry is a robust command-line tool and API for analyzing email server configurations, DNS records, and security diagnostics. Built in Python, it offers detailed insights into a domain’s MX servers, DNS setup, and blacklist status, surpassing tools like MXToolbox with concurrent checks, an extensive blacklist provider list, and a Flask-based API. The latest updates enhance stability, error handling, and usability for both terminal and API interfaces.

## Features

- **MX Record Lookup**: Retrieves and sorts unique MX hosts by priority.
- **Comprehensive DNS Checks**: Queries A, CNAME, TXT, SPF, and DMARC records.
- **Advanced Diagnostics**:
  - Reverse DNS lookup for MX host IPs.
  - SMTP connectivity testing with detailed error reporting.
  - Blacklist checks against nine providers: Spamhaus, Barracuda, SORBS, SpamCop, UCEPROTECT, CBL, DroneBL, PSBL, EFnet RBL.
- **Concurrent Processing**: Uses `ThreadPoolExecutor` for efficient parallel checks.
- **Flask API**: Provides programmatic access to diagnostics via HTTP endpoints, running on port 5001 with debug mode.
- **Robust Error Handling**: Handles invalid domains, DNS errors, JSON serialization issues, and signal conflicts.
- **Pyodide Compatibility**: Avoids local file I/O for browser-based execution.
- **User-Friendly Terminal Interface**: Validates domain input and supports graceful shutdown (`Ctrl+C`).
- **Structured Output**: Human-readable terminal output and JSON-compatible API responses.

## Latest Updates (June 2025)

- **Expanded Blacklist Providers**: Added `dnsbl-1.uceprotect.net`, `cbl.abuseat.org`, `dnsbl.dronebl.org`, `psbl.surriel.com`, and `rbl.efnetrbl.org` for broader spam detection.
- **Flask in Main Thread**: Moved Flask server to the main thread to fix `ValueError: signal only works in main thread`, enabling debug mode.
- **Improved Error Handling**:
  - Fixed `TypeError: Object of type bytes is not JSON serializable` by decoding SMTP banners.
  - Resolved `UnicodeError` with hostname validation in `resolve_ip`.
  - Corrected `KeyError: 'blacklist'` and `AttributeError: 'str' object has no attribute 'get'` in blacklist processing.
- **Enhanced Terminal Interface**: Added domain input validation and graceful `Ctrl+C` shutdown.
- **Consistent SMTP Checks**: Ensured reliable output, addressing `SMTP Check: N/A` issues.
- **Robust Diagnostics**: Fixed result assignment for reverse DNS and blacklists.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/makalin/MailSentry.git
   cd MailSentry
   ```

2. **Set Up Virtual Environment**:
   ```bash
   python3 -m venv mailsentry_env
   source mailsentry_env/bin/activate
   ```

3. **Install Dependencies**:
   Requires Python 3.8+ and the following libraries:
   ```bash
   pip install dnspython flask
   ```

4. **Run the App**:
   ```bash
   python mailsch.py
   ```

## Usage

### Terminal Usage
Run the script and enter a domain when prompted:
```bash
python mailsch.py
Enter domain to check (e.g., example.com): google.com
```

**Example Output**:
```
MX Server Check for google.com (2025-06-11T14:07:00Z UTC)
==================================================
Unique MX Hosts (by priority):
Host: smtp.google.com, Priority: 10

DNS Records:
  A: ['142.250.190.78']
  CNAME: ['None']
  TXT: ['"v=spf1 include:_spf.google.com ~all"']

Diagnostics:
- smtp.google.com
  IP: 142.250.190.78
  Reverse DNS: smtp.google.com
  SMTP Check: success
    Banner: 220 smtp.google.com ESMTP ...
  Blacklists:
    zen.spamhaus.org: False
    b.barracudacentral.org: False
    dnsbl.sorbs.net: False
    bl.spamcop.net: False
    dnsbl-1.uceprotect.net: False
    cbl.abuseat.org: False
    dnsbl.dronebl.org: False
    psbl.surriel.com: False
    rbl.efnetrbl.org: False

SPF Record: "v=spf1 include:_spf.google.com ~all"
DMARC Record: v=DMARC1; p=reject; rua=mailto:dmarc-reports@google.com;
==================================================
```

### API Usage
The Flask server runs on `http://localhost:5001`.

1. **Check Domain**:
   Send a POST request to `/api/check`:
   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"domain":"google.com"}' http://localhost:5001/api/check
   ```

   **Example Response**:
   ```json
   {
     "domain": "google.com",
     "mx_records": [
       {"host": "smtp.google.com", "priority": 10}
     ],
     "dns_records": {
       "A": ["142.250.190.78"],
       "CNAME": ["None"],
       "TXT": ["\"v=spf1 include:_spf.google.com ~all\""]
     },
     "diagnostics": {
       "unique_hosts": ["smtp.google.com"],
       "smtp.google.com": {
         "ip": "142.250.190.78",
         "reverse_dns": "smtp.google.com",
         "smtp": {"status": "success", "banner": "220 smtp.google.com ESMTP ...", "error": null},
         "blacklists": [
           {"blacklist": "zen.spamhaus.org", "listed": false},
           {"blacklist": "b.barracudacentral.org", "listed": false},
           {"blacklist": "dnsbl.sorbs.net", "listed": false},
           {"blacklist": "bl.spamcop.net", "listed": false},
           {"blacklist": "dnsbl-1.uceprotect.net", "listed": false},
           {"blacklist": "cbl.abuseat.org", "listed": false},
           {"blacklist": "dnsbl.dronebl.org", "listed": false},
           {"blacklist": "psbl.surriel.com", "listed": false},
           {"blacklist": "rbl.efnetrbl.org", "listed": false}
         ]
       },
       "spf": "\"v=spf1 include:_spf.google.com ~all\"",
       "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc-reports@google.com;"
     },
     "timestamp": "2025-06-11T14:07:00Z"
   }
   ```

2. **Check API Status**:
   ```bash
   curl http://localhost:5001/api/status
   ```

   **Response**:
   ```json
   {"status": "MailSentry API is running", "version": "1.0.0"}
   ```

## API Endpoints

- **POST /api/check**
  - **Payload**: `{"domain": "example.com"}`
  - **Response**: JSON with MX records, DNS records, and diagnostics.
  - **Status Codes**:
    - `200`: Success
    - `400`: Invalid or missing domain
    - `500`: Internal server error with details

- **GET /api/status**
  - **Response**: JSON confirming API status and version.

## Setup Script

A bash script (`setup_mailsentry.sh`) simplifies setup:
```bash
chmod +x setup_mailsentry.sh
./setup_mailsentry.sh
```

**Example `setup_mailsentry.sh`**:
```bash
#!/usr/bin/env bash
echo "Setting up MailSentry environment..."
if command -v conda &>/dev/null && conda info --envs &>/dev/null; then
    conda deactivate
fi
if command -v pyenv &>/dev/null; then
    pyenv shell 3.11.0
else
    echo "pyenv not found. Ensure pyenv is installed."
    exit 1
fi
cd /Users/makalin/Downloads
if [ ! -d "mailsentry_env" ]; then
    python3 -m venv mailsentry_env
fi
source mailsentry_env/bin/activate
pip install --upgrade pip
pip install dnspython flask
echo "Running MailSentry..."
python3 mailsch.py
```

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## Development Ideas

- Add support for more DNS record types (NS, SOA).
- Implement response caching for API efficiency.
- Add API authentication and rate-limiting.
- Develop a web UI using React or Flask templates.
- Integrate a database for result persistence.

## Requirements

- Python 3.8+
- Libraries: `dnspython`, `flask`
- Optional: pyenv for version management, virtualenv for isolation

## Troubleshooting

- **Port Conflict**:
  ```bash
  lsof -i :5001
  kill -9 <pid>
  ```
  Or change the port in `mailsch.py` (line ~220).
- **DNS Errors**:
  Test DNS resolution:
  ```bash
  dig MX google.com
  ```
  Update DNS servers if needed:
  ```bash
  echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
  ```
- **Conda Interference**:
  Disable Conda auto-activation:
  ```bash
  conda config --set auto_activate_base false
  source ~/.zshrc
  ```

## License

MIT License. See [LICENSE](LICENSE) for details.
