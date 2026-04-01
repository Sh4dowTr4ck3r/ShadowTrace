# ShadowTrace

ShadowTrace is a terminal-based OSINT toolkit for digital investigations and cyber reconnaissance.

Current release includes 12 main modules plus report export and API key configuration.

## Main Menu Modules

| Option | Module | Purpose |
|---|---|---|
| 1 | Username Recon | Check a username across common social and developer platforms |
| 2 | Username Permutation Engine | Generate username variants and scan them |
| 3 | Email Intelligence | Gravatar checks, breach checks, disposable detection |
| 4 | IP Intelligence | GeoIP, reverse DNS, abuse intel, Shodan/VT when keys exist |
| 5 | Domain Reconnaissance | DNS, cert transparency, subdomains, WHOIS/RDAP, Wayback |
| 6 | WiFi Network Recon | Inspect nearby WiFi network details and enrichment |
| 7 | Image Metadata / EXIF | Extract image metadata, EXIF tags, and GPS coordinates |
| 8 | MAC Address Lookup | Vendor lookup and address-type checks |
| 9 | Email Header Analyzer | Parse raw headers or .eml/.txt files |
| 10 | Google Dork Generator | Generate targeted dork queries |
| 11 | Export Report | Save findings to JSON/HTML/CSV |
| 12 | Configure API Keys | Store API keys in local config |
| 0 | Exit | Quit ShadowTrace |

## Installation

### 1. Create and activate a virtual environment (recommended)

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Run

```powershell
python .\shadowtrace.py
```

If your system has multiple Python installations, make sure you run with the same interpreter where dependencies are installed.

## Dependencies

- `requests` (required)
- `Pillow` (recommended for full image metadata/EXIF support in option 7)

## API Keys (Optional)

ShadowTrace works without API keys, but enrichment improves with:

- Shodan
- HIBP
- AbuseIPDB
- VirusTotal

You can configure keys in two ways:

1. From menu option 12 (Configure API Keys)
2. By editing `ShadowTrace_config.json` manually

Example config:

```json
{
	"api_keys": {
		"shodan": "YOUR_KEY",
		"hibp": "YOUR_KEY",
		"abuseipdb": "YOUR_KEY",
		"virustotal": "YOUR_KEY"
	},
	"output_dir": "reports",
	"timeout": 10,
	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
}
```

Key notes:

- `ShadowTrace_config.json` is the runtime config file for API keys and app settings
- Keep this file private (it can contain secrets)
- If `hibp` is missing, email breach checks fall back to manual lookup links

Where to get API keys:

- Shodan: https://shodan.io
- HIBP: https://haveibeenpwned.com/API/Key
- AbuseIPDB: https://www.abuseipdb.com
- VirusTotal: https://www.virustotal.com

## Testing

```powershell
python .\test_shadowtrace.py
```



