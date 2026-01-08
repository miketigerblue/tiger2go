# tigerfetch

A high-performance OSINT vulnerability ingestor written in Go. `tigerfetch` aggregates security advisories from RSS/Atom feeds, enriches them with official CVE data from NVD (National Vulnerability Database), tracks CISA KEV (Known Exploited Vulnerabilities), and monitors daily EPSS (Exploit Prediction Scoring System) scores.

## Features

- **RSS/Atom Feed Aggregation**: Automatically fetch security advisories from multiple RSS and Atom feeds
- **CVE Enrichment**: Enrich advisories with detailed CVE information from the NVD API
- **CISA KEV Integration**: Identify vulnerabilities in the CISA Known Exploited Vulnerabilities catalog
- **EPSS Tracking**: Monitor exploit prediction scores to prioritize vulnerabilities
- **High Performance**: Built in Go for speed and efficiency
- **Configurable**: JSON-based configuration for feeds and API settings
- **Data Persistence**: Store raw and enriched data in JSON format for analysis
- **Flexible Output**: Support for both human-readable and JSON output

## Installation

### Prerequisites

- Go 1.19 or higher

### Build from Source

```bash
git clone https://github.com/miketigerblue/tiger2go.git
cd tiger2go
go build -o tigerfetch ./cmd/tigerfetch
```

## Usage

### Initialize Configuration

Create a default configuration file:

```bash
./tigerfetch -init
```

This creates a `config.json` file with default settings.

### Basic Usage

Fetch and enrich security advisories:

```bash
./tigerfetch
```

### Command Line Options

```
-config string
    Path to configuration file (default "config.json")
-debug
    Enable debug logging
-init
    Initialize default configuration file
-version
    Show version information
-fetch-only
    Only fetch advisories without enrichment
-enrich-only
    Only enrich existing advisories
-json
    Output results as JSON
```

### Examples

Fetch advisories without enrichment:
```bash
./tigerfetch -fetch-only
```

Enrich existing advisories:
```bash
./tigerfetch -enrich-only
```

Output as JSON:
```bash
./tigerfetch -json
```

Enable debug logging:
```bash
./tigerfetch -debug
```

## Configuration

The `config.json` file allows you to customize feeds and API settings:

```json
{
  "feeds": [
    {
      "name": "NVD",
      "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
      "enabled": true
    },
    {
      "name": "CISA",
      "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
      "enabled": true
    }
  ],
  "nvd": {
    "api_key": "",
    "rate_limit_ms": 6000
  },
  "storage": {
    "data_dir": "./data"
  },
  "http": {
    "timeout_seconds": 30
  }
}
```

### Configuration Options

- **feeds**: List of RSS/Atom feeds to monitor
  - `name`: Friendly name for the feed
  - `url`: Feed URL
  - `enabled`: Whether to fetch this feed
- **nvd**: NVD API configuration
  - `api_key`: Optional NVD API key for higher rate limits
  - `rate_limit_ms`: Milliseconds between API requests (6000ms = 10 req/min without API key)
- **storage**: Data storage settings
  - `data_dir`: Directory to store fetched and enriched data
- **http**: HTTP client settings
  - `timeout_seconds`: Request timeout in seconds

### Getting an NVD API Key

To get higher rate limits, request an API key from NVD:
https://nvd.nist.gov/developers/request-an-api-key

With an API key, you can make 50 requests per 30 seconds instead of 5.

## Data Sources

### RSS/Atom Feeds

tigerfetch can parse both RSS 2.0 and Atom feeds. Common security advisory feeds include:

- NVD Recent CVE Feed
- CISA Cybersecurity Advisories
- Vendor-specific security bulletins
- Security research feeds

### NVD (National Vulnerability Database)

The NVD provides comprehensive CVE information including:
- Detailed vulnerability descriptions
- CVSS scores (v2, v3.0, v3.1)
- References and affected products
- Publication and modification dates

### CISA KEV (Known Exploited Vulnerabilities)

CISA maintains a catalog of vulnerabilities known to be actively exploited. tigerfetch identifies which CVEs appear in this catalog to help prioritize remediation.

### EPSS (Exploit Prediction Scoring System)

EPSS provides data-driven predictions of the likelihood that a vulnerability will be exploited. Scores range from 0 to 1 (0-100%), helping security teams prioritize patching efforts.

## Output

### File Output

Data is saved to the configured data directory with timestamps:

- `advisories_YYYY-MM-DD.json`: Raw advisories from feeds
- `enriched_advisories_YYYY-MM-DD.json`: Advisories with CVE, KEV, and EPSS data
- `cves_YYYY-MM-DD.json`: CVE details
- `kevs_YYYY-MM-DD.json`: CISA KEV catalog entries
- `epss_scores_YYYY-MM-DD.json`: EPSS scores

### Console Output

By default, tigerfetch provides a human-readable summary including:
- Number of advisories fetched
- CVE enrichment statistics
- Known exploited vulnerabilities (KEVs)
- Processing status and errors

Use the `-json` flag for machine-readable JSON output.

## Architecture

```
tigerfetch/
├── cmd/tigerfetch/         # Main application
├── pkg/
│   ├── models/            # Data models
│   ├── feeds/             # RSS/Atom feed parser
│   ├── nvd/               # NVD API client
│   ├── cisa/              # CISA KEV API client
│   ├── epss/              # EPSS API client
│   ├── storage/           # Data persistence
│   └── config/            # Configuration management
└── internal/
    └── logger/            # Logging utilities
```

## Development

### Running Tests

```bash
go test ./...
```

### Building

```bash
go build -o tigerfetch ./cmd/tigerfetch
```

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
