# Hopkins TS Lab – Device Table Viewer

A local web viewer for the device table stored in Confluence. Fetches the table, displays it with an intuitive UI, and provides network utilities like ping checks and port scanning.

## Features

- **Live Confluence Sync**: Fetches and displays the device table from Confluence
- **Dark/Light Mode**: Toggle between dark and light themes
- **Real-time Search**: Filter devices by name, IP, MAC address, or location
- **Ping Status**: Check device availability with inline ping indicators
- **Port Scanning**: Run nmap scans on any device IP to see open ports
- **Click-to-Copy**: Copy IPs and MAC addresses with a single click
- **Auto-Refresh**: Automatically re-check device status every 30 seconds
- **Responsive Design**: Works on desktop and mobile devices

## Prerequisites

- Python 3.7+
- Atlassian Cloud API credentials (email and API token)
- `nmap` installed (for port scanning feature)
- Network access to Confluence and target devices

## Installation

1. Clone or download this repository
2. Install Python dependencies:
   ```bash
   pip install requests
   ```
3. Set up your Atlassian credentials

## Configuration

### Using Environment Variables

Create `/etc/a-app.env` (or modify the `ENV_FILE` path in the script):
```
ATLASSIAN_EMAIL=your-email@example.com
ATLASSIAN_API_TOKEN=your-api-token
```

Or set environment variables directly:
```bash
export ATLASSIAN_EMAIL=your-email@example.com
export ATLASSIAN_API_TOKEN=your-api-token
```

### Configuration Options

Edit these constants at the top of `a.py`:
- `CONFLUENCE_BASE`: Base URL for your Confluence instance
- `PAGE_ID`: The Confluence page ID containing your device table
- `PORT`: Local port to serve on (default: 8080)
- `PING_TIMEOUT_MS`: Ping timeout in milliseconds (default: 800)
- `SCAN_HOST_TIMEOUT`: nmap timeout per host (default: 90s)

## Usage

Run the application:
```bash
python a.py
```

Output:
```
⏳  Fetching page from Confluence…
✅  Table extracted successfully.
🌐  Serving at  http://localhost:8080
    Press Ctrl+C to stop.
```

Open your browser and navigate to:
```
http://localhost:8080
```

## Features in Detail

### Filtering
Type in the search box to filter devices by any field (device name, IP address, MAC address, location, etc.)

### Status Checking
- Green dot (●) = Device is online
- Red dot (●) = Device is offline
- Orange dot (●) = Status is being checked
- Click any dot to manually re-check that device

### Port Scanning
Click the **nmap** button next to any IP address to scan the top 1000 TCP ports. Results show open ports and their associated services.

### Refresh Data
Use the **Refresh data** button to re-fetch the table from Confluence. Use **Check status** to re-ping all devices.

## Requirements

- **Python packages**: `requests`
- **System tools**: `nmap` (for port scanning)

## Architecture

The application consists of:
- **Backend**: Simple HTTP server that serves the page and handles API requests
  - `GET /` – Serves the main HTML page
  - `GET /ping?ip=<addr>` – Checks if a device is online
  - `GET /scan?ip=<addr>` – Runs an nmap TCP connect scan
  - `POST /refresh` – Fetches latest data from Confluence
- **Frontend**: Responsive single-page application with:
  - Real-time filtering
  - Dark/light mode toggle
  - Matrix rain background effect (subtle, themed)
  - Live status indicators and modals

## Security Notes

- API credentials should be stored securely (use environment files, not hardcoded)
- Port scans are restricted to valid IPv4 addresses
- The application validates all inputs before passing to system commands
- Uses HTTP basic authentication with Confluence API

## Troubleshooting

### "Error fetching page"
- Check your Atlassian email and API token
- Verify the Confluence page ID is correct
- Ensure you have access to that page

### Ping shows all devices as offline
- Check network connectivity
- Verify devices are reachable from your network
- Some devices may not respond to ping (try port scan instead)

### nmap command not found
- Install nmap:
  - **Linux**: `sudo apt install nmap` or `sudo yum install nmap`
  - **macOS**: `brew install nmap`
  - **Windows**: Download from [nmap.org](https://nmap.org/download.html)

## License

© Hopkins TS Lab. All rights reserved.
