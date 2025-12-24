# ZTE Fiber Dashboard Example

A simple real-time dashboard displaying PON optical metrics and LAN port status from your ZTE F8648P router.

## Features

- **PON Optical Metrics**: RX/TX power, temperature, voltage, bias current
- **LAN Port Status**: Link state, speed, traffic counters
- **System Info**: Firmware version, uptime, CPU/RAM usage
- **Auto-refresh**: Updates every 30 seconds
- **Alert Thresholds**: Color-coded warnings for signal degradation

## Quick Start

### Using Docker Compose (Recommended)

1. Create a `.env` file with your router credentials:
   ```bash
   ZTE_HOST=192.168.178.1
   ZTE_USERNAME=admin
   ZTE_PASSWORD=your_password
   ```

2. Start the services:
   ```bash
   docker compose up -d
   ```

3. Open the dashboard: http://localhost:8080

### Running Standalone

If you already have the ZTE API server running:

1. Start the dashboard server:
   ```bash
   export ZTE_API_URL=http://your-zte-api-server:8000
   python3 server.py
   ```

2. Open: http://localhost:8080

### Using Docker Only

```bash
# Build the dashboard image
docker build -t zte-dashboard .

# Run with your existing ZTE API server
docker run -d \
  --name zte-dashboard \
  -p 8080:8080 \
  -e ZTE_API_URL=http://your-zte-api:8000 \
  zte-dashboard
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | `8080` | Dashboard server port |
| `ZTE_API_URL` | `http://localhost:8000` | ZTE API server URL |

## API Endpoints (Proxied)

The dashboard proxies these endpoints from the ZTE API server:

| Endpoint | Description |
|----------|-------------|
| `/api/pon` | PON optical data |
| `/api/lan` | LAN port status |
| `/api/device` | Device information |
| `/api/system/stats` | System statistics |

## Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| RX Power | < -25 dBm | < -27 dBm |
| Temperature | > 70°C | > 80°C |

## Screenshot

The dashboard displays:
- Device info (model, firmware, uptime)
- PON optical module metrics in a grid
- LAN ports with link status and traffic stats

## Customization

Edit `index.html` to customize:
- Colors (CSS variables in `:root`)
- Refresh interval (default: 30 seconds)
- Alert thresholds
- Layout and styling
