# ZTE F8648P Router API Server

A lightweight RESTful API server for ZTE F8648P GPON fiber routers. Provides programmatic access to router status, PON optical data, network configuration, and more.

## Features

- **PON Optical Data** - RX/TX power, temperature, voltage, bias current
- **Device Information** - Model, firmware, serial number, hardware version
- **LAN Port Status** - Link state, speed, duplex, traffic counters
- **VoIP Status** - Line registration status for all configured lines
- **WAN Status** - Connection type, status, VLAN, traffic counters
- **System Stats** - CPU usage, memory usage, uptime, flash storage
- **Connected Devices** - List of devices connected to the router
- **OpenAPI/Swagger** - Full interactive API documentation

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/zte-api-server.git
   cd zte-api-server
   ```

2. Create your environment file:
   ```bash
   cp .env.example .env
   # Edit .env with your router credentials
   ```

3. Start the server:
   ```bash
   docker compose up -d
   ```

4. Access the API:
   - API: http://localhost:8000
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### Using Docker

```bash
docker build -t zte-api-server .

docker run -d \
  --name zte-api \
  -p 8000:8000 \
  -e ZTE_HOST=192.168.178.1 \
  -e ZTE_USERNAME=admin \
  -e ZTE_PASSWORD=your_password \
  zte-api-server
```

### Running Locally

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables:
   ```bash
   export ZTE_HOST=192.168.178.1
   export ZTE_USERNAME=admin
   export ZTE_PASSWORD=your_password
   ```

3. Run the server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ZTE_HOST` | `192.168.178.1` | Router IP address |
| `ZTE_USERNAME` | `admin` | Router username |
| `ZTE_PASSWORD` | `admin` | Router password |
| `ZTE_TIMEOUT` | `10` | Request timeout in seconds |

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | Authenticate with the router |
| POST | `/logout` | End the router session |

### Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check and router connectivity |
| GET | `/status` | Full router status (all data) |

### PON

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/pon` | PON optical module data |

**Response Example:**
```json
{
  "onu_state": "Operation State (O5)",
  "rx_power_dbm": -14.78,
  "tx_power_dbm": 6.02,
  "voltage_mv": 3218,
  "current_ma": 35.48,
  "temperature_c": 52.57
}
```

### Device

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/device` | Device information |

**Response Example:**
```json
{
  "model": "F8648P",
  "serial_number": "ZTEXXXXXXXXXXX",
  "hardware_version": "V2.0",
  "software_version": "V2.0.12P1N15H",
  "boot_version": "V2.0.12P10N5",
  "manufacturer": "ZTE"
}
```

### Network

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/lan` | LAN port status |
| GET | `/wan` | WAN connection status |
| GET | `/devices` | Connected devices list |

**WAN Response Example:**
```json
{
  "name": "Cosmote_Internet",
  "connection_type": "PPPoE",
  "status": "Connected",
  "tx_bytes": 273744815,
  "rx_bytes": 1146284273,
  "vlan_id": 835,
  "mac_address": "00:11:22:33:44:55"
}
```

**Connected Devices Response Example:**
```json
[
  {
    "ip_address": "192.168.178.200",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "interface": "LAN1",
    "last_seen": "2025-12-24 09:17:49"
  }
]
```

### VoIP

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/voip` | VoIP line registration status |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/system/stats` | CPU, memory, uptime, storage stats |

**System Stats Response Example:**
```json
{
  "cpu_usage": 1,
  "memory_usage": 62,
  "uptime_seconds": 3022841,
  "flash_used_percent": 71
}
```

## Usage Examples

### curl

```bash
# Get PON optical data
curl http://localhost:8000/pon

# Get full status (all data in one request)
curl http://localhost:8000/status

# Get system stats (CPU, memory, uptime)
curl http://localhost:8000/system/stats

# Get connected devices
curl http://localhost:8000/devices

# Get WAN connection info
curl http://localhost:8000/wan

# Login first (if needed)
curl -X POST http://localhost:8000/login
```

### Python

```python
import requests

BASE_URL = "http://localhost:8000"

# Login
requests.post(f"{BASE_URL}/login")

# Get PON data
pon = requests.get(f"{BASE_URL}/pon").json()
print(f"RX Power: {pon['rx_power_dbm']} dBm")
print(f"TX Power: {pon['tx_power_dbm']} dBm")

# Get system stats
stats = requests.get(f"{BASE_URL}/system/stats").json()
print(f"CPU: {stats['cpu_usage']}%, Memory: {stats['memory_usage']}%")
print(f"Uptime: {stats['uptime_seconds'] // 86400} days")

# Get connected devices
devices = requests.get(f"{BASE_URL}/devices").json()
for device in devices:
    print(f"Device: {device['ip_address']} on {device['interface']}")

# Get full status (all data in one request)
status = requests.get(f"{BASE_URL}/status").json()
print(f"Device: {status['device']['model']}")
print(f"WAN: {status['wan'][0]['status'] if status['wan'] else 'N/A'}")
```

### JavaScript

```javascript
const BASE_URL = 'http://localhost:8000';

// Get PON data
const response = await fetch(`${BASE_URL}/pon`);
const ponData = await response.json();
console.log(`RX Power: ${ponData.rx_power_dbm} dBm`);
```

## Technical Details

### Authentication

The ZTE F8648P uses SHA256 token-based authentication:

1. Client requests a login token from the router
2. Password is hashed: `SHA256(password + token)`
3. Hash is sent to router for authentication
4. Session is maintained via cookies

### API Notes

- The server handles router authentication automatically
- Sessions expire after inactivity; the server re-authenticates as needed
- Rate limiting may apply from the router side
- CORS is enabled for all origins (configurable in production)

### Router API Structure

The router uses XML-based responses with two main request types:
- `menuView` - Load page views (required before fetching data)
- `menuData` - Fetch actual data from Lua modules

## Health Monitoring

The Docker container includes a health check that verifies:
- API server is running
- Router connectivity status

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' zte-api
```

## Development

### Project Structure

```
zte-api-server/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI application
│   └── zte_client.py    # ZTE router client library
├── examples/
│   └── dashboard/       # Example dashboard application
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Examples

### Dashboard

A ready-to-use dashboard displaying PON optical metrics and LAN port status.

```bash
cd examples/dashboard

# Create .env with your router credentials
cp .env.example .env
# Edit .env with your settings

# Start with Docker Compose
docker compose up -d

# Open http://localhost:8080
```

See [examples/dashboard/README.md](examples/dashboard/README.md) for details.

### Running Tests

```bash
# Install dev dependencies
pip install pytest httpx

# Run tests
pytest
```

### Building Docker Image

```bash
docker build -t zte-api-server:latest .
```

## Troubleshooting

### "Router unavailable" error

- Verify the router IP is correct and reachable
- Check if another session is active on the router
- Wait a few minutes if rate limiting is active

### "Authentication failed" error

- Verify username and password
- Check if the account is locked due to failed attempts

### Session timeout errors

- The server automatically re-authenticates
- If persistent, restart the container

## License

MIT License

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Acknowledgments

- ZTE F8648P router API reverse-engineering community
- FastAPI framework
