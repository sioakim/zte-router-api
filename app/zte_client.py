"""
ZTE F8648P Router API Client

Lightweight Python client for ZTE GPON routers.
Uses SHA256 token-based authentication (not RSA as the web UI suggests).
"""

import hashlib
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Any, Optional
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener


@dataclass
class PONData:
    """PON optical module data"""
    onu_state: Optional[str] = None
    rx_power_dbm: Optional[float] = None
    tx_power_dbm: Optional[float] = None
    voltage_mv: Optional[int] = None
    current_ma: Optional[float] = None
    temperature_c: Optional[float] = None
    video_rx_power_dbm: Optional[float] = None
    rf_tx_power_dbm: Optional[float] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class DeviceInfo:
    """Device information"""
    model: Optional[str] = None
    serial_number: Optional[str] = None
    hardware_version: Optional[str] = None
    software_version: Optional[str] = None
    boot_version: Optional[str] = None
    manufacturer: Optional[str] = None
    oui: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class LANPort:
    """LAN port status"""
    name: str
    link: str
    speed: Optional[int] = None
    duplex: Optional[str] = None
    bytes_rx: Optional[int] = None
    bytes_tx: Optional[int] = None
    packets_rx: Optional[int] = None
    packets_tx: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class WANConnection:
    """WAN connection info"""
    name: Optional[str] = None
    connection_type: Optional[str] = None
    ip_address: Optional[str] = None
    gateway: Optional[str] = None
    dns_servers: Optional[list] = None
    status: Optional[str] = None
    tx_bytes: Optional[int] = None
    rx_bytes: Optional[int] = None
    vlan_id: Optional[int] = None
    mac_address: Optional[str] = None

    def to_dict(self) -> dict:
        result = {k: v for k, v in self.__dict__.items() if v is not None}
        return result


@dataclass
class ConnectedDevice:
    """Connected device info"""
    ip_address: str
    mac_address: str
    interface: Optional[str] = None
    hostname: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class VoIPLine:
    """VoIP line status"""
    line_id: str
    number: Optional[str] = None
    status: Optional[str] = None
    registered: bool = False

    def to_dict(self) -> dict:
        return self.__dict__


class ZTEClientError(Exception):
    """ZTE client error"""
    pass


class ZTEAuthenticationError(ZTEClientError):
    """Authentication failed"""
    pass


class ZTESessionError(ZTEClientError):
    """Session expired or invalid"""
    pass


class ZTEClient:
    """
    ZTE F8648P Router API Client

    Provides access to router data via the internal web API.
    Handles SHA256 token-based authentication automatically.
    """

    # ONU state mapping
    ONU_STATES = {
        1: "Initial State (O1)",
        2: "Standby State (O2)",
        3: "Serial Number State (O3)",
        4: "Ranging State (O4)",
        5: "Operation State (O5)",
    }

    def __init__(self, host: str, username: str = "admin", password: str = "admin", timeout: int = 10):
        """
        Initialize ZTE client.

        Args:
            host: Router IP address or hostname
            username: Login username (default: admin)
            password: Login password
            timeout: Request timeout in seconds
        """
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.base_url = f"http://{host}"
        self.session_token: Optional[str] = None
        self._logged_in = False

        # Setup cookie-enabled opener
        self.cookie_jar = CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))

    @property
    def is_logged_in(self) -> bool:
        """Check if currently logged in"""
        return self._logged_in

    def _request(self, path: str, method: str = "GET", data: dict = None) -> Optional[str]:
        """Make HTTP request with cookies"""
        url = f"{self.base_url}{path}"

        if data and method == "POST":
            encoded_data = urlencode(data).encode('utf-8')
            req = Request(url, data=encoded_data, method=method)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        else:
            req = Request(url, method=method)

        req.add_header("User-Agent", "ZTE-API-Client/1.0")
        req.add_header("Referer", self.base_url)
        req.add_header("Accept", "application/xml, text/xml, */*")

        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                return response.read().decode('utf-8')
        except Exception as e:
            raise ZTEClientError(f"Request failed: {e}")

    def _get_timestamp(self) -> int:
        """Get cache-busting timestamp"""
        return int(time.time() * 1000)

    def _load_view(self, view_tag: str) -> bool:
        """
        Load a menuView (required before fetching menuData).

        The ZTE router requires loading the view template before
        data can be fetched for that section.
        """
        ts = self._get_timestamp()
        try:
            response = self._request(f"/?_type=menuView&_tag={view_tag}&Menu3Location=0&_={ts}")
            return response is not None and "SessionTimeout" not in response
        except ZTEClientError:
            return False

    def _parse_xml_params(self, xml_data: str, patterns: dict) -> dict:
        """Parse XML data using ParaName/ParaValue pattern"""
        result = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, xml_data)
            if match:
                value = match.group(1).strip()
                # Try to convert to number
                try:
                    if '.' in value:
                        result[key] = float(value)
                    else:
                        result[key] = int(value)
                except ValueError:
                    result[key] = value
        return result

    def login(self) -> bool:
        """
        Login to ZTE router using SHA256 token authentication.

        Flow:
        1. GET login_entry to get session token
        2. GET login_token to get salt for SHA256
        3. POST login_entry with SHA256(password + salt)

        Returns:
            True if login successful

        Raises:
            ZTEAuthenticationError: If login fails
        """
        # Step 1: Get initial session token
        try:
            response = self._request("/?_type=loginData&_tag=login_entry")
        except ZTEClientError as e:
            raise ZTEAuthenticationError(f"Failed to connect: {e}")

        if not response:
            raise ZTEAuthenticationError("Failed to get initial session")

        try:
            import json
            data = json.loads(response)
            self.session_token = data.get("sess_token", "")

            # Check if locked out
            if data.get("lockingTime", 0) > 0:
                raise ZTEAuthenticationError(
                    f"Login locked. Wait {data['lockingTime']} seconds."
                )

        except json.JSONDecodeError:
            raise ZTEAuthenticationError("Failed to parse session response")

        # Step 2: Get login token (salt for SHA256)
        try:
            token_response = self._request("/?_type=loginData&_tag=login_token")
        except ZTEClientError as e:
            raise ZTEAuthenticationError(f"Failed to get login token: {e}")

        if not token_response:
            raise ZTEAuthenticationError("Failed to get login token")

        # Parse XML to extract token
        try:
            root = ET.fromstring(token_response)
            login_token = root.text.strip() if root.text else ""
        except ET.ParseError:
            match = re.search(r'>([^<]+)<', token_response)
            login_token = match.group(1) if match else ""

        if not login_token:
            raise ZTEAuthenticationError("Failed to extract login token")

        # Step 3: Compute SHA256(password + token) and login
        password_hash = hashlib.sha256(
            (self.password + login_token).encode()
        ).hexdigest()

        login_data = {
            "action": "login",
            "Username": self.username,
            "Password": password_hash,
            "_sessionTOKEN": self.session_token
        }

        try:
            login_response = self._request(
                "/?_type=loginData&_tag=login_entry", "POST", login_data
            )
        except ZTEClientError as e:
            raise ZTEAuthenticationError(f"Login request failed: {e}")

        if not login_response:
            raise ZTEAuthenticationError("Login request failed")

        try:
            import json
            result = json.loads(login_response)
            self.session_token = result.get("sess_token", self.session_token)

            if result.get("login_need_refresh"):
                self._logged_in = True
                return True
            else:
                error_msg = result.get("loginErrMsg", "Unknown error")
                raise ZTEAuthenticationError(f"Login failed: {error_msg}")

        except json.JSONDecodeError:
            raise ZTEAuthenticationError("Failed to parse login response")

    def logout(self) -> bool:
        """Logout from the router"""
        if not self._logged_in:
            return True

        try:
            self._request(
                "/?_type=loginData&_tag=logout_entry",
                "POST",
                {"IF_LogOff": 1, "_sessionTOKEN": self.session_token}
            )
            self._logged_in = False
            return True
        except ZTEClientError:
            return False

    def get_pon_data(self) -> PONData:
        """
        Fetch PON optical module data.

        Returns:
            PONData object with optical parameters

        Raises:
            ZTESessionError: If session is invalid
        """
        if not self._load_view("ponopticalinfo"):
            raise ZTESessionError("Failed to load PON view")

        ts = self._get_timestamp()
        response = self._request(f"/?_type=menuData&_tag=optical_info_lua.lua&_={ts}")

        if not response:
            raise ZTEClientError("Failed to fetch PON data")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        patterns = {
            "rx_power": r"<ParaName>RxPower</ParaName><ParaValue>([^<]+)</ParaValue>",
            "tx_power": r"<ParaName>TxPower</ParaName><ParaValue>([^<]+)</ParaValue>",
            "voltage": r"<ParaName>Volt</ParaName><ParaValue>([^<]+)</ParaValue>",
            "current": r"<ParaName>Current</ParaName><ParaValue>([^<]+)</ParaValue>",
            "temperature": r"<ParaName>Temp</ParaName><ParaValue>([^<]+)</ParaValue>",
            "reg_status": r"<ParaName>RegStatus</ParaName><ParaValue>([^<]+)</ParaValue>",
            "video_rx": r"<ParaName>VideoRxPower</ParaName><ParaValue>([^<]+)</ParaValue>",
            "rf_tx": r"<ParaName>RFTxPower</ParaName><ParaValue>([^<]+)</ParaValue>",
        }

        data = self._parse_xml_params(response, patterns)

        # Convert reg_status to human-readable state
        reg_status = data.get("reg_status")
        onu_state = None
        if isinstance(reg_status, int):
            onu_state = self.ONU_STATES.get(reg_status, f"Unknown ({reg_status})")

        return PONData(
            onu_state=onu_state,
            rx_power_dbm=data.get("rx_power"),
            tx_power_dbm=data.get("tx_power"),
            voltage_mv=data.get("voltage"),
            current_ma=data.get("current"),
            temperature_c=data.get("temperature"),
            video_rx_power_dbm=data.get("video_rx"),
            rf_tx_power_dbm=data.get("rf_tx"),
        )

    def get_device_info(self) -> DeviceInfo:
        """
        Fetch device information.

        Returns:
            DeviceInfo object with device details
        """
        if not self._load_view("statusMgr"):
            raise ZTESessionError("Failed to load status view")

        ts = self._get_timestamp()
        response = self._request(f"/?_type=menuData&_tag=devmgr_statusmgr_lua.lua&_={ts}")

        if not response:
            raise ZTEClientError("Failed to fetch device info")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        patterns = {
            "model": r"<ParaName>ModelName</ParaName><ParaValue>([^<]+)</ParaValue>",
            "serial": r"<ParaName>SerialNumber</ParaName><ParaValue>([^<]+)</ParaValue>",
            "hw_ver": r"<ParaName>HardwareVer</ParaName><ParaValue>([^<]+)</ParaValue>",
            "sw_ver": r"<ParaName>SoftwareVer</ParaName><ParaValue>([^<]+)</ParaValue>",
            "boot_ver": r"<ParaName>BootVer</ParaName><ParaValue>([^<]+)</ParaValue>",
            "manufacturer": r"<ParaName>ManuFacturer</ParaName><ParaValue>([^<]+)</ParaValue>",
            "oui": r"<ParaName>ManuFacturerOui</ParaName><ParaValue>([^<]+)</ParaValue>",
        }

        data = self._parse_xml_params(response, patterns)

        return DeviceInfo(
            model=data.get("model"),
            serial_number=data.get("serial"),
            hardware_version=data.get("hw_ver"),
            software_version=data.get("sw_ver"),
            boot_version=data.get("boot_ver"),
            manufacturer=data.get("manufacturer"),
            oui=data.get("oui"),
        )

    def get_lan_status(self) -> list[LANPort]:
        """
        Fetch LAN port status.

        Returns:
            List of LANPort objects
        """
        if not self._load_view("localNetStatus"):
            raise ZTESessionError("Failed to load LAN status view")

        ts = self._get_timestamp()
        response = self._request(f"/?_type=menuData&_tag=status_lan_info_lua.lua&_={ts}")

        if not response:
            raise ZTEClientError("Failed to fetch LAN status")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        ports = []
        instances = re.findall(r'<Instance>(.*?)</Instance>', response, re.DOTALL)

        for instance in instances:
            patterns = {
                "id": r"<ParaName>_InstID</ParaName><ParaValue>([^<]+)</ParaValue>",
                "status": r"<ParaName>Status</ParaName><ParaValue>([^<]+)</ParaValue>",
                "speed": r"<ParaName>Speed</ParaName><ParaValue>([^<]+)</ParaValue>",
                "duplex": r"<ParaName>Duplex</ParaName><ParaValue>([^<]+)</ParaValue>",
                "bytes_rx": r"<ParaName>InBytes</ParaName><ParaValue>([^<]+)</ParaValue>",
                "bytes_tx": r"<ParaName>OutBytes</ParaName><ParaValue>([^<]+)</ParaValue>",
                "packets_rx": r"<ParaName>InPkts</ParaName><ParaValue>([^<]+)</ParaValue>",
                "packets_tx": r"<ParaName>OutPkts</ParaName><ParaValue>([^<]+)</ParaValue>",
            }

            data = self._parse_xml_params(instance, patterns)

            if data.get("id"):
                # Convert ID to friendly name
                port_id = data["id"]
                match = re.search(r'IF(\d+)', port_id)
                name = f"LAN{match.group(1)}" if match else port_id

                # Status: 0=Up, 1=Down
                link = "Up" if data.get("status") == 0 else "Down"

                ports.append(LANPort(
                    name=name,
                    link=link,
                    speed=data.get("speed"),
                    duplex=data.get("duplex"),
                    bytes_rx=data.get("bytes_rx"),
                    bytes_tx=data.get("bytes_tx"),
                    packets_rx=data.get("packets_rx"),
                    packets_tx=data.get("packets_tx"),
                ))

        return ports

    def get_voip_status(self) -> list[VoIPLine]:
        """
        Fetch VoIP line status.

        Returns:
            List of VoIPLine objects
        """
        if not self._load_view("voipStatus"):
            raise ZTESessionError("Failed to load VoIP status view")

        ts = self._get_timestamp()
        response = self._request(f"/?_type=menuData&_tag=voipRegStatus_lua.lua&_={ts}")

        if not response:
            raise ZTEClientError("Failed to fetch VoIP status")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        lines = []
        instances = re.findall(r'<Instance>(.*?)</Instance>', response, re.DOTALL)

        for i, instance in enumerate(instances, 1):
            patterns = {
                "number": r"<ParaName>DirectoryNumber</ParaName><ParaValue>([^<]+)</ParaValue>",
                "status": r"<ParaName>IsOnline</ParaName><ParaValue>([^<]+)</ParaValue>",
            }

            data = self._parse_xml_params(instance, patterns)

            number = data.get("number", "")
            # Ensure number is a string (parser may convert to int)
            if number:
                number = str(number)
            is_online = data.get("status") == 1

            # Determine status string
            if not number or number == "":
                status = "Inactive"
            elif is_online:
                status = "Registered"
            else:
                status = "Unregistered"

            lines.append(VoIPLine(
                line_id=f"Line{i}",
                number=number if number else None,
                status=status,
                registered=is_online,
            ))

        return lines

    def get_wan_status(self) -> list[WANConnection]:
        """
        Fetch WAN connection status.

        Returns:
            List of WANConnection objects
        """
        if not self._load_view("ethWanConfig"):
            raise ZTESessionError("Failed to load WAN status view")

        ts = self._get_timestamp()
        response = self._request(
            f"/?_type=menuData&_tag=wan_internet_lua.lua&TypeUplink=2&pageType=0&_={ts}"
        )

        if not response:
            raise ZTEClientError("Failed to fetch WAN status")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        connections = []
        instances = re.findall(r'<Instance>(.*?)</Instance>', response, re.DOTALL)

        for instance in instances:
            patterns = {
                "name": r"<ParaName>WANCName</ParaName><ParaValue>([^<]+)</ParaValue>",
                "type": r"<ParaName>TransType</ParaName><ParaValue>([^<]+)</ParaValue>",
                "mode": r"<ParaName>mode</ParaName><ParaValue>([^<]+)</ParaValue>",
                "vlan_id": r"<ParaName>VLANID</ParaName><ParaValue>([^<]+)</ParaValue>",
                "mac": r"<ParaName>WorkIFMac</ParaName><ParaValue>([^<]+)</ParaValue>",
                "mtu": r"<ParaName>MTU</ParaName><ParaValue>([^<]+)</ParaValue>",
                "tx_bytes": r"<ParaName>TxBytes</ParaName><ParaValue>([^<]+)</ParaValue>",
                "rx_bytes": r"<ParaName>RxBytes</ParaName><ParaValue>([^<]+)</ParaValue>",
                "tx_packets": r"<ParaName>TxPackets</ParaName><ParaValue>([^<]+)</ParaValue>",
                "rx_packets": r"<ParaName>RxPackets</ParaName><ParaValue>([^<]+)</ParaValue>",
                "conn_error": r"<ParaName>ConnError</ParaName><ParaValue>([^<]+)</ParaValue>",
                "enabled": r"<ParaName>Enable</ParaName><ParaValue>([^<]+)</ParaValue>",
                "services": r"<ParaName>StrServList</ParaName><ParaValue>([^<]+)</ParaValue>",
            }

            data = self._parse_xml_params(instance, patterns)

            if data.get("name"):
                # Determine status from conn_error
                conn_error = data.get("conn_error", "")
                status = "Connected" if conn_error == "ERROR_NONE" else conn_error

                connections.append(WANConnection(
                    name=data.get("name"),
                    connection_type=data.get("type"),
                    ip_address=None,  # Not available in this endpoint
                    gateway=None,
                    status=status,
                    tx_bytes=data.get("tx_bytes"),
                    rx_bytes=data.get("rx_bytes"),
                    vlan_id=data.get("vlan_id"),
                    mac_address=data.get("mac"),
                ))

        return connections

    def get_system_stats(self) -> dict:
        """
        Fetch system statistics (CPU, memory usage, uptime).

        Returns:
            Dictionary with system stats
        """
        if not self._load_view("statusMgr"):
            raise ZTESessionError("Failed to load status view")

        ts = self._get_timestamp()
        response = self._request(f"/?_type=menuData&_tag=devmgr_statusmgr_lua.lua&_={ts}")

        if not response:
            raise ZTEClientError("Failed to fetch system stats")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        # Parse CPU usage (4 cores) and memory
        patterns = {
            "cpu1": r"<ParaName>CpuUsage1</ParaName><ParaValue>([^<]+)</ParaValue>",
            "cpu2": r"<ParaName>CpuUsage2</ParaName><ParaValue>([^<]+)</ParaValue>",
            "cpu3": r"<ParaName>CpuUsage3</ParaName><ParaValue>([^<]+)</ParaValue>",
            "cpu4": r"<ParaName>CpuUsage4</ParaName><ParaValue>([^<]+)</ParaValue>",
            "memory_usage": r"<ParaName>MemUsage</ParaName><ParaValue>([^<]+)</ParaValue>",
            "uptime_seconds": r"<ParaName>PowerOnTime</ParaName><ParaValue>([^<]+)</ParaValue>",
            "flash_used_percent": r"<ParaName>Flash_Percent_Used</ParaName><ParaValue>([^<]+)</ParaValue>",
        }

        data = self._parse_xml_params(response, patterns)

        # Calculate average CPU usage
        cpu_values = [data.get(f"cpu{i}") for i in range(1, 5) if data.get(f"cpu{i}") is not None]
        if cpu_values:
            data["cpu_usage"] = int(sum(cpu_values) / len(cpu_values))

        return data

    def get_connected_devices(self) -> list[ConnectedDevice]:
        """
        Fetch list of connected devices.

        Returns:
            List of ConnectedDevice objects
        """
        # Load homepage view first
        if not self._load_view("homePage"):
            raise ZTESessionError("Failed to load home page view")

        ts = self._get_timestamp()
        response = self._request(
            f"/?_type=menuData&_tag=accessdev_homepage_lua.lua&_={ts}"
        )

        if not response:
            raise ZTEClientError("Failed to fetch connected devices")

        if "SessionTimeout" in response:
            self._logged_in = False
            raise ZTESessionError("Session expired")

        devices = []
        instances = re.findall(r'<Instance>(.*?)</Instance>', response, re.DOTALL)

        for instance in instances:
            patterns = {
                "ip": r"<ParaName>IPAddress</ParaName><ParaValue>([^<]+)</ParaValue>",
                "mac": r"<ParaName>MACAddress</ParaName><ParaValue>([^<]+)</ParaValue>",
                "interface": r"<ParaName>AliasName</ParaName><ParaValue>([^<]+)</ParaValue>",
                "last_seen": r"<ParaName>LastConnection</ParaName><ParaValue>([^<]+)</ParaValue>",
            }

            data = self._parse_xml_params(instance, patterns)

            if data.get("ip") and data.get("mac"):
                # Clean up HTML entities in last_seen
                last_seen = data.get("last_seen", "")
                if last_seen:
                    last_seen = last_seen.replace("&#32;", " ")

                devices.append(ConnectedDevice(
                    ip_address=str(data.get("ip")),
                    mac_address=str(data.get("mac")),
                    interface=data.get("interface"),
                    last_seen=last_seen if last_seen else None,
                ))

        return devices

    def __enter__(self):
        """Context manager entry"""
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.logout()
        return False
