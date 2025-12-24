"""
ZTE Router OpenAPI Server

RESTful API for ZTE F8648P GPON routers.
Provides programmatic access to router status and configuration.
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .zte_client import (
    ZTEClient,
    ZTEClientError,
    ZTEAuthenticationError,
    ZTESessionError,
    PONData,
    DeviceInfo,
    LANPort,
    VoIPLine,
    WANConnection,
    ConnectedDevice,
)


# Configuration from environment
ZTE_HOST = os.environ.get("ZTE_HOST", "192.168.178.1")
ZTE_USERNAME = os.environ.get("ZTE_USERNAME", "admin")
ZTE_PASSWORD = os.environ.get("ZTE_PASSWORD", "admin")
ZTE_TIMEOUT = int(os.environ.get("ZTE_TIMEOUT", "10"))

# Global client instance
_client: Optional[ZTEClient] = None


def get_client() -> ZTEClient:
    """Get or create ZTE client instance"""
    global _client
    if _client is None:
        _client = ZTEClient(
            host=ZTE_HOST,
            username=ZTE_USERNAME,
            password=ZTE_PASSWORD,
            timeout=ZTE_TIMEOUT,
        )
    return _client


def ensure_logged_in(client: ZTEClient = Depends(get_client)) -> ZTEClient:
    """Dependency to ensure client is logged in"""
    if not client.is_logged_in:
        try:
            client.login()
        except ZTEAuthenticationError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except ZTEClientError as e:
            raise HTTPException(status_code=503, detail=f"Router unavailable: {e}")
    return client


def with_session_retry(func):
    """Decorator to retry on session errors with fresh login"""
    def wrapper(client: ZTEClient):
        try:
            return func(client)
        except ZTESessionError:
            # Session expired, force re-login and retry once
            client._logged_in = False
            client.login()
            return func(client)
    return wrapper


# Pydantic models for API responses
class PONDataResponse(BaseModel):
    """PON optical module data"""
    onu_state: Optional[str] = Field(None, description="ONU registration state (O1-O5)")
    rx_power_dbm: Optional[float] = Field(None, description="Receive power in dBm")
    tx_power_dbm: Optional[float] = Field(None, description="Transmit power in dBm")
    voltage_mv: Optional[int] = Field(None, description="Supply voltage in mV")
    current_ma: Optional[float] = Field(None, description="Bias current in mA")
    temperature_c: Optional[float] = Field(None, description="Temperature in Celsius")
    video_rx_power_dbm: Optional[float] = Field(None, description="Video RX power in dBm")
    rf_tx_power_dbm: Optional[float] = Field(None, description="RF TX power in dBm")

    class Config:
        json_schema_extra = {
            "example": {
                "onu_state": "Operation State (O5)",
                "rx_power_dbm": -14.78,
                "tx_power_dbm": 6.02,
                "voltage_mv": 3218,
                "current_ma": 35.48,
                "temperature_c": 52.57
            }
        }


class DeviceInfoResponse(BaseModel):
    """Device information"""
    model: Optional[str] = Field(None, description="Device model name")
    serial_number: Optional[str] = Field(None, description="Serial number")
    hardware_version: Optional[str] = Field(None, description="Hardware version")
    software_version: Optional[str] = Field(None, description="Firmware version")
    boot_version: Optional[str] = Field(None, description="Bootloader version")
    manufacturer: Optional[str] = Field(None, description="Manufacturer name")
    oui: Optional[str] = Field(None, description="Manufacturer OUI")

    class Config:
        json_schema_extra = {
            "example": {
                "model": "F8648P",
                "serial_number": "ZTEXXXXXXXXXXX",
                "hardware_version": "V2.0",
                "software_version": "V2.0.12P1N15H",
                "boot_version": "V2.0.12P10N5",
                "manufacturer": "ZTE"
            }
        }


class LANPortResponse(BaseModel):
    """LAN port status"""
    name: str = Field(..., description="Port name (e.g., LAN1)")
    link: str = Field(..., description="Link status (Up/Down)")
    speed: Optional[int] = Field(None, description="Link speed in Mbps")
    duplex: Optional[str] = Field(None, description="Duplex mode (Full/Half)")
    bytes_rx: Optional[int] = Field(None, description="Bytes received")
    bytes_tx: Optional[int] = Field(None, description="Bytes transmitted")
    packets_rx: Optional[int] = Field(None, description="Packets received")
    packets_tx: Optional[int] = Field(None, description="Packets transmitted")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "LAN1",
                "link": "Up",
                "speed": 1000,
                "duplex": "Full",
                "bytes_rx": 39599654,
                "bytes_tx": 35090928
            }
        }


class VoIPLineResponse(BaseModel):
    """VoIP line status"""
    line_id: str = Field(..., description="Line identifier (e.g., Line1)")
    number: Optional[str] = Field(None, description="SIP URI or phone number")
    status: str = Field(..., description="Status (Registered/Unregistered/Inactive)")
    registered: bool = Field(..., description="Is line registered")

    class Config:
        json_schema_extra = {
            "example": {
                "line_id": "Line1",
                "number": "+30210XXXXXXX@ims.example.com",
                "status": "Registered",
                "registered": True
            }
        }


class WANConnectionResponse(BaseModel):
    """WAN connection status"""
    name: Optional[str] = Field(None, description="Connection name")
    connection_type: Optional[str] = Field(None, description="Connection type (PPPoE, DHCP, etc.)")
    status: Optional[str] = Field(None, description="Connection status")
    tx_bytes: Optional[int] = Field(None, description="Bytes transmitted")
    rx_bytes: Optional[int] = Field(None, description="Bytes received")
    vlan_id: Optional[int] = Field(None, description="VLAN ID")
    mac_address: Optional[str] = Field(None, description="WAN MAC address")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Cosmote_Internet",
                "connection_type": "PPPoE",
                "status": "Connected",
                "tx_bytes": 273744815,
                "rx_bytes": 1146284273,
                "vlan_id": 835,
                "mac_address": "00:11:22:33:44:55"
            }
        }


class SystemStatsResponse(BaseModel):
    """System statistics"""
    cpu_usage: Optional[int] = Field(None, description="Average CPU usage percentage")
    memory_usage: Optional[int] = Field(None, description="Memory usage percentage")
    uptime_seconds: Optional[int] = Field(None, description="System uptime in seconds")
    flash_used_percent: Optional[int] = Field(None, description="Flash storage used percentage")

    class Config:
        json_schema_extra = {
            "example": {
                "cpu_usage": 1,
                "memory_usage": 62,
                "uptime_seconds": 3022841,
                "flash_used_percent": 71
            }
        }


class ConnectedDeviceResponse(BaseModel):
    """Connected device info"""
    ip_address: str = Field(..., description="Device IP address")
    mac_address: str = Field(..., description="Device MAC address")
    interface: Optional[str] = Field(None, description="Connected interface (LAN1, etc.)")
    last_seen: Optional[str] = Field(None, description="Last connection time")

    class Config:
        json_schema_extra = {
            "example": {
                "ip_address": "192.168.178.200",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "interface": "LAN1",
                "last_seen": "2025-12-24 09:17:49"
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    router_connected: bool = Field(..., description="Router connectivity status")
    router_host: str = Field(..., description="Router IP/hostname")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "router_connected": True,
                "router_host": "192.168.178.1"
            }
        }


class LoginResponse(BaseModel):
    """Login response"""
    success: bool = Field(..., description="Login success status")
    message: str = Field(..., description="Status message")


class ErrorResponse(BaseModel):
    """Error response"""
    detail: str = Field(..., description="Error message")


# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    print(f"ZTE API Server starting...")
    print(f"Router: {ZTE_HOST}")
    yield
    # Shutdown
    global _client
    if _client and _client.is_logged_in:
        _client.logout()
    print("ZTE API Server stopped")


# FastAPI application
app = FastAPI(
    title="ZTE Router API",
    description="""
## ZTE F8648P GPON Router API

RESTful API for accessing ZTE F8648P fiber router data.

### Features
- **PON Optical Data**: RX/TX power, temperature, voltage, current
- **Device Information**: Model, firmware, serial number
- **LAN Port Status**: Link state, speed, traffic counters
- **VoIP Status**: Line registration status
- **WAN Status**: Connection info and IP addresses

### Authentication
The server handles router authentication automatically using credentials
configured via environment variables.

### Notes
- Rate limiting may apply from the router side
- Sessions expire after inactivity
""",
    version="1.0.0",
    lifespan=lifespan,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication failed"},
        503: {"model": ErrorResponse, "description": "Router unavailable"},
    },
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health endpoint
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health check",
    description="Check API server health and router connectivity",
)
async def health_check():
    """Health check endpoint"""
    client = get_client()
    return HealthResponse(
        status="healthy",
        router_connected=client.is_logged_in,
        router_host=ZTE_HOST,
    )


# Login endpoint
@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    summary="Login to router",
    description="Authenticate with the ZTE router",
)
async def login():
    """Login to router"""
    client = get_client()
    try:
        if client.is_logged_in:
            return LoginResponse(success=True, message="Already logged in")
        client.login()
        return LoginResponse(success=True, message="Login successful")
    except ZTEAuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=503, detail=str(e))


# Logout endpoint
@app.post(
    "/logout",
    response_model=LoginResponse,
    tags=["Authentication"],
    summary="Logout from router",
    description="End the session with the ZTE router",
)
async def logout():
    """Logout from router"""
    client = get_client()
    if client.logout():
        return LoginResponse(success=True, message="Logout successful")
    return LoginResponse(success=False, message="Logout failed")


# PON data endpoint
@app.get(
    "/pon",
    response_model=PONDataResponse,
    tags=["PON"],
    summary="Get PON optical data",
    description="Fetch PON optical module parameters including RX/TX power, temperature, voltage, and current",
)
async def get_pon_data(client: ZTEClient = Depends(ensure_logged_in)):
    """Get PON optical module data"""
    try:
        get_data = with_session_retry(lambda c: c.get_pon_data())
        data = get_data(client)
        return PONDataResponse(**data.to_dict())
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# Device info endpoint
@app.get(
    "/device",
    response_model=DeviceInfoResponse,
    tags=["Device"],
    summary="Get device information",
    description="Fetch device model, firmware version, and other hardware details",
)
async def get_device_info(client: ZTEClient = Depends(ensure_logged_in)):
    """Get device information"""
    try:
        get_data = with_session_retry(lambda c: c.get_device_info())
        data = get_data(client)
        return DeviceInfoResponse(**data.to_dict())
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# LAN status endpoint
@app.get(
    "/lan",
    response_model=list[LANPortResponse],
    tags=["LAN"],
    summary="Get LAN port status",
    description="Fetch status of all LAN ports including link state, speed, and traffic counters",
)
async def get_lan_status(client: ZTEClient = Depends(ensure_logged_in)):
    """Get LAN port status"""
    try:
        get_data = with_session_retry(lambda c: c.get_lan_status())
        ports = get_data(client)
        return [LANPortResponse(**p.to_dict()) for p in ports]
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# VoIP status endpoint
@app.get(
    "/voip",
    response_model=list[VoIPLineResponse],
    tags=["VoIP"],
    summary="Get VoIP line status",
    description="Fetch VoIP line registration status for all configured lines",
)
async def get_voip_status(client: ZTEClient = Depends(ensure_logged_in)):
    """Get VoIP line status"""
    try:
        get_data = with_session_retry(lambda c: c.get_voip_status())
        lines = get_data(client)
        return [VoIPLineResponse(**l.to_dict()) for l in lines]
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# WAN status endpoint
@app.get(
    "/wan",
    response_model=list[WANConnectionResponse],
    tags=["WAN"],
    summary="Get WAN connection status",
    description="Fetch WAN connection information including IP addresses and connection status",
)
async def get_wan_status(client: ZTEClient = Depends(ensure_logged_in)):
    """Get WAN connection status"""
    try:
        get_data = with_session_retry(lambda c: c.get_wan_status())
        connections = get_data(client)
        return [WANConnectionResponse(**c.to_dict()) for c in connections]
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# System stats endpoint
@app.get(
    "/system/stats",
    response_model=SystemStatsResponse,
    tags=["System"],
    summary="Get system statistics",
    description="Fetch CPU and memory usage, uptime, and storage statistics",
)
async def get_system_stats(client: ZTEClient = Depends(ensure_logged_in)):
    """Get system statistics"""
    try:
        get_data = with_session_retry(lambda c: c.get_system_stats())
        stats = get_data(client)
        return SystemStatsResponse(**stats)
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# Connected devices endpoint
@app.get(
    "/devices",
    response_model=list[ConnectedDeviceResponse],
    tags=["Network"],
    summary="Get connected devices",
    description="Fetch list of devices connected to the router",
)
async def get_connected_devices(client: ZTEClient = Depends(ensure_logged_in)):
    """Get connected devices"""
    try:
        get_data = with_session_retry(lambda c: c.get_connected_devices())
        devices = get_data(client)
        return [ConnectedDeviceResponse(**d.to_dict()) for d in devices]
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


# Combined status endpoint
@app.get(
    "/status",
    tags=["Status"],
    summary="Get full router status",
    description="Fetch all available status information in a single request",
)
async def get_full_status(client: ZTEClient = Depends(ensure_logged_in)):
    """Get full router status"""
    try:
        # Use retry wrapper for each call
        get_device = with_session_retry(lambda c: c.get_device_info())
        get_pon = with_session_retry(lambda c: c.get_pon_data())
        get_lan = with_session_retry(lambda c: c.get_lan_status())
        get_voip = with_session_retry(lambda c: c.get_voip_status())
        get_wan = with_session_retry(lambda c: c.get_wan_status())
        get_system = with_session_retry(lambda c: c.get_system_stats())
        get_devices = with_session_retry(lambda c: c.get_connected_devices())

        return {
            "device": get_device(client).to_dict(),
            "pon": get_pon(client).to_dict(),
            "lan": [p.to_dict() for p in get_lan(client)],
            "voip": [l.to_dict() for l in get_voip(client)],
            "wan": [c.to_dict() for c in get_wan(client)],
            "system": get_system(client),
            "devices": [d.to_dict() for d in get_devices(client)],
        }
    except ZTESessionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ZTEClientError as e:
        raise HTTPException(status_code=500, detail=str(e))
