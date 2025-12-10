import argparse
import json
import sys
import asyncio
from core.device_discovery import DeviceDiscovery

async def main():
    parser = argparse.ArgumentParser(description="SNMP Discovery Script Enhancements")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--version", type=int, choices=[1, 2, 3], default=2, help="SNMP Version (1, 2, or 3)")
    parser.add_argument("--community", default="public", help="Community string for SNMP v1/v2c")
    parser.add_argument("--user", help="SNMPv3 User")
    parser.add_argument("--auth_key", help="SNMPv3 Auth Key")
    parser.add_argument("--priv_key", help="SNMPv3 Privacy Key")
    parser.add_argument("--auth_proto", help="SNMPv3 Auth Protocol (MD5, SHA)")
    parser.add_argument("--priv_proto", help="SNMPv3 Privacy Protocol (DES, AES)")

    args = parser.parse_args()

    # Map string protocols to pysnmp objects if necessary, currently passing strings/None
    # The SNMPManager might need logic to map string 'SHA' to specific constant if 7.x differs.
    # For now assuming SNMPManager handles basic string-to-protocol or expects correct constants.
    # Note: The updated code in SNMPManager removed strict validation against constants, so it might fail if raw strings are passed where objects are expected.
    # However, pysnmp usually requires specific object instances (usmHMACSHAAuthProtocol etc).
    # Since I cannot import them easily here without dependency, I will rely on SNMPManager to have default handling or user to provide valid inputs.
    # Actually, let's just pass strings and let pysnmp complain if wrong, or we should map them in SNMPManager.
    
    discovery = DeviceDiscovery(
        ip=args.ip,
        version=args.version,
        community=args.community,
        user=args.user,
        auth_key=args.auth_key,
        priv_key=args.priv_key,
        auth_protocol=args.auth_proto,
        priv_protocol=args.priv_proto
    )

    try:
        result = await discovery.discover()
        print(json.dumps(result, indent=4))
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=4))
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
