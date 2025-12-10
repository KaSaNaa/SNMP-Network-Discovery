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

    # Map SNMPv3 protocol strings to pysnmp protocol objects
    auth_protocol = None
    priv_protocol = None
    
    if args.version == 3:
        # Import SNMPv3 protocol objects (pysnmp 7.x naming)
        from pysnmp.hlapi.v3arch.asyncio import (
            USM_AUTH_HMAC96_MD5, USM_AUTH_HMAC96_SHA,
            USM_AUTH_HMAC128_SHA224, USM_AUTH_HMAC192_SHA256,
            USM_AUTH_HMAC256_SHA384, USM_AUTH_HMAC384_SHA512,
            USM_AUTH_NONE,
            USM_PRIV_CBC56_DES, USM_PRIV_CBC168_3DES,
            USM_PRIV_CFB128_AES, USM_PRIV_CFB192_AES, USM_PRIV_CFB256_AES,
            USM_PRIV_CFB192_AES_BLUMENTHAL, USM_PRIV_CFB256_AES_BLUMENTHAL,
            USM_PRIV_NONE
        )
        
        # Map authentication protocols (pysnmp 7.x uses USM_AUTH_* constants)
        auth_map = {
            'MD5': USM_AUTH_HMAC96_MD5,
            'SHA': USM_AUTH_HMAC96_SHA,
            'SHA1': USM_AUTH_HMAC96_SHA,
            'SHA224': USM_AUTH_HMAC128_SHA224,
            'SHA256': USM_AUTH_HMAC192_SHA256,
            'SHA384': USM_AUTH_HMAC256_SHA384,
            'SHA512': USM_AUTH_HMAC384_SHA512,
            'NONE': USM_AUTH_NONE,
        }
        
        # Map privacy protocols (pysnmp 7.x uses USM_PRIV_* constants)
        priv_map = {
            'DES': USM_PRIV_CBC56_DES,
            '3DES': USM_PRIV_CBC168_3DES,
            'AES': USM_PRIV_CFB128_AES,
            'AES128': USM_PRIV_CFB128_AES,
            'AES192': USM_PRIV_CFB192_AES,
            'AES256': USM_PRIV_CFB256_AES,
            'AES192BLUMENTHAL': USM_PRIV_CFB192_AES_BLUMENTHAL,
            'AES256BLUMENTHAL': USM_PRIV_CFB256_AES_BLUMENTHAL,
            'NONE': USM_PRIV_NONE,
        }
        
        if args.auth_proto:
            auth_protocol = auth_map.get(args.auth_proto.upper())
            if not auth_protocol:
                print(json.dumps({"error": f"Invalid auth protocol: {args.auth_proto}. Valid options: {', '.join(auth_map.keys())}"}, indent=4))
                sys.exit(1)
        
        if args.priv_proto:
            priv_protocol = priv_map.get(args.priv_proto.upper())
            if not priv_protocol:
                print(json.dumps({"error": f"Invalid privacy protocol: {args.priv_proto}. Valid options: {', '.join(priv_map.keys())}"}, indent=4))
                sys.exit(1)
    
    discovery = DeviceDiscovery(
        ip=args.ip,
        version=args.version,
        community=args.community,
        user=args.user,
        auth_key=args.auth_key,
        priv_key=args.priv_key,
        auth_protocol=auth_protocol,  # Pass the mapped object
        priv_protocol=priv_protocol   # Pass the mapped object
    )

    try:
        result = await discovery.discover()
        print(json.dumps(result, indent=4))
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=4))
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
