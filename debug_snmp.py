from pysnmp.hlapi.v3arch.sync import *
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
import logging

# Configure logging to stdout
logging.basicConfig(level=logging.DEBUG)

def test_snmp(target, community):
    print(f"Testing SNMP v2c on {target} with community '{community}'...")
    
    try:
        user_data = CommunityData(community, mpModel=1) # mpModel=1 for v2c
        transport = UdpTransportTarget((target, 161), timeout=2.0, retries=2)
        oid = ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0"))
        
        print("Sending getCmd...")
        iterator = getCmd(
            SnmpEngine(),
            user_data,
            transport,
            ContextData(),
            oid
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        if errorIndication:
            print(f"Error Indication: {errorIndication}")
        elif errorStatus:
            print(f"Error Status: {errorStatus.prettyPrint()}")
        else:
            for varBind in varBinds:
                print(f"Success! {varBind[0]} = {varBind[1]}")
                
    except Exception as e:
        print(f"Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python debug_snmp.py <IP> [community]")
        sys.exit(1)
    
    ip = sys.argv[1]
    comm = sys.argv[2] if len(sys.argv) > 2 else 'public'
    test_snmp(ip, comm)
