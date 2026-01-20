#!/usr/bin/env python3
# ip_validator.py
# Validates IPv4 addresses.



import platform
import subprocess

def validate_ip(ip_address):
    """
    Validate an IPv4 address.
    """
    try:
        ip_address = ip_address.strip()
        octets = ip_address.split(".")

        if len(octets) != 4:
            return False
        
        for octet in octets:
            if not octet.isdigit():
                return False

            # prevent leading zeros
            if len(octet) > 1 and octet.startswith("0"):
                return False

            num = int(octet)
            if num < 0 or num > 255:
                return False
        
        return True

    except ValueError:
        return False


def ping_address(ip_address):
    """
    Ping a Validated IP address once and return True/False.
    """
    system = platform.system().lower()
    
    command = (
        ["ping", "-n", "1", ip_address] 
        if system == "windows" 
        else ["ping", "-c", "1", ip_address]
    )

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3  # prevent ping hanging for a long period.
        )
        return result.returncode == 0
    except Exception:
        return False


# Shows examples of Valid IP addresses and invalid IP addresses.
test_ips = [
    "192.168.1.1",
    "10.0.0.1",
    "256.1.1.1",
    "192.168.1",
    "abc.def.ghi.jkl",
    "192.168.1.1.1"
]

print("IP Address Validator")
print("=" * 40)

for ip in test_ips:
    result = "VALID" if validate_ip(ip) else "INVALID"
    print(f"{ip:20} → {result}")

print("\n" + "=" * 40)

# Interactive mode to validate user input IP address. And ping if valid. 
user_ip = input("\nEnter an IP address to validate: ").strip()

if validate_ip(user_ip):
    print(f"VALID IPv4 address.\nPinging...")
    if ping_address(user_ip):
        print(f"Ping to {user_ip} succeeded!")
    else:
        print(f"Ping to {user_ip} failed.")
else:
    print(f"{user_ip} is NOT a valid IPv4 address.")

 