import ipaddress
import socket
import urllib.parse

def is_safe_target(target: str) -> bool:
    """Validate target to prevent SSRF and internal probing."""
    # Strip scheme if present
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        hostname = parsed.hostname
        if not hostname:
            return False
    else:
        # Check if they passed something like host:port without scheme
        hostname = target.split("/")[0].split(":")[0]

    if not hostname:
        return False

    if hostname.lower() in ["localhost", "127.0.0.1", "::1"]:
        return False

    try:
        # Try to resolve the hostname
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_loopback or
            ip_obj.is_private or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            ip_obj.is_reserved):
            return False
    except socket.gaierror:
        # If it doesn't resolve, let the DNS check handle the failure normally
        pass
    except ValueError:
        return False

    return True
