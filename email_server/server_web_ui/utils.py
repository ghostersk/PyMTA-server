"""
Common utilities for the SMTP server web UI.

This module provides shared functionality used across different blueprints.
"""

import socket
import requests
import dns.resolver
from typing import Dict, List, Optional, Union
from email_server.settings_loader import load_settings
import logging

logger = logging.getLogger(__name__)

def get_public_ip() -> str:
    """Get the public IP address of the server."""
    try:
        response1 = requests.get('http://ifconfig.me/ip', timeout=3, verify=False)

        ip = response1.text.strip()
        if ip and ip != 'unknown':
            return ip
    except Exception:
        try:
            # Fallback method
            response = requests.get('http://httpbin.org/ip', timeout=3, verify=False)
            ip = response.json()['origin'].split(',')[0].strip()
            if ip and ip != 'unknown':
                return ip
        except Exception:
            pass

    # Use fallback from settings.ini if available
    try:
        settings = load_settings()
        fallback_ip = settings.get('DKIM', 'SPF_SERVER_IP', fallback=None)
        if fallback_ip and fallback_ip.strip() and fallback_ip != '""':
            # Check if it's a valid IPv4 address (basic check)
            parts = fallback_ip.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return fallback_ip.strip()
    except Exception:
        pass

    return '127.0.0.1'  # Last resort fallback

def check_dns_record(domain: str, record_type: str, expected_value: Optional[str] = None) -> Dict[str, Union[bool, str, List[str]]]:
    """Check DNS record for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        # Use Cloudflare's DNS servers
        resolver.nameservers = ['1.1.1.1', '1.0.0.1']
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Try to get records
        try:
            answers = resolver.resolve(domain, record_type)
        except dns.resolver.NXDOMAIN:
            return {
                'success': False,
                'message': f'Domain {domain} does not exist',
                'records': []
            }
        except dns.resolver.NoAnswer:
            return {
                'success': False,
                'message': f'No {record_type} records found for {domain}',
                'records': []
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'DNS lookup error: {str(e)}',
                'records': []
            }
        
        # Convert answers to strings, handle TXT records specially
        if record_type == 'TXT':
            # For TXT records, concatenate strings and normalize
            records = []
            for rdata in answers:
                # Join strings and decode bytes if needed
                full_txt = ''
                for string in rdata.strings:
                    if isinstance(string, bytes):
                        string = string.decode('utf-8')
                    full_txt += string
                # Normalize whitespace and add quotes
                normalized = '"' + ' '.join(full_txt.split()) + '"'
                records.append(normalized)
        else:
            records = [str(rdata) for rdata in answers]
        
        # If we're looking for a specific value
        if expected_value:
            # For TXT records, normalize the expected value
            if record_type == 'TXT':
                if not expected_value.startswith('"'):
                    expected_value = '"' + expected_value.strip('"') + '"'
                # Normalize whitespace in expected value
                expected_value = '"' + ' '.join(expected_value.strip('"').split()) + '"'
                
                # Debug logging
                logger.debug(f"Comparing DNS records:")
                logger.debug(f"Expected: {expected_value}")
                logger.debug(f"Found: {records}")
            
            # Check if normalized expected value matches any normalized record
            if expected_value in records:
                return {
                    'success': True,
                    'message': f'Found matching {record_type} record',
                    'records': records
                }
            else:
                return {
                    'success': False,
                    'message': f'Expected {record_type} record not found',
                    'records': records
                }
        
        # If we just want to check if records exist
        return {
            'success': True,
            'message': f'Found {len(records)} {record_type} record(s)',
            'records': records
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'DNS lookup error: {str(e)}',
            'records': []
        }

def generate_spf_record(domain: str, server_ip: str, existing_spf: Optional[str] = None) -> str:
    """Generate recommended SPF record, preserving existing mechanisms if present."""
    if existing_spf:
        # Parse existing SPF record
        mechanisms = existing_spf.split()
        
        # Check if our IP is already included
        ip_mechanism = f'ip4:{server_ip}'
        if ip_mechanism in mechanisms:
            return existing_spf
        
        # Find the all mechanism (should be last)
        all_mechanism = next((m for m in reversed(mechanisms) if m.startswith('-all') or m.startswith('~all') or m == 'all'), None)
        
        if all_mechanism:
            # Insert our IP before the all mechanism
            insert_pos = mechanisms.index(all_mechanism)
            mechanisms.insert(insert_pos, ip_mechanism)
        else:
            # No all mechanism found, append our IP and a ~all
            mechanisms.append(ip_mechanism)
            mechanisms.append('~all')
        
        return ' '.join(mechanisms)
    else:
        # Create new SPF record
        return f'v=spf1 ip4:{server_ip} ~all' 