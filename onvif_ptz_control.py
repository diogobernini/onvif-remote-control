#!/usr/bin/env python3
import os
import sys
import time
import socket
import getpass
import threading
import ipaddress
import json
from xml.etree import ElementTree
import urllib.request
import urllib.error
import http.client
import readchar
import netifaces

# ONVIF discovery and control classes
class OnvifDiscovery:
    """Class to handle ONVIF device discovery on the network"""
    
    DISCOVERY_MSG = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:84ede3de-7dec-11d0-c360-F01234567890</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

    def __init__(self):
        self.devices = []
        self.sock = None

    def discover(self):
        """Discover ONVIF devices on the network using WS-Discovery"""
        self.devices = []
        
        # Create UDP socket for discovery
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        self.sock.settimeout(5)
        
        # Try to discover devices on all network interfaces
        interfaces = self._get_network_interfaces()
        if not interfaces:
            print("No valid network interfaces found.")
            return self.devices
            
        for interface in interfaces:
            try:
                print(f"Searching for ONVIF cameras on interface {interface}...")
                # Send discovery message
                self.sock.sendto(self.DISCOVERY_MSG.encode(), ('239.255.255.250', 3702))
                
                # Try to receive responses for a few seconds
                start_time = time.time()
                while time.time() - start_time < 3:
                    try:
                        data, addr = self.sock.recvfrom(10240)
                        
                        # Parse the response
                        response = data.decode('utf-8')
                        device_info = self._parse_discovery_response(response, addr[0])
                        if device_info and device_info not in self.devices:
                            self.devices.append(device_info)
                            
                    except socket.timeout:
                        break
                        
            except Exception as e:
                print(f"Error discovering on interface {interface}: {e}")
                
        self.sock.close()
        return self.devices
    
    def _get_network_interfaces(self):
        """Get list of usable network interfaces"""
        interfaces = []
        
        try:
            for iface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        # Skip localhost and invalid addresses
                        if ip and not ip.startswith('127.'):
                            interfaces.append(ip)
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            
        return interfaces
    
    def _parse_discovery_response(self, response, sender_ip):
        """Parse WS-Discovery response to extract device information"""
        try:
            # Parse XML response
            root = ElementTree.fromstring(response)
            
            # Extract XAddrs (device service addresses)
            device_info = {
                'ip': sender_ip,
                'name': f"Camera {sender_ip}"  # Default name based on IP
            }
            
            # Try to find Scopes which may contain device name
            scope_name = None
            for element in root.iter():
                if element.tag.endswith('Scopes'):
                    scopes = element.text.strip().split()
                    for scope in scopes:
                        # Look for name in scopes
                        if 'name/' in scope.lower():
                            try:
                                name_part = scope.split('/')[-1]
                                if name_part:
                                    scope_name = urllib.parse.unquote(name_part)
                            except:
                                pass
                        
                        # Try hardware info as fallback
                        elif 'hardware/' in scope.lower():
                            try:
                                hw_part = scope.split('/')[-1]
                                if hw_part and not scope_name:
                                    scope_name = urllib.parse.unquote(hw_part)
                            except:
                                pass
            
            # Use discovered name if found
            if scope_name:
                device_info['name'] = scope_name
            
            # Find the service URL
            for element in root.iter():
                if element.tag.endswith('XAddrs'):
                    xaddrs = element.text.strip()
                    if xaddrs:
                        # Use sender IP if XAddrs contains a device-reported address that might be internal
                        device_url = xaddrs.split()[0]
                        if not self._is_accessible_address(device_url):
                            # Replace IP in URL with the sender IP
                            parts = urllib.parse.urlparse(device_url)
                            netloc_parts = parts.netloc.split(':')
                            if len(netloc_parts) > 1:
                                port = netloc_parts[1]
                                new_netloc = f"{sender_ip}:{port}"
                            else:
                                new_netloc = sender_ip
                            
                            parts = parts._replace(netloc=new_netloc)
                            device_url = urllib.parse.urlunparse(parts)
                        
                        device_info['url'] = device_url
                        
                        # Get device types
                        for element2 in root.iter():
                            if element2.tag.endswith('Types'):
                                device_info['types'] = element2.text
                                
                        return device_info
            
            return None
        except Exception as e:
            print(f"Error parsing discovery response: {e}")
            return None
            
    def _is_accessible_address(self, url):
        """Check if the URL contains an IP address that is accessible from this machine"""
        try:
            parts = urllib.parse.urlparse(url)
            host = parts.netloc.split(':')[0]
            
            # Check if it's a loopback address
            if host == 'localhost' or host.startswith('127.'):
                return False
                
            # Check if it's a private/internal address that might not be routable
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private:
                    # Additional check to see if we can actually reach this IP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    port = int(parts.netloc.split(':')[1]) if ':' in parts.netloc else 80
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
            except:
                # Not an IP address, might be a hostname
                pass
                
            return True
        except:
            return False


class OnvifPTZControl:
    """Class to control ONVIF PTZ camera movements"""
    
    # SOAP templates for ONVIF commands
    TEMPLATES = {
        # SOAP template for authentication and basic info request
        'get_device_info': """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{username}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>""",

        # SOAP template for PTZ service capabilities request
        'get_ptz_services': """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{username}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetServices xmlns="http://www.onvif.org/ver10/device/wsdl">
      <IncludeCapability>true</IncludeCapability>
    </GetServices>
  </s:Body>
</s:Envelope>""",

        # SOAP template for PTZ profiles request
        'get_profiles': """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{username}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
  </s:Body>
</s:Envelope>""",

        # SOAP template for continuous PTZ move request
        'continuous_move': """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{username}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{profile_token}</ProfileToken>
      <Velocity>
        <PanTilt x="{pan}" y="{tilt}" xmlns="http://www.onvif.org/ver10/schema"/>
        <Zoom x="{zoom}" xmlns="http://www.onvif.org/ver10/schema"/>
      </Velocity>
    </ContinuousMove>
  </s:Body>
</s:Envelope>""",

        # SOAP template for stop movement request
        'stop': """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{username}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <Stop xmlns="http://www.onvif.org/ver20/ptz/wsdl">
      <ProfileToken>{profile_token}</ProfileToken>
      <PanTilt>true</PanTilt>
      <Zoom>true</Zoom>
    </Stop>
  </s:Body>
</s:Envelope>"""
    }

    def __init__(self, device_url, username, password):
        self.device_url = device_url
        self.username = username
        self.password = password
        self.base_url = self._get_base_url(device_url)
        self.services = {}
        self.profile_token = None
        self.last_command_time = 0
        self.authorized = False
        
        # Device information fields
        self.device_name = "Unknown Camera"
        self.model = "Unknown"
        self.manufacturer = "Unknown"
        self.firmware = "Unknown"
        self.serial = "Unknown"
    
    def _get_base_url(self, url):
        """Extract the base URL from the device URL"""
        parts = urllib.parse.urlparse(url)
        return f"{parts.scheme}://{parts.netloc}"
    
    def _create_security_token(self):
        """Create security token for ONVIF authentication"""
        import datetime
        import base64
        import hashlib
        import random
        
        # Generate nonce
        nonce = bytes([random.randrange(256) for _ in range(16)])
        nonce_base64 = base64.b64encode(nonce).decode()
        
        # Get current time in UTC
        created = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Create password digest (see ONVIF authentication specs)
        password_hash = hashlib.sha1(nonce + created.encode() + self.password.encode()).digest()
        password_digest = base64.b64encode(password_hash).decode()
        
        return {
            'username': self.username,
            'password': password_digest,
            'nonce': nonce_base64,
            'created': created
        }

    def _send_request(self, service_url, template_name, additional_params=None):
        """Send SOAP request to the ONVIF device"""
        if time.time() - self.last_command_time < 0.05:
            time.sleep(0.05)  # Prevent overloading the camera with too many commands
            
        # Prepare the request payload
        params = self._create_security_token()
        if additional_params:
            params.update(additional_params)
        
        body = self.TEMPLATES[template_name].format(**params)
        
        # Parse URL
        url_parts = urllib.parse.urlparse(service_url)
        host = url_parts.netloc
        path = url_parts.path if url_parts.path else '/'
        
        # Set up the HTTP connection
        if url_parts.scheme == 'https':
            conn = http.client.HTTPSConnection(host, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, timeout=10)
        
        # Set headers
        headers = {
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'Content-Length': str(len(body))
        }
        
        # Send the request
        try:
            conn.request('POST', path, body=body, headers=headers)
            response = conn.getresponse()
            
            if response.status == 200:
                response_data = response.read().decode('utf-8')
                self.last_command_time = time.time()
                return response_data
            else:
                print(f"Error: Server returned status {response.status} - {response.reason}")
                if response.status == 401:
                    print("Authentication failed. Check your username and password.")
                    self.authorized = False
                response_data = response.read().decode('utf-8')
                print(f"Response: {response_data[:200]}...")
                return None
        except Exception as e:
            print(f"Error sending request to {service_url}: {e}")
            return None
        finally:
            conn.close()

    def connect(self):
        """Connect to the camera and verify credentials"""
        try:
            # Try to get device info to verify connection and credentials
            response = self._send_request(f"{self.base_url}/onvif/device_service", 'get_device_info')
            if not response:
                return False
                
            # Parse the response to get device info
            root = ElementTree.fromstring(response)
            
            # Extract some basic device info
            ns = {'tds': 'http://www.onvif.org/ver10/device/wsdl'}
            
            model = root.find('.//tds:Model', ns)
            manufacturer = root.find('.//tds:Manufacturer', ns)
            firmware = root.find('.//tds:FirmwareVersion', ns)
            serial = root.find('.//tds:SerialNumber', ns)
            
            # Build camera name from the device info
            camera_name = []
            if manufacturer is not None:
                camera_name.append(manufacturer.text)
            if model is not None:
                camera_name.append(model.text)
                
            if camera_name:
                device_name = " ".join(camera_name)
                print(f"\nConnected to: {device_name}")
                # Update device info
                self.device_name = device_name
                self.model = model.text if model is not None else "Unknown"
                self.manufacturer = manufacturer.text if manufacturer is not None else "Unknown"
                self.firmware = firmware.text if firmware is not None else "Unknown"
                self.serial = serial.text if serial is not None else "Unknown"
                self.authorized = True
            else:
                print("Connected, but couldn't get device details")
                self.device_name = "Unknown Camera"
                self.authorized = True
            
            # Get services
            self._get_services()
            
            # Get profile token for PTZ operations
            self._get_profile_token()
            
            return self.authorized
            
        except Exception as e:
            print(f"Error connecting to the camera: {e}")
            return False

    def _get_services(self):
        """Get available services from the camera"""
        try:
            response = self._send_request(f"{self.base_url}/onvif/device_service", 'get_ptz_services')
            if not response:
                return
                
            # Parse the response to get services
            root = ElementTree.fromstring(response)
            
            # Extract services and their URLs
            ns = {'tds': 'http://www.onvif.org/ver10/device/wsdl'}
            
            for service in root.findall('.//tds:Service', ns):
                namespace = service.find('.//tds:Namespace', ns)
                xaddr = service.find('.//tds:XAddr', ns)
                
                if namespace is not None and xaddr is not None:
                    service_name = namespace.text.split('/')[-1]
                    self.services[service_name] = xaddr.text
                    
                    # Specific check for PTZ service
                    if 'ptz' in namespace.text.lower():
                        self.services['ptz'] = xaddr.text
            
            # Fallback to common service paths if not found
            if 'ptz' not in self.services:
                self.services['ptz'] = f"{self.base_url}/onvif/ptz_service"
                
            if 'media' not in self.services:
                self.services['media'] = f"{self.base_url}/onvif/media_service"
                
        except Exception as e:
            print(f"Error getting services: {e}")
    
    def _get_profile_token(self):
        """Get a profile token that supports PTZ operations"""
        try:
            media_service = self.services.get('media', f"{self.base_url}/onvif/media_service")
            response = self._send_request(media_service, 'get_profiles')
            
            if not response:
                print("Failed to get profiles, using default profile token 'Profile_1'")
                self.profile_token = "Profile_1"
                return
                
            # Parse the response to get profiles
            root = ElementTree.fromstring(response)
            
            # Check for profiles with PTZ configuration
            ns = {'trt': 'http://www.onvif.org/ver10/media/wsdl'}
            
            for profile in root.findall('.//trt:Profiles', ns):
                token = profile.get('token')
                if token:
                    # For simplicity, use the first profile found
                    self.profile_token = token
                    print(f"Using profile: {token}")
                    return
            
            # Fallback to default profile if none found
            print("No profiles found, using default profile token 'Profile_1'")
            self.profile_token = "Profile_1"
            
        except Exception as e:
            print(f"Error getting profile token: {e}")
            self.profile_token = "Profile_1"  # Fallback to a common default
    
    def move(self, pan=0, tilt=0, zoom=0):
        """Send continuous move command to the camera"""
        try:
            if not self.authorized or not self.profile_token:
                print("Not properly connected to the camera")
                return False
                
            ptz_service = self.services.get('ptz', f"{self.base_url}/onvif/ptz_service")
            
            # Prepare parameters
            params = {
                'profile_token': self.profile_token,
                'pan': pan,
                'tilt': tilt,
                'zoom': zoom
            }
            
            # Send the move command
            response = self._send_request(ptz_service, 'continuous_move', params)
            return response is not None
            
        except Exception as e:
            print(f"Error moving camera: {e}")
            return False
    
    def stop(self):
        """Stop all camera movements"""
        try:
            if not self.authorized or not self.profile_token:
                return False
                
            ptz_service = self.services.get('ptz', f"{self.base_url}/onvif/ptz_service")
            
            # Prepare parameters
            params = {
                'profile_token': self.profile_token
            }
            
            # Send the stop command
            response = self._send_request(ptz_service, 'stop', params)
            return response is not None
            
        except Exception as e:
            print(f"Error stopping camera: {e}")
            return False


# File operations for saved cameras
def save_cameras_to_file(devices, filename='saved_cameras.json'):
    """Save discovered cameras to a JSON file"""
    try:
        # Only save essential information
        save_data = []
        for device in devices:
            # Create a copy of the device dict to avoid modifying the original
            device_copy = {
                'ip': device.get('ip', ''),
                'url': device.get('url', ''),
                'last_seen': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Add credentials if they exist
            if 'username' in device:
                device_copy['username'] = device.get('username', '')
            if 'password' in device:
                device_copy['password'] = device.get('password', '')
                
            save_data.append(device_copy)
            
        with open(filename, 'w') as f:
            json.dump(save_data, f, indent=4)
            
        print(f"\nSaved {len(devices)} cameras to {filename}")
        return True
    except Exception as e:
        print(f"Error saving cameras to file: {e}")
        return False

def load_cameras_from_file(filename='saved_cameras.json'):
    """Load saved cameras from a JSON file"""
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                devices = json.load(f)
            print(f"\nLoaded {len(devices)} cameras from {filename}")
            return devices
        else:
            print(f"\nNo saved camera file found ({filename})")
            return []
    except Exception as e:
        print(f"Error loading cameras from file: {e}")
        return []

# Main application to control PTZ cameras
def main():
    # Check for required dependencies
    missing_deps = []
    try:
        import readchar
    except ImportError:
        missing_deps.append('readchar')
    
    try:
        import netifaces
    except ImportError:
        missing_deps.append('netifaces')
    
    if missing_deps:
        print("Missing required dependencies. Please install them with:")
        print(f"pip install {' '.join(missing_deps)}")
        return
    
    # Clear the terminal screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=========================================")
    print("  ONVIF PTZ Camera Control Application  ")
    print("=========================================")
    
    # Try to load saved cameras first
    saved_cameras = load_cameras_from_file()
    
    # Ask user whether to use saved cameras or scan again
    devices = []
    if saved_cameras:
        print("\nOptions:")
        print("1. Use saved cameras")
        print("2. Scan for cameras on the network")
        
        choice = input("\nSelect an option (1-2): ").strip()
        
        if choice == '1':
            devices = saved_cameras
        elif choice == '2':
            # Discover cameras
            print("\nSearching for ONVIF cameras on your network...")
            discovery = OnvifDiscovery()
            devices = discovery.discover()
            
            # Save newly discovered cameras
            if devices:
                save_cameras_to_file(devices)
        else:
            print("Invalid choice. Defaulting to scanning for cameras.")
            print("\nSearching for ONVIF cameras on your network...")
            discovery = OnvifDiscovery()
            devices = discovery.discover()
    else:
        # No saved cameras, do discovery
        print("\nSearching for ONVIF cameras on your network...")
        discovery = OnvifDiscovery()
        devices = discovery.discover()
        
        # Save discovered cameras
        if devices:
            save_cameras_to_file(devices)
    
    if not devices:
        print("\nNo ONVIF cameras found on the network.")
        print("\nPossible reasons:")
        print("1. No ONVIF-compatible cameras on the network")
        print("2. Cameras have ONVIF discovery disabled")
        print("3. Network configuration blocking discovery packets")
        
        # Ask user if they want to manually enter a camera IP
        print("\nDo you want to manually enter a camera IP address? (y/n)")
        if input().lower().strip() == 'y':
            camera_ip = input("Enter camera IP address: ").strip()
            port = input("Enter camera port (default: 80): ").strip() or "80"
            devices = [{
                'url': f"http://{camera_ip}:{port}/onvif/device_service",
                'ip': camera_ip
            }]
            
            # Save the manually entered camera
            save_cameras_to_file(devices)
        else:
            print("Exiting application.")
            return
    
    # Display found cameras
    print(f"\nFound {len(devices)} ONVIF device(s):")
    for i, device in enumerate(devices):
        name = device.get('name', f"Camera {device['ip']}")
        print(f"{i+1}. {name} - {device['ip']} - {device.get('url', 'Unknown URL')}")
    
    # Let user select a camera
    selected_idx = 0
    if len(devices) > 1:
        while True:
            selection = input("\nSelect a camera (1-{}): ".format(len(devices)))
            try:
                selected_idx = int(selection) - 1
                if 0 <= selected_idx < len(devices):
                    break
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a number.")
    
    selected_device = devices[selected_idx]
    print(f"\nSelected camera: {selected_device['ip']}")
    
    # Get credentials with retry options
    max_attempts = 3
    attempt = 0
    connected = False
    
    while attempt < max_attempts and not connected:
        print("\nEnter camera credentials (attempt {}/{}):".format(attempt + 1, max_attempts))
        print("Press ESC at any time to return to camera selection")
        
        # Use saved credentials if available
        username = selected_device.get('username', '')
        password = selected_device.get('password', '')
        
        if username and password:
            print(f"Using saved credentials for {selected_device['ip']}")
        else:
            # Get username with ESC check
            username = ""
            print("Username: ", end="", flush=True)
            
            while True:
                char = readchar.readchar()
                # ESC key in readchar is represented by the escape character '\x1b'
                if char == '\x1b':
                    print("\nReturning to camera selection...")
                    return main()  # Restart the main function to reselect camera
                elif char == '\r' or char == '\n':
                    print()
                    break
                else:
                    username += char
                    print(char, end="", flush=True)
            
            # Get password with ESC check
            print("Password: ", end="", flush=True)
            password = ""
            
            while True:
                char = readchar.readchar()
                # ESC key in readchar is represented by the escape character '\x1b'
                if char == '\x1b':
                    print("\nReturning to camera selection...")
                    return main()  # Restart the main function to reselect camera
                elif char == '\r' or char == '\n':
                    print()
                    break
                else:
                    password += char
                    print("*", end="", flush=True)
        
        # Initialize PTZ controller
        print("\nConnecting to camera...")
        ptz_controller = OnvifPTZControl(selected_device['url'], username, password)
        
        connected = ptz_controller.connect()
        if not connected:
            print(f"Failed to connect to the camera. {max_attempts - attempt - 1} attempts remaining.")
            attempt += 1
            if attempt >= max_attempts:
                print("\nMax attempts reached. Returning to camera selection...")
                return main()  # Restart the main function to reselect camera
                
        # If successfully connected, save the credentials and device details in the device info for future use
        if connected and 'url' in selected_device:
            # Update the current device with credentials and device information
            selected_device['username'] = username
            selected_device['password'] = password
            selected_device['name'] = ptz_controller.device_name
            selected_device['model'] = ptz_controller.model
            selected_device['manufacturer'] = ptz_controller.manufacturer
            selected_device['firmware'] = ptz_controller.firmware
            selected_device['serial'] = ptz_controller.serial
            
            # Check if this device is already in the saved list
            saved_cameras = load_cameras_from_file()
            device_exists = False
            
            for i, device in enumerate(saved_cameras):
                if device.get('url') == selected_device['url']:
                    # Update existing device with new information
                    saved_cameras[i]['username'] = username
                    saved_cameras[i]['password'] = password
                    saved_cameras[i]['name'] = ptz_controller.device_name
                    saved_cameras[i]['model'] = ptz_controller.model
                    saved_cameras[i]['manufacturer'] = ptz_controller.manufacturer
                    saved_cameras[i]['firmware'] = ptz_controller.firmware
                    saved_cameras[i]['serial'] = ptz_controller.serial
                    saved_cameras[i]['last_seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
                    device_exists = True
                    break
            
            # If device doesn't exist in saved list, add it
            if not device_exists:
                saved_cameras.append({
                    'ip': selected_device.get('ip', ''),
                    'url': selected_device.get('url', ''),
                    'username': username,
                    'password': password,
                    'name': ptz_controller.device_name,
                    'model': ptz_controller.model,
                    'manufacturer': ptz_controller.manufacturer,
                    'firmware': ptz_controller.firmware,
                    'serial': ptz_controller.serial,
                    'last_seen': time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
            # Save the updated list
            save_cameras_to_file(saved_cameras)
    
    # Setup keyboard control interface
    print("\n============ Control Instructions ============")
    print("Use arrow keys to control the camera:")
    print("← → : Pan left/right")
    print("↑ ↓ : Tilt up/down")
    print("+ - : Zoom in/out")
    print("q   : Quit")
    print("==============================================")
    
    try:
        # Control loop
        while True:
            key = readchar.readkey()
            
            # Process key presses
            if key == readchar.key.UP:
                print("Moving up")
                ptz_controller.move(pan=0, tilt=0.3)
                ptz_controller.stop()
            elif key == readchar.key.DOWN:
                print("Moving down")
                ptz_controller.move(pan=0, tilt=-0.3)
                ptz_controller.stop()
            elif key == readchar.key.LEFT:
                print("Moving left")
                ptz_controller.move(pan=-0.3, tilt=0)
                ptz_controller.stop()
            elif key == readchar.key.RIGHT:
                print("Moving right")
                ptz_controller.move(pan=0.3, tilt=0)
                ptz_controller.stop()
            elif key == '+':
                print("Zooming in")
                ptz_controller.move(pan=0, tilt=0, zoom=0.3)
                ptz_controller.stop()
            elif key == '-':
                print("Zooming out")
                ptz_controller.move(pan=0, tilt=0, zoom=-0.3)
                ptz_controller.stop()
            elif key.lower() == 'q':
                print("\nExiting application...")
                break
    
    except KeyboardInterrupt:
        print("\nApplication interrupted.")
    finally:
        # Make sure to stop all movements when exiting
        ptz_controller.stop()
        print("Camera control stopped.")


if __name__ == "__main__":
    main()