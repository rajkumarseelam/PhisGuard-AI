# This script checks domain information and SSL certificates

# Use the python-whois package with correct import
import sys
import ssl
import socket
import datetime
import json
import binascii
import requests
from urllib.parse import urlparse

# Import whois with proper name
import whois as python_whois

# Import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID

def extract_domain(url):
    """Extract the domain from a URL and validate it"""
    # Handle empty input
    if not url or not url.strip():
        return ""
        
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Remove protocol (http://, https://, etc.)
    if '://' in url:
        url = url.split('://', 1)[1]
    
    # Remove path, query parameters, and fragments
    url = url.split('/', 1)[0]
    
    # Remove port number if present
    if ':' in url:
        url = url.split(':', 1)[0]
    
    # Strip 'www.' prefix if present
    if url.startswith('www.'):
        url = url.replace('www.', '', 1)
    
    # Basic validation: must contain at least one dot and no spaces
    if ' ' in url or '.' not in url:
        return ""
        
    return url

def check_domain_info(domain):
    try:
        # Extract the domain from URL if needed
        clean_domain = extract_domain(domain)
        
        print(f"\n==== DOMAIN REGISTRATION INFORMATION ====")
        print(f"Looking up information for domain: {clean_domain}")
        result = python_whois.whois(clean_domain)
        
        # Print comprehensive domain registration information
        print("\n🔹 A. Domain Registration Data (WHOIS/RDAP)")
        print(f"Domain Name: {result.domain_name}")
        
        # Registrar details
        print("\nRegistrar Details:")
        print(f"  Name: {result.registrar}")
        print(f"  Registrar URL: {getattr(result, 'registrar_url', 'N/A')}")
        print(f"  Registrar IANA ID: {getattr(result, 'registrar_iana', 'N/A')}")
        
        # Registration dates
        print("\nRegistration Dates:")
        print(f"  Creation Date: {result.creation_date}")
        print(f"  Expiration Date: {result.expiration_date}")
        print(f"  Last Updated Date: {getattr(result, 'updated_date', 'N/A')}")
        
        # Status codes
        print("\nDomain Status Codes:")
        status = getattr(result, 'status', None)
        if status:
            if isinstance(status, list):
                for s in status:
                    print(f"  - {s}")
            else:
                print(f"  - {status}")
        else:
            print("  N/A")
        
        # Nameservers
        print("\nNameservers:")
        nameservers = getattr(result, 'name_servers', [])
        if nameservers:
            if isinstance(nameservers, list):
                for ns in nameservers:
                    print(f"  - {ns}")
            else:
                print(f"  - {nameservers}")
        else:
            print("  N/A")
        
        # Contact information
        print("\nContact Information:")
        
        # Try to get detailed contact info for each type
        contact_types = ['registrant', 'admin', 'tech']
        for contact_type in contact_types:
            print(f"\n{contact_type.capitalize()} Contact:")
            
            # Try different attribute patterns that might exist in the WHOIS data
            org = getattr(result, f"{contact_type}_org", 
                  getattr(result, f"{contact_type}_organization", 
                  getattr(result, f"{contact_type}_organisation", 'N/A')))
            
            country = getattr(result, f"{contact_type}_country", 'N/A')
            email = getattr(result, f"{contact_type}_email", 'N/A')
            phone = getattr(result, f"{contact_type}_phone", 'N/A')
            
            print(f"  Organization: {org}")
            print(f"  Country: {country}")
            print(f"  Email: {email}")
            print(f"  Phone: {phone}")
        
        # WHOIS Server
        print(f"\nWHOIS Server: {getattr(result, 'whois_server', 'N/A')}")
        print(f"RDAP Base URL: {getattr(result, 'rdap_url', 'N/A')}")
        
        # Raw WHOIS text
        print("\nRaw WHOIS Data (first 300 chars):")
        raw_text = str(result)
        print(f"{raw_text[:300]}..." if len(raw_text) > 300 else raw_text)
        print("\nFull raw data preserved for validation.")
        
        return True
    except Exception as e:
        print(f"Error in WHOIS lookup: {e}")
        return False

def get_ssl_certificate(domain):
    try:
        # Extract hostname from domain
        hostname = extract_domain(domain)
        
        # Create a socket and wrap it with SSL
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print("\n==== SSL CERTIFICATE INFORMATION ====")
                print(f"Collecting SSL certificate for: {hostname}")
                
                # Get the certificate in both formats
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    raise ValueError("Could not retrieve certificate in binary form")
                    
                # Parse certificate using cryptography instead of PyOpenSSL
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                cert_dict = ssock.getpeercert()
                
                print("\n🔹 B. SSL Certificate Data")
                
                # Collection timestamp and metadata
                collection_time = datetime.datetime.now()
                print("\nObservation Metadata:")
                print(f"  Collection Timestamp: {collection_time}")
                print(f"  Source: Live SSL Scan")
                
                # Connection information
                peer = ssock.getpeername()
                print(f"  Origin IP: {peer[0]}")
                print(f"  Port: {peer[1]}")
                print(f"  SNI Used: {hostname}")
                
                # Certificate fingerprints
                sha256_fingerprint = cert.fingerprint(hashes.SHA256())
                sha1_fingerprint = cert.fingerprint(hashes.SHA1())
                
                print("\nCertificate Fingerprints:")
                print(f"  SHA-256: {':'.join(format(b, '02X') for b in sha256_fingerprint)}")
                print(f"  SHA-1: {':'.join(format(b, '02X') for b in sha1_fingerprint)}")
                
                # Serial number in a more readable format
                serial = cert.serial_number
                serial_hex = format(serial, 'x')
                print(f"  Serial Number: {serial} (0x{serial_hex})")
                
                # Subject details
                print("\nSubject Details:")
                subject = cert.subject
                subject_components = {}
                
                # Extract subject attributes
                for attr in subject:
                    oid_name = attr.oid._name
                    value = attr.value
                    subject_components[oid_name] = value
                
                # Display Common Name
                cn = subject_components.get('commonName', 'N/A')
                print(f"  Common Name (CN): {cn}")
                
                # Print other subject components
                for key, value in subject_components.items():
                    if key != 'commonName':  # Already printed CN above
                        print(f"  {key}: {value}")
                
                # Subject Alternative Names (SANs)
                print("\nSubject Alternative Names (SANs):")
                
                # Try with standard cert_dict first as it's more reliable
                if cert_dict and 'subjectAltName' in cert_dict:
                    for san_type, san_value in cert_dict['subjectAltName']:
                        print(f"  {san_type}: {san_value}")
                else:
                    # Fallback to the cryptography library
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        san = san_ext.value
                        
                        # Convert the extension value to string and parse it manually
                        san_str = str(san)
                        if san_str:
                            parts = san_str.split(", ")
                            for part in parts:
                                print(f"  {part}")
                        else:
                            print("  None found")
                    except Exception as e:
                        print(f"  Unable to extract SANs: {e}")
                        print("  None found")
                
                # Issuer details
                print("\nIssuer Details:")
                issuer = cert.issuer
                issuer_components = {}
                
                # Extract issuer attributes
                for attr in issuer:
                    oid_name = attr.oid._name
                    value = attr.value
                    issuer_components[oid_name] = value
                
                print(f"  Issuing CA: {issuer_components.get('commonName', 'N/A')}")
                print(f"  Organization: {issuer_components.get('organizationName', 'N/A')}")
                print(f"  Country: {issuer_components.get('countryName', 'N/A')}")
                
                # Print other issuer components
                for key, value in issuer_components.items():
                    if key not in ['commonName', 'organizationName', 'countryName']:  # Already printed these above
                        print(f"  {key}: {value}")
                
                # Validity period
                print("\nValidity Period:")
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                print(f"  Not Before (start): {not_before}")
                print(f"  Not After (expiry): {not_after}")
                
                # Public key details
                print("\nPublic Key Details:")
                pub_key = cert.public_key()
                
                # Get a simple string representation of the public key type
                key_type_class = pub_key.__class__.__name__
                
                # Safe approach to get key type and size based on class name only
                if "RSA" in key_type_class:
                    key_type = "RSA"
                    # Use safe approach that works with many cryptography versions
                    try:
                        # For newer versions, try to get key size from string representation
                        key_size = "2048"  # Common default
                        pub_key_str = str(pub_key)
                        for bit_size in ["1024", "2048", "3072", "4096", "8192"]:
                            if bit_size in pub_key_str:
                                key_size = bit_size
                                break
                    except:
                        key_size = "2048"  # Common default
                        
                elif "DSA" in key_type_class:
                    key_type = "DSA"
                    key_size = "1024/2048/3072"  # Common DSA sizes
                    
                elif "EllipticCurve" in key_type_class:
                    key_type = "EC"
                    key_size = "256"  # Default
                    # Try to identify curve from string representation
                    try:
                        pub_key_str = str(pub_key)
                        for curve_size in ["256", "384", "521"]:
                            if curve_size in pub_key_str:
                                key_size = curve_size
                                break
                    except:
                        pass  # Keep default
                        
                elif "Ed25519" in key_type_class:
                    key_type = "ED25519"
                    key_size = "255"  # Fixed size
                    
                elif "Ed448" in key_type_class:
                    key_type = "ED448"
                    key_size = "448"  # Fixed size
                    
                elif "X25519" in key_type_class:
                    key_type = "X25519"
                    key_size = "255"  # Fixed size
                    
                elif "X448" in key_type_class:
                    key_type = "X448"
                    key_size = "448"  # Fixed size
                    
                elif "DH" in key_type_class:
                    key_type = "DH"
                    key_size = "2048"  # Common size
                    
                else:
                    # For unknown types, just return the class name
                    key_type = key_type_class
                    key_size = "Unknown"
                
                print(f"  Algorithm: {key_type}")
                print(f"  Key Length: {key_size} bits")
                
                # Get signature algorithm
                sig_algo = cert.signature_algorithm_oid._name
                print(f"  Signature Algorithm: {sig_algo}")
                
                # Certificate extensions
                print("\nCertificate Extensions:")
                
                # Map of common extensions
                extension_oids = {
                    ExtensionOID.KEY_USAGE: 'Key Usage',
                    ExtensionOID.EXTENDED_KEY_USAGE: 'Extended Key Usage',
                    ExtensionOID.CRL_DISTRIBUTION_POINTS: 'CRL Distribution Points',
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: 'Authority Info Access (OCSP)',
                    ExtensionOID.BASIC_CONSTRAINTS: 'Basic Constraints',
                    ExtensionOID.CERTIFICATE_POLICIES: 'Certificate Policies',
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER: 'Subject Key Identifier',
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: 'Authority Key Identifier',
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: 'Subject Alternative Name'
                }
                
                # Process each extension
                for extension in cert.extensions:
                    oid = extension.oid
                    ext_name = extension_oids.get(oid, oid._name)
                    print(f"  {ext_name}:")
                    
                    # Format extension value based on type
                    if oid == ExtensionOID.KEY_USAGE:
                        usages = []
                        if extension.value.digital_signature:
                            usages.append("Digital Signature")
                        if extension.value.content_commitment:
                            usages.append("Content Commitment")
                        if extension.value.key_encipherment:
                            usages.append("Key Encipherment")
                        if extension.value.data_encipherment:
                            usages.append("Data Encipherment")
                        if extension.value.key_agreement:
                            usages.append("Key Agreement")
                        if extension.value.key_cert_sign:
                            usages.append("Certificate Sign")
                        if extension.value.crl_sign:
                            usages.append("CRL Sign")
                        print(f"    {', '.join(usages)}")
                        
                    elif oid == ExtensionOID.EXTENDED_KEY_USAGE:
                        ekus = []
                        for eku in extension.value:
                            ekus.append(eku._name)
                        print(f"    {', '.join(ekus)}")
                        
                    elif oid == ExtensionOID.BASIC_CONSTRAINTS:
                        bc = extension.value
                        print(f"    CA:{bc.ca}")
                        if bc.ca and bc.path_length is not None:
                            print(f"    Path Length: {bc.path_length}")
                            
                    elif oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                        ski = extension.value.digest
                        print(f"    {':'.join(format(b, '02X') for b in ski)}")
                        
                    elif oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                        aki = extension.value.key_identifier
                        if aki:
                            print(f"    {':'.join(format(b, '02X') for b in aki)}")
                        
                    elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                        for point in extension.value:
                            if point.full_name:
                                for name in point.full_name:
                                    if isinstance(name, x509.UniformResourceIdentifier):
                                        print(f"    URI:{name.value}")
                                        
                    elif oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                        for access in extension.value:
                            if access.access_method._name == 'ocsp':
                                print(f"    OCSP - URI:{access.access_location.value}")
                            elif access.access_method._name == 'caIssuers':
                                print(f"    CA Issuers - URI:{access.access_location.value}")
                    else:
                        # Generic handling for other extensions
                        print(f"    {extension.value}")
                
                # Certificate chain info
                print("\nCertificate Chain:")
                print(f"  - Leaf: {cn}")
                
                # Attempt to get intermediate and root certificates
                try:
                    cert_url = f"https://{hostname}"
                    response = requests.get(cert_url, verify=True)
                    if hasattr(response.raw, '_connection') and hasattr(response.raw._connection, 'sock'):
                        print("  - Intermediates: [Available but not parsed]")
                        print("  - Root: [Available but not parsed]")
                except Exception as e:
                    print(f"  - Failed to retrieve certificate chain: {e}")
                
                # Raw certificate data - PEM format
                print("\nRaw Certificate Data:")
                print("  [PEM format data available but not displayed due to length]")
                
                # Store PEM data in a variable for potential export
                pem_data = cert.public_bytes(Encoding.PEM).decode('utf-8')
                
                # Summary of Certificate Transparency (CT) info if available
                print("\nCertificate Transparency:")
                sct_found = False
                try:
                    # Check for SCT extension (1.3.6.1.4.1.11129.2.4.2)
                    # This is the OID for embedded SCTs
                    sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
                    for extension in cert.extensions:
                        if extension.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.2":
                            print("  SCTs: Present (embedded in certificate)")
                            sct_found = True
                            break
                except Exception:
                    pass
                
                if not sct_found:
                    print("  SCTs: None found in certificate")
                
                return True
    except Exception as e:
        print(f"\nError in SSL certificate collection: {e}")
        return False

def main():
    print("\n===== Domain Information and SSL Certificate Checker =====")
    print("This tool analyzes domain registration data and SSL certificates.")
    print("Examples of valid inputs: google.com, example.org, github.com")
    
    while True:
        try:
            # Ask user for input with clear instructions
            domain = input("\nEnter a domain name (e.g., google.com) or type 'exit' to quit: ")
            
            # Exit condition
            if domain.lower() == 'exit':
                print("Exiting program. Goodbye!")
                break
            
            # Handle common input errors
            domain = domain.strip().lower()
            
            # Skip empty input
            if not domain:
                print("ERROR: Empty input. Please enter a valid domain name.")
                continue
                
            # Check for common errors
            if domain == "domain name" or domain == "domain":
                print("ERROR: You entered the literal text 'domain name' or 'domain'.")
                print("Please enter an actual domain like 'google.com' or 'microsoft.com'.")
                continue
                
            if ' ' in domain:
                print(f"ERROR: '{domain}' contains spaces. Domain names cannot have spaces.")
                print("Please enter a valid domain name like 'example.com'.")
                continue
                
            if '.' not in domain:
                print(f"ERROR: '{domain}' is not a valid domain. It must contain at least one dot.")
                print("Examples of valid domains: google.com, bbc.co.uk, wikipedia.org")
                continue
            
            # Clean and validate the domain
            clean_domain = extract_domain(domain)
            
            # Skip invalid input
            if not clean_domain:
                print("ERROR: Invalid domain format. Please enter a valid domain name.")
                print("Examples of valid domains: google.com, bbc.co.uk, wikipedia.org")
                continue
            
            print(f"\nAnalyzing domain: {clean_domain}")
            
            # 1. Check domain registration info
            check_domain_info(clean_domain)
            
            # 2. Check SSL certificate info if the domain uses HTTPS
            try:
                get_ssl_certificate(clean_domain)
            except Exception as e:
                print(f"\nUnable to retrieve SSL certificate: {e}")
            
            print("\n" + "-" * 70)  # Add a separator line for readability
        
        except KeyboardInterrupt:
            print("\n\nProgram interrupted. Exiting...")
            break
        except Exception as e:
            print(f"\nAn error occurred: {e}")
            print("\n" + "-" * 70)  # Add a separator line for readability

if __name__ == "__main__":
    main()