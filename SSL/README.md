# Domain Information and SSL Certificate Analyzer

##SSL Domain Analyzer Tool

## Overview
The `domain_info.py` tool is a comprehensive Python script designed for cybersecurity analysis and domain intelligence gathering. It provides detailed information about domain registration and SSL certificate analysis, making it valuable for security professionals, researchers, and threat intelligence gathering.

## 🔍 What It Captures

### A. Domain Registration Information (WHOIS/RDAP)
The tool captures comprehensive domain registration data including:

#### **Registrar Details**
- Registrar name and organization
- Registrar URL and contact information
- Registrar IANA ID for verification
- WHOIS server information
- RDAP (Registration Data Access Protocol) base URL

#### **Registration Timeline**
- **Creation Date**: When the domain was first registered
- **Expiration Date**: When the domain registration expires
- **Last Updated Date**: Most recent modification to domain records
- Registration renewal history

#### **Domain Status Codes**
- Current domain status (e.g., `clientTransferProhibited`, `serverUpdateProhibited`)
- Administrative locks and restrictions
- Transfer and update permissions

#### **DNS Infrastructure**
- **Nameservers**: Complete list of authoritative DNS servers
- DNS hosting provider identification
- DNS configuration analysis

#### **Contact Information**
Extracts contact details for three categories:
- **Registrant Contact**: Domain owner information
- **Administrative Contact**: Domain administrator details  
- **Technical Contact**: Technical point of contact

For each contact type, captures:
- Organization name
- Country of registration
- Email addresses (when publicly available)
- Phone numbers (when publicly available)

#### **Raw WHOIS Data**
- Complete raw WHOIS response for manual analysis
- Preserves all original data for validation and compliance

---

### B. SSL Certificate Analysis
Performs comprehensive SSL/TLS certificate examination:

#### **Connection Metadata**
- **Collection Timestamp**: Exact time of certificate retrieval
- **Source IP Address**: Server's actual IP address
- **Port Information**: Connection port (typically 443)
- **SNI (Server Name Indication)**: Used for multi-domain certificates

#### **Certificate Fingerprints**
- **SHA-256 Fingerprint**: Modern cryptographic hash for certificate identification
- **SHA-1 Fingerprint**: Legacy hash for compatibility
- **Serial Number**: Unique certificate identifier (decimal and hexadecimal)

#### **Certificate Subject Details**
- **Common Name (CN)**: Primary domain the certificate is issued for
- **Organization Information**: Certificate holder's organization
- **Organizational Unit**: Department or division
- **Locality**: City or region
- **State/Province**: Geographic location
- **Country**: Two-letter country code

#### **Subject Alternative Names (SANs)**
- Complete list of all domains covered by the certificate
- Wildcard domain coverage analysis
- Multi-domain certificate mapping

#### **Certificate Authority (Issuer) Information**
- **Issuing CA**: Certificate Authority that signed the certificate
- **CA Organization**: Issuer's organization name
- **CA Country**: Certificate Authority's country
- **Complete Issuer Chain**: Full hierarchical path

#### **Validity and Timing**
- **Not Before Date**: Certificate activation timestamp
- **Not After Date**: Certificate expiration timestamp
- **Validity Period**: Total certificate lifespan
- **Expiration Analysis**: Days until expiration

#### **Cryptographic Details**
- **Public Key Algorithm**: RSA, EC (Elliptic Curve), DSA, or Ed25519
- **Key Size**: Bit length for security strength analysis
- **Signature Algorithm**: Hash and encryption method used
- **Encryption Strength**: Security level assessment

#### **Certificate Extensions**
- **Key Usage**: Permitted cryptographic operations
- **Extended Key Usage**: Specific certificate purposes
- **Basic Constraints**: CA certificate indicators
- **Authority Key Identifier**: Links to issuing CA
- **Subject Key Identifier**: Unique key identification
- **CRL Distribution Points**: Certificate revocation check URLs
- **OCSP Information**: Online Certificate Status Protocol endpoints

---

## 🛠️ Technical Requirements

### Dependencies
```bash
pip install python-whois cryptography requests
```

### Required Libraries
- **python-whois**: Domain registration data retrieval
- **cryptography**: Advanced SSL certificate parsing
- **ssl & socket**: Network connections and SSL handling
- **requests**: HTTP/HTTPS communications
- **datetime**: Timestamp handling
- **json**: Data serialization
- **binascii**: Binary data conversion

---

## 🚀 Usage

### Basic Usage
```bash
python domain_info.py
```

### Interactive Mode
The tool runs in interactive mode and accepts various domain formats:
- `google.com`
- `https://example.org`
- `www.github.com`
- `microsoft.com:443`

### Input Validation
- Automatically strips protocols (`http://`, `https://`)
- Removes `www.` prefixes
- Handles port numbers
- Validates domain format
- Provides error messages for invalid input

---

## 📊 Output Format

### Domain Registration Section
```
==== DOMAIN REGISTRATION INFORMATION ====
🔹 A. Domain Registration Data (WHOIS/RDAP)
Domain Name: example.com
Registrar Details:
  Name: Example Registrar Inc.
  Registrar URL: https://www.example-registrar.com
  ...
```

### SSL Certificate Section
```
==== SSL CERTIFICATE INFORMATION ====
🔹 B. SSL Certificate Data
Observation Metadata:
  Collection Timestamp: 2025-09-20 10:30:45
  Source: Live SSL Scan
  ...
```

---

## 🔒 Security Applications

### Threat Intelligence
- **Domain Profiling**: Analyze suspicious domains for threat assessment
- **Infrastructure Mapping**: Understand domain ownership and hosting relationships
- **Certificate Analysis**: Detect certificate anomalies and potential impersonation

### Compliance and Auditing
- **Certificate Monitoring**: Track SSL certificate expiration and renewal
- **Domain Ownership Verification**: Validate domain registration details
- **Security Assessment**: Evaluate cryptographic strength and configurations

### Incident Response
- **Forensic Analysis**: Gather domain and certificate evidence
- **Attribution**: Link domains to threat actors through registration patterns
- **Timeline Reconstruction**: Analyze domain and certificate creation timelines

---

## ⚠️ Important Notes

### Rate Limiting
- Respects WHOIS server rate limits
- Implements connection timeouts for reliability
- Handles network errors gracefully

### Privacy Considerations
- Only accesses publicly available information
- Respects domain privacy services
- Follows GDPR and data protection guidelines

### Accuracy
- Data accuracy depends on registrar information quality
- Some registrars may limit publicly available data
- Certificate information is captured in real-time

---

## 🔧 Error Handling

The tool includes comprehensive error handling for:
- Network connectivity issues
- Invalid domain formats
- SSL connection failures
- WHOIS server unavailability
- Certificate parsing errors
- Rate limiting responses

---

## 📝 License
This tool is part of the PhisGuard-AI project and is intended for legitimate security research and analysis purposes.

---

## 🤝 Contributing
This tool was created by **Suraj Kumar** as part of the PhisGuard-AI project. Contributions to improve the tool's functionality and accuracy are welcome. Please ensure all enhancements maintain the tool's security focus and data accuracy standards.

## 👨‍💻 Author & Maintainer
- **Suraj Kumar** - Original creator and primary developer
