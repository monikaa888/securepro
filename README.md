# 🔐 SecureShare Pro - PKI-Based Secure File Sharing System

> **A comprehensive secure file sharing system with PKI, digital signatures, and hybrid encryption**

## 🏗️ Architecture Design

### PKI (Public Key Infrastructure) Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURESHARE PRO ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐    │
│   │   ALICE     │      │     BOB     │      │   CHARLIE   │    │
│   │   (User)    │      │   (User)    │      │   (User)    │    │
│   └──────┬──────┘      └──────┬──────┘      └──────┬──────┘    │
│          │                    │                    │           │
│          │  ┌─────────────────┼─────────────────┐  │           │
│          │  │   RSA-2048 Key Pair Generation     │  │           │
│          │  │  ┌─────────┐    ┌─────────────┐   │  │           │
│          │  │  │ Private │◄──►│   Public    │   │  │           │
│          │  │  │   Key   │    │     Key     │   │  │           │
│          │  │  └─────────┘    └─────────────┘   │  │           │
│          │  │                                   │  │           │
│          │  │   X.509 Self-Signed Certificate   │  │           │
│          │  └───────────────────────────────────┘  │           │
│          │                    │                    │           │
│          ▼                    ▼                    ▼           │
│   ┌─────────────────────────────────────────────────────┐      │
│   │              SECURE KEY VAULT (Simulated HSM)       │      │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │      │
│   │  │  keys.json  │  │certificates │  │ shared_files│  │      │
│   │  │ (Encrypted) │  │    .json    │  │   .json     │  │      │
│   │  └─────────────┘  └─────────────┘  └─────────────┘  │      │
│   └─────────────────────────────────────────────────────┘      │
│                              │                                  │
│          ┌───────────────────┼───────────────────┐             │
│          ▼                   ▼                   ▼             │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐       │
│   │  AES-256    │    │    RSA      │    │    SHA-256  │       │
│   │   GCM       │    │   OAEP      │    │   Signatures│       │
│   │ Encryption  │    │  Encryption │    │  & HMAC     │       │
│   └─────────────┘    └─────────────┘    └─────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Cryptographic Stack

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Asymmetric Encryption** | RSA-2048 with OAEP | Key exchange, hybrid encryption |
| **Symmetric Encryption** | AES-256-GCM | File content encryption |
| **Digital Signatures** | RSA-PSS with SHA-256 | Authentication, non-repudiation |
| **Key Derivation** | PBKDF2-SHA256 | Password-based key derivation |
| **Certificates** | X.509 v3 | Identity verification |
| **Hash Functions** | SHA-256 | Integrity verification |

### Hybrid Encryption Flow

```
┌────────────────────────────────────────────────────────────────┐
│                    HYBRID ENCRYPTION FLOW                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  SENDER                         RECIPIENT                      │
│    │                               │                           │
│    │  1. Generate random AES-256 key                           │
│    │  2. Encrypt file content with AES-256-GCM                 │
│    │  3. Encrypt AES key with recipient's RSA public key       │
│    │  4. Sign encrypted package with sender's private key      │
│    │  5. Send: [Encrypted File + Encrypted Key + IV + Tag + Sig]│
│    │  6. Verify signature with sender's public key             │
│    │  7. Decrypt AES key with recipient's RSA private key      │
│    │  8. Decrypt file content with AES-256-GCM                 │
│    │  9. Verify file integrity with SHA-256 hash               │
│    │                               │                           │
└────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Run Locally
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python securefile.py

# Run tests
python securefile.py --test
```

### Run with Docker
```bash
# Build the image
docker build -t secureshare-pro .

# Run the application
docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v $(pwd)/data:/app/data secureshare-pro
```

### Pull from GitHub Container Registry
```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Pull the image
docker pull ghcr.io/USERNAME/securepro:latest

# Run
docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix \
    ghcr.io/USERNAME/securepro:latest
```

## 📦 Docker Usage

### Building Locally

```bash
# Clone the repository
git clone https://github.com/USERNAME/securepro.git
cd securepro

# Build Docker image
docker build -t secureshare-pro:latest .

# Run with X11 forwarding (for GUI)
xhost +local:docker
docker run -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v $(pwd)/secure_vault:/app/secure_vault \
    -v $(pwd)/data:/app/data \
    --network host \
    secureshare-pro:latest
```

### Using GitHub Container Registry

```bash
# Authenticate
docker login ghcr.io -u GITHUB_USERNAME -p GITHUB_TOKEN

# Pull latest release
docker pull ghcr.io/USERNAME/securepro:latest

# Run container
docker run -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v secureshare_data:/app/secure_vault \
    ghcr.io/USERNAME/securepro:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  secureshare-pro:
    image: ghcr.io/USERNAME/securepro:latest
    container_name: secureshare-pro
    environment:
      - DISPLAY=${DISPLAY}
    volumes:
      - /tmp/.X11-unix:/tmp/.X11-unix:ro
      - ./data:/app/data
      - ./secure_vault:/app/secure_vault
    network_mode: host
    restart: unless-stopped
```

## 🔐 Security Features

### Implemented Security Mechanisms

1. **PKI Infrastructure**
   - RSA-2048 key pair generation
   - X.509 self-signed certificates
   - Certificate storage and retrieval

2. **Hybrid Encryption**
   - AES-256-GCM for file encryption (fast, symmetric)
   - RSA-OAEP for key encryption (secure, asymmetric)
   - Perfect forward secrecy

3. **Digital Signatures**
   - RSA-PSS with SHA-256
   - Non-repudiation
   - Tamper detection

4. **Key Protection**
   - PBKDF2 key derivation (100,000 iterations)
   - Salted keys
   - Password-protected private keys

5. **Attack Prevention**
   - Tamper detection (signature verification)
   - Replay protection (timestamps)
   - Integrity verification (SHA-256 hashes)

### Security Verification

```bash
# Run security tests
python securefile.py --test

# Run static analysis
bandit -r .

# Run code quality
pylint securefile.py
```

## 📁 Project Structure

```
securepro/
├── securefile.py              # Main application (GUI + Crypto)
├── Dockerfile                 # Docker build file
├── requirements.txt           # Python dependencies
├── .github/
│   └── workflows/
│       └── main.yml          # CI/CD pipeline
├── tests/
│   ├── __init__.py
│   └── test_securefile.py    # Unit tests (20 tests)
├── secure_vault/              # Key storage (simulated HSM)
│   ├── keys.json
│   ├── certificates.json
│   └── shared_files.json
├── certs/                     # Certificate storage
│   └── monika.pem
├── keystores/                 # Key store
│   └── monika.p12
├── trusted_certs/             # Trusted certificates
└── .gitignore                 # Git ignore rules
```

## 🧪 Testing

### Unit Tests Coverage

```bash
# Run all tests
pytest tests/test_securefile.py -v

# Test results
tests/test_securefile.py::TestCryptoEngine - 7 tests
tests/test_securefile.py::TestKeyVault - 4 tests
tests/test_securefile.py::TestSecureFileSharingSystem - 6 tests
tests/test_securefile.py::TestIntegration - 2 tests
```

### Test Categories

| Test Class | Tests | Coverage |
|------------|-------|----------|
| TestCryptoEngine | 7 | Key generation, encryption, signatures |
| TestKeyVault | 4 | Key storage, certificate management |
| TestSecureFileSharingSystem | 6 | User management, file operations |
| TestIntegration | 2 | Complete workflow, tamper detection |

## 🚢 CI/CD Pipeline

### GitHub Actions Workflow

The CI/CD pipeline automatically:
1. Runs on every push and pull request
2. Executes PyLint for code quality
3. Runs Bandit for security analysis
4. Executes all unit tests
5. Builds and pushes Docker image on version tags
6. Creates GitHub releases

### Workflow Triggers

```yaml
on:
  push:
    branches: ["**"]        # All branches
  pull_request:
    branches: ["**"]        # All PRs
  tags:
    - "v*"                  # Version tags (releases)
  workflow_dispatch:         # Manual trigger
```

## 🔮 Future Development

### Planned Features

1. **Enhanced PKI**
   - Certificate Authority (CA) support
   - Certificate chain validation
   - CRL (Certificate Revocation List) support
   - OCSP (Online Certificate Status Protocol)

2. **Advanced Cryptography**
   - Elliptic Curve Cryptography (ECC)
   - Post-quantum cryptography readiness
   - Homomorphic encryption (research)

3. **Network Features**
   - Secure peer-to-peer file transfer
   - Encrypted messaging
   - Group file sharing
   - Secure key exchange protocol

4. **Enterprise Features**
   - LDAP/Active Directory integration
   - Multi-factor authentication
   - Audit logging
   - HSM integration
   - Role-based access control

5. **UI/UX Improvements**
   - Web interface
   - Mobile app
   - CLI interface
   - Dark/Light theme toggle

6. **Deployment Options**
   - Kubernetes deployment
   - Docker Compose production stack
   - Cloud deployment (AWS, GCP, Azure)
   - IoT device support

### Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your feature
4. Add tests for new functionality
5. Submit a pull request

## 📚 Documentation

### Core Documentation
- **securefile.py** - Main application with comprehensive docstrings
- **tests/test_securefile.py** - 20 unit tests with examples
- **.github/workflows/main.yml** - CI/CD pipeline configuration

### Additional Resources
- [Architecture Guide](#-architecture-design)
- [Security Features](#-security-features)
- [Docker Usage](#-docker-usage)
- [Testing Guide](#-testing)

## 🛡️ Security Considerations

### For Production Use

1. **Key Management**
   - Use hardware security modules (HSM)
   - Implement key rotation policies
   - Secure key backup procedures

2. **Certificate Management**
   - Use trusted CA certificates
   - Implement certificate expiration monitoring
   - Establish revocation procedures

3. **Access Control**
   - Strong password policies
   - Multi-factor authentication
   - Audit logging

4. **Network Security**
   - TLS for all communications
   - Firewall rules
   - Intrusion detection

### Security Limitations

- Self-signed certificates (development only)
- Simulated HSM (use real HSM for production)
- Local-only key storage (consider cloud KMS)

## 📄 License

This project is for educational purposes as part of the ST6051CEM - Practical Cryptography module.

## 👤 Author

**SecureShare Pro**
- Module: ST6051CEM - Practical Cryptography
- Student: [Your Name]
- Student ID: [Your ID]

---

## 🎯 Quick Reference

| Task | Command |
|------|---------|
| Run application | `python securefile.py` |
| Run tests | `pytest tests/test_securefile.py -v` |
| Security scan | `bandit -r . --exit-zero` |
| Code quality | `pylint securefile.py || true` |
| Build Docker | `docker build -t secureshare-pro .` |
| Run Docker | `docker run secureshare-pro` |

---

**🔐 SecureShare Pro - Military-Grade Encryption Made Simple** 🔐

```bash
# Get started
python securefile.py
```

