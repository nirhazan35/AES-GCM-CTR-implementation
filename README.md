
---

# AES Secure Communication Project

This project demonstrates **secure client-server communication** using:
1. **AES-GCM** for authenticated encryption (confidentiality + integrity).
2. **AES-CTR** for confidential encryption without integrity protection.

Each mode has its own **client** and **server** implementation, and a **test suite** is provided to verify functionality and security properties.

---

## Features

- **AES-GCM**: Authenticated encryption (with integrity checks).
- **AES-CTR**: Confidential encryption (no integrity checks).
- **Python-based servers** listening on **different UDP ports**:
  - GCM Server → port **9999**.
  - CTR Server → port **9998**.
- **Clients** for each mode that **register** with the server by sending their name, then **send** and **receive** encrypted messages.
- **Tests** covering:
  - AES CTR and GCM encryption/decryption correctness.
  - Client-server message passing.
  - Security properties (confidentiality, tampering detection, etc.).

---

## Installation & Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/nirhazan35/AES-GCM-CTR-implementation.git
   cd AES-GCM-CRT-implementation
   ```

2. **Create a Virtual Environment & Activate**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On macOS/Linux
   venv\Scripts\activate     # On Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set the AES Key**
   - Copy or create a `.env` file in the root directory with:
     ```ini
     AES_KEY=<hex-encoded key of 16, 24, or 32 bytes>
     ```
     For example, a 256-bit (32-byte) key:
     ```ini
     AES_KEY=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
     ```
   - This key will be used by **both** the GCM and CTR servers/clients.
   

---

## Usage

### 1. Running the AES-GCM Server & Client
- **Server** (AES-GCM on port 9999):
  ```bash
  python server_GCM.py
  ```
  You should see `Server started on port 9999`.

- **Client** (AES-GCM):
  ```bash
  python client_GCM.py
  ```
  - Enter a **unique name** when prompted.  
  - Use `recipient_name|message` to send a message to another registered client.

#### Example: Two GCM Clients
1. **Terminal A**: `python server_GCM.py`
2. **Terminal B**:  
   ```bash
   python client_GCM.py
   # Enter: GCMClient1
   ```
   - Send: `GCMClient2|Hello from GCMClient1!`
3. **Terminal C**:  
   ```bash
   python client_GCM.py
   # Enter: GCMClient2
   ```
   - Receive: `Hello from GCMClient1!`

---

### 2. Running the AES-CTR Server & Client
- **Server** (AES-CTR on port 9998):
  ```bash
  python server_CTR.py
  ```
  You should see `Server started on port 9998`.

- **Client** (AES-CTR):
  ```bash
  python client_CTR.py
  ```
  - Enter a **unique name** when prompted.  
  - Use `recipient_name|message` to send a message to another registered client.

#### Example: Two CTR Clients
1. **Terminal A**: `python server_CTR.py`
2. **Terminal B**:  
   ```bash
   python client_CTR.py
   # Enter: CTRClient1
   ```
   - Send: `CTRClient2|Hello from CTRClient1!`
3. **Terminal C**:  
   ```bash
   python client_CTR.py
   # Enter: CTRClient2
   ```
   - Receive: `Hello from CTRClient1!`

> **Note:** AES-CTR **does not** provide message integrity. Tampering is not detected.

---

## Running Tests

This project includes multiple tests:

| File                            | Description                                                           |
|---------------------------------|-----------------------------------------------------------------------|
| **`test_aes_ctr.py`**           | Validates AES-CTR unit tests (key/nonce sizes, encryption/decryption) |
| **`test_aes_gcm.py`**           | Validates AES-GCM unit tests (encryption/decryption, auth tags)       |
| **`test_client_server_ctr.py`** | Tests client-server flow using AES-CTR                                |
| **`test_client_server_gcm.py`** | Tests client-server flow using AES-GCM                                |
| **`test_security_properties.py`** | Tests confidentiality and integrity properties across modes         |

### 1. Run All Tests
```bash
pytest -v
```

### 2. Run Individual Tests
- **AES-CTR Tests**:
  ```bash
  pytest -v test_aes_ctr.py test_client_server_ctr.py
  ```
- **AES-GCM Tests**:
  ```bash
  pytest -v test_aes_gcm.py test_client_server_gcm.py
  ```
- **Security Property Tests**:
  ```bash
  pytest -v test_security_properties.py
  ```

---

## Key Points

1. **AES Key**  
   - Stored in `.env` under `AES_KEY` (hex-encoded, 128/192/256 bits).  
   - Must be identical for the server and clients to decrypt each other’s traffic.

2. **Server Ports**  
   - **server_GCM**: default UDP port **9999**.  
   - **server_CTR**: default UDP port **9998**.

3. **No Integrity in CTR**  
   - AES-CTR does not detect tampering.  
   - AES-GCM includes an authentication tag for integrity checks.

4. **UDP Protocol**  
   - Communication uses UDP. Packet loss or reordering could occur in real-world scenarios.

---