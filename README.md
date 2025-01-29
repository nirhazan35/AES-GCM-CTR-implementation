# AES-GCM Secure Communication Project

This project provides a secure client-server communication system using **AES-GCM encryption** to ensure confidentiality and integrity. The system consists of an **AES-GCM encryption module**, a **server**, and a **client**. The project includes a comprehensive test suite to validate security and functionality.

## Features
✅ AES-GCM encryption for secure message transmission  
✅ HMAC-based authentication for integrity verification  
✅ Secure key management and IV handling  
✅ Client-server communication over UDP  
✅ Comprehensive unit and integration tests  

---

## Installation & Setup

### **1. Clone the Repository**
```sh
 git clone https://github.com/nirhazan35/AES-GCM-implementation.git
 cd AES-GCM-implementation
```

### **2. Set Up a Virtual Environment**
```sh
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate    # On Windows
```

### **3. Install Dependencies**
```sh
pip install -r requirements.txt
```

---

## Running the Project

### **Start the Server**
Run the server to listen for incoming encrypted messages:
```sh
python server.py
```

### **Start a Client**
Run a client to send messages securely:
```sh
python client.py
```
The client will prompt you for a name and allow you to send encrypted messages to other connected clients.

### **Communication Example**
This is how you send messages to other clients:
```sh
<reciever_name>|<message>
```

### **Simulating Two Clients Communicating**
1. **Start the server** in a separate terminal:
   ```sh
   python server.py
   ```
2. **Start the first client**:
   ```sh
   python client.py
   ```
   - Enter `Client1` as the name.
3. **Start the second client** in another terminal:
   ```sh
   python client.py
   ```
   - Enter `Client2` as the name.
4. **Send a message from Client1 to Client2**:
   - Type: `Client2|Hello, this is Client1!`
   - Press Enter.
5. **Verify the message**:
   - Client2 should receive: `Hello, this is Client1!`

---

## **Project Structure**
```
AES-GCM-implementation/
│-- aes_gcm.py          # AES-GCM encryption & decryption
│-- client.py           # Client for sending secure messages
│-- server.py           # Server for handling secure communication
│-- test_aes_gcm.py     # Unit tests for AES-GCM module
│-- test_client_server.py # Integration tests for client-server communication
│-- requirements.txt    # Python dependencies
│-- README.md           # Project documentation
```

---

## Running Tests
The project includes comprehensive tests to ensure security and functionality.

### **Run All Tests**
```sh
pytest -v
```

### **Run AES-GCM Encryption Tests**
```sh
pytest -v test_aes_gcm.py
```

### **Run Client-Server Communication Tests**
```sh
pytest -v test_client_server.py
```

### **Understanding the Tests**
✅ **`test_aes_gcm.py`**: Tests encryption, decryption, authentication, and edge cases.  
✅ **`test_client_server.py`**: Tests message transmission, encryption integrity, and client-server interactions.  


---

## License
This project is licensed under the MIT License.

---

## Contact
For questions or contributions, reach out to the project maintainers.

