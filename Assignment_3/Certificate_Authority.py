import socket
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# Function to sign a certificate
def issue_certificate(client_id, client_public_key):
    issue_time = int(time.time())
    duration = 3600  # Certificate valid for 1 hour

    cert_data = {
        "client_id": client_id,
        "public_key": client_public_key.decode(),
        "issued_at": issue_time,
        "validity": duration,
        "certificate_authority": "CA"
    }

    cert_bytes = json.dumps(cert_data).encode()
    
    encrypted_certificate = ca_private_key.sign(
        cert_bytes,
       padding.PKCS1v15(),
        hashes.SHA256()
    )

    return {"original_certificate": cert_data, "encrypted_certificate": encrypted_certificate.hex()}

# Handle Client Requests
def handle_client(client_socket):
    try:
        data = client_socket.recv(4096).decode()
        request = json.loads(data)
        
        if request["type"] == "register":
            # A client wants a signed certificate
            client_id = request["client_id"]
            client_public_key = request["public_key"].encode()

            # client_public_key = load_public_key(client_id)
            
            cert = issue_certificate(client_id, client_public_key)
            certificates[client_id] = cert
            # print(certificates)
            response = {"status": "success", "certificate": cert}
            client_socket.send(json.dumps(response).encode())
            print("CA: Client Registered...")

        elif request["type"] == "get_cert":
            # A client wants another client's certificate
            requested_id = request["client_id"]
            
            if requested_id in certificates:
                response = {"status": "success", "certificate": certificates[requested_id]}
            else:
                response = {"status": "error", "message": "Certificate not found"}
            
            client_socket.send(json.dumps(response).encode())
            print("CA: Certificate sent...")

    except Exception as e:
        print(f"CA: Error handling client: {e}")
    finally:
        client_socket.close()

# def load_public_key(client_id):
#     client = client_id[-1].lower()
#     print(f"{client}_public_key.pem")
#     with open(f"{client}_public_key.pem", "rb") as f:
#         return serialization.load_pem_public_key(f.read())
    
# Start CA Server
def start_ca_server(host="0.0.0.0", port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"CA: [+] CA Server running on {host}:{port}")

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"CA: [+] Connection from {addr}")
            threading.Thread(target=handle_client, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("\nCA: [!] Shutting down CA Server gracefully.")
    finally:
        server.close()
        print("CA: [+] CA Server closed.")

if __name__ == "__main__":
    # Generate CA Key Pair (Public/Private)
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_public_key = ca_private_key.public_key()

    # Save CA Public Key to a File
    with open("ca_public_key.pem", "wb") as f:
        f.write(
            ca_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    # Dictionary to store client certificates
    certificates = {}

    start_ca_server()