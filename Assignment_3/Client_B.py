import socket
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
# Generate Client Key Pair
b_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
b_public_key = b_private_key.public_key()

# Serialize Public Key
b_pub_key_pem = b_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def load_ca_public_key():
    with open("ca_public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

ca_public_key = load_ca_public_key()

def verify_certificate(signed_cert_hex, cert_data):
    signed_cert = bytes.fromhex(signed_cert_hex)
    cert_bytes = json.dumps(cert_data).encode()

    try:
        # Verifying signature using the **CA's Public Key**
        ca_public_key.verify(
            signed_cert,
            cert_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True  # Signature is valid
    except:
        return False  # Invalid certificate


def send_request_to_CA(request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 5000))
        s.send(json.dumps(request).encode())
        response = s.recv(4096).decode()
        return json.loads(response)


def fetch_certificate(client_id):
    request = {"type" : "get_cert", "client_id" : client_id}
    response = send_request_to_CA(request)
    if response["status"] == "success" :
        print(f"{client_id}'s Certificate received...")
        if verify_certificate(response["certificate"]["encrypted_certificate"], response["certificate"]["original_certificate"]):
            print(f"Certificate verified...")
            return response["certificate"]
        else:
            print(f"Certificate verification failed...")
            return None
    else:
        print("Failed to get certificate.")
        return None
    

def get_encrypted_request(request, a_public_key, b_private_key):
    request_bytes = json.dumps(request).encode()

    # Encrypt with B's Public Key
    encrypted_request = a_public_key.encrypt(
        request_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Sign with A's Private Key
    signature = b_private_key.sign(
        request_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return {
        "encrypted_request": encrypted_request.hex(),
        "signature": signature.hex()
    }

def decrypt_and_verify(encrypted_data, b_private_key, a_public_key):
    encrypted_request = bytes.fromhex(encrypted_data["encrypted_request"])
    
    signature = bytes.fromhex(encrypted_data["signature"])

    # Decrypt with B's Private Key
    decrypted_request = b_private_key.decrypt(
        encrypted_request,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Verify Signature with A's Public Key
    try:
        a_public_key.verify(
            signature,
            decrypted_request,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid....")
    except:
        print("Signature verification failed...")

    return json.loads(decrypted_request.decode())

def handle_messages(client_socket):
    try:
        data = client_socket.recv(4096).decode()
        request = json.loads(data)
        
        client_id = request["client_id"]
        if(client_id not in personal_certificate_store):
            certificate_a = fetch_certificate(client_id)
        else:
            certificate_a = personal_certificate_store[client_id]
            if(certificate_a["original_certificate"]["issued_at"] + certificate_a["original_certificate"]["validity"] < time.time()):
                certificate_a = fetch_certificate(client_id)       
        
        personal_certificate_store[client_id] = certificate_a

        a_public_key = serialization.load_pem_public_key(certificate_a["original_certificate"]["public_key"].encode())

        
        decrypted_request = decrypt_and_verify(request, b_private_key, a_public_key)
     
        if(decrypted_request["type"] == "greetings"):
            if(decrypted_request["message"] == "hello1"):
                response = {"type": "acknolegement", "status": "success", "message": "ack1"}
                encrypted_response = get_encrypted_request(response, a_public_key, b_private_key)

                client_socket.send(json.dumps(encrypted_response).encode())
            elif(decrypted_request["message"] == "hello2"):
                response = {"type": "acknolegement", "status": "success", "message": "ack2"}
                encrypted_response = get_encrypted_request(response, a_public_key, b_private_key)

                client_socket.send(json.dumps(encrypted_response).encode())
            elif(decrypted_request["message"] == "hello3"):
                response = {"type": "acknolegement", "status": "success", "message": "ack3"}
                encrypted_response = get_encrypted_request(response, a_public_key, b_private_key)

                client_socket.send(json.dumps(encrypted_response).encode())
            else:
                print("Unknown message")
                response = {"type": "acknolegement", "status": "error", "message": "Unknown message"}
                encrypted_response = get_encrypted_request(response, a_public_key, b_private_key)

                client_socket.send(json.dumps(encrypted_response).encode())
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()


def start_client(host="0.0.0.0", port=5001):
    client_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_B.bind((host, port))
    client_B.listen(5)
    print(f"[+] Client B running on {host}:{port}")

    try:
        while True:
            client_socket, addr = client_B.accept()
            print(f"[+] Connection from {addr}")
            threading.Thread(target=handle_messages, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Client B gracefully.")
    finally:
        client_B.close()

# Request a Signed Certificate from CA and then start the client for listening
if __name__ == "__main__":
    client_id = "Client_B"
    request = {"type": "register", "client_id": client_id, "public_key": b_pub_key_pem.decode()}
    response = send_request_to_CA(request)

    personal_certificate_store = {}

    if response["status"] == "success":
        print(f"Certificate received:")
    else:
        print("Failed to get certificate.")
        # 🔑 Save CA Public Key to a File
    threading.Thread(target=start_client).start()

