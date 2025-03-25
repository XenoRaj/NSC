import socket
import json
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
# Generate Client Key Pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize Public Key
pub_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def load_ca_public_key():
    with open("ca_public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

ca_public_key = load_ca_public_key()

def send_request(request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 5000))
        s.send(json.dumps(request).encode())
        response = s.recv(4096).decode()
        return json.loads(response)

def get_certificate(client_id):
    # Request a Signed Certificate from CA for self
    # client_id = "Client_B"
    request = {"type": "get_cert", "client_id": client_id, "public_key": pub_key_pem.decode()}
    response = send_request(request)

    if response["status"] == "success":
        print(f"Certificate received:\n{json.dumps(response['certificate'], indent=4)}")
    else:
        print("Failed to get certificate.")

def handle_messages(client_socket):
    try:
        data = client_socket.recv(4096).decode()
        request = json.loads(data)
        
        if(request["type"] == "greetings"):
            if(request["message"] == "hello1"):
                response = {"type": "acknolegement", "status": "success", "message": "ack1"}
                client_socket.send(json.dumps(response).encode())
            elif(request["message"] == "hello2"):
                response = {"type": "acknolegement", "status": "success", "message": "ack2"}
                client_socket.send(json.dumps(response).encode())
            elif(request["message"] == "hello3"):
                response = {"type": "acknolegement", "status": "success", "message": "ack3"}
                client_socket.send(json.dumps(response).encode())
            else:
                print("Unknown message")
                response = {"type": "acknolegement", "status": "error", "message": "Unknown message"}
                client_socket.send(json.dumps(response).encode())
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
    request = {"type": "register", "client_id": client_id, "public_key": pub_key_pem.decode()}
    response = send_request(request)

    if response["status"] == "success":
        print(f"Certificate received:\n{json.dumps(response['certificate'], indent=4)}")
    else:
        print("Failed to get certificate.")
    threading.Thread(target=start_client).start()

