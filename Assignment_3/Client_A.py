import socket
import json
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

def send_request(request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 5000))
        s.send(json.dumps(request).encode())
        response = s.recv(4096).decode()
        return json.loads(response)

# Request a Signed Certificate from CA
client_id = "Client_A"
request = {"type": "register", "client_id": client_id, "public_key": pub_key_pem.decode()}
response = send_request(request)

if response["status"] == "success":
    print(f"Certificate received:\n{json.dumps(response['certificate'], indent=4)}")
else:
    print("Failed to get certificate.")
