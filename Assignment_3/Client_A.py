import socket
import json
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
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
    

def send_request_to_B(request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 5001))
        s.send(json.dumps(request).encode())
        response = s.recv(4096).decode()
        
        return json.loads(response)
    
def fetch_certificate(client_id):
    request = {"type" : "get_cert", "client_id" : client_id}
    response = send_request_to_CA(request)
    if response["status"] == "success" :
        print(f"B's Certificate received...")
        if verify_certificate(response["certificate"]["encrypted_certificate"], response["certificate"]["original_certificate"]):
            print(f"Certificate verified...")
            return response["certificate"]
        else:
            print(f"Certificate verification failed...")
            return None
    else:
        print("Failed to get certificate.")
        return None

def send_message_to_B(message):
    request = {"type" : "greetings", "client_id" : "Client_A", "message" : message}
    response = send_request_to_B(request)

    if response["status"] == "success":
        print(f"Reply from B: {response['message']}")
    else:
        print(f"Bad response from B: {response['message']}")
    return response["message"]


def start_client_A():
   
    certificate = fetch_certificate("Client_B")
    if(certificate != None):
        try:
            print("Sending messages to B...")

            print("Message 1: hello1")
            reply = send_message_to_B("hello1")  
            assert reply == "ack1"

            print("Message 2: hello2")
            reply = send_message_to_B("hello2")
            assert reply == "ack2"

            print("Message 3: hello3")
            reply = send_message_to_B("hello3")
            assert reply == "ack3"

            print("All messages sent successfully...")
            print("Client A exiting...")
        except Exception as e:
            print(f"Error: {e}")
        

        



# Request a Signed Certificate from CA
if __name__ == "__main__":
    client_id = "Client_A"
    request = {"type": "register", "client_id": client_id, "public_key": pub_key_pem.decode()}
    response = send_request_to_CA(request)

    if response["status"] == "success":
        print(f"Certificate registered...")
    else:
        print("Failed to get certificate.")
    
    ca_public_key = load_ca_public_key()
    threading.Thread(target=start_client_A).start()

