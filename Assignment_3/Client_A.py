import socket
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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
    

def get_encrypted_request(request, b_public_key, a_private_key):
    request_bytes = json.dumps(request).encode()

    # Encrypt with B's Public Key
    encrypted_request = b_public_key.encrypt(
        request_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Sign with A's Private Key
    signature = a_private_key.sign(
        request_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return {
        "encrypted_request": encrypted_request.hex(),
        "signature": signature.hex(),
        "client_id": "Client_A"
    }

def decrypt_and_verify(encrypted_data, a_private_key, b_public_key):
    encrypted_request = bytes.fromhex(encrypted_data["encrypted_request"])
    signature = bytes.fromhex(encrypted_data["signature"])

    # Decrypt with B's Private Key
    decrypted_request = a_private_key.decrypt(
        encrypted_request,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Verify Signature with A's Public Key
    try:
        b_public_key.verify(
            signature,
            decrypted_request,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid...")
    except:
        print("Signature verification failed...")

    return json.loads(decrypted_request.decode())

def send_message_to_B(message, b_public_key):
    request = {"type" : "greetings", "client_id" : "Client_A", "message" : message}

    encypted_request = get_encrypted_request(request, b_public_key, a_private_key)
    response = send_request_to_B(encypted_request)
    
    decrypted_response = decrypt_and_verify(response, a_private_key, b_public_key)
    if decrypted_response["status"] == "success":
        print(f"Reply from B: {decrypted_response['message']}")
    else:
        print(f"Bad response from B: {decrypted_response['message']}")
    return decrypted_response["message"]


def start_client_A():
    
    if("Client_B" not in personal_certificate_store):    
        certificate_b = fetch_certificate("Client_B")
    else:
        certificate_b = personal_certificate_store["Client_B"]
        if(certificate_b["original_certificate"]["issued_at"] + certificate_b["original_certificate"]["validity"] < time.time()):
            certificate_b = fetch_certificate("Client_B")
    
    personal_certificate_store["Client_B"] = certificate_b
    b_public_key = serialization.load_pem_public_key(certificate_b["original_certificate"]["public_key"].encode())
    if(certificate_b != None):
        try:
            print("Sending messages to B...")

            print("Message 1: hello1")
            reply = send_message_to_B("hello1", b_public_key)  
            assert reply == "ack1"

            print("Message 2: hello2")
            reply = send_message_to_B("hello2", b_public_key)
            assert reply == "ack2"

            print("Message 3: hello3")
            reply = send_message_to_B("hello3", b_public_key)
            assert reply == "ack3"

            print("All messages sent successfully...")
            print("Client A exiting...")
        except Exception as e:
            print(f"Error: {e}")
        

        



# Request a Signed Certificate from CA
if __name__ == "__main__":
    client_id = "Client_A"
    # Generate Client Key Pair
    a_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    a_public_key = a_private_key.public_key()

    # Serialize Public Key
    a_pub_key_pem = a_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    request = {"type": "register", "client_id": client_id, "public_key": a_pub_key_pem.decode()}
    response = send_request_to_CA(request)

    personal_certificate_store = {}

    if response["status"] == "success":
        print(f"Certificate registered...")
    else:
        print("Failed to get certificate.")
    
    ca_public_key = load_ca_public_key()
        # Save A Public Key to a File
    threading.Thread(target=start_client_A).start()

