import socket
import os
import json
import base64
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timezone

# Server configuration
HOST = '127.0.0.1'  # Localhost
PORT = 5000         # Port to listen on

# Directory where the PDF files are stored
GRADESHEET_DIRECTORY = "gradesheets"
CERTIFICATE_DIRECTORY = "certificates"

# Directory to store the public key
PUBLIC_KEY_FILE = "server_public_key.pem"

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Save the public key to a file
with open(PUBLIC_KEY_FILE, "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
print(f"Server: Public key saved to '{PUBLIC_KEY_FILE}'")


passwords = {
    "BT24CS1000" : "1024",
    "BT24CS1001" : "1025",
    "BT24CS1002" : "1026",
    "BT24CS1003" : "1027",
    "BT24CS1004" : "1028",
    "BT24CS1005" : "1029",
    "BT24CS1006" : "1030",
    "BT24CS1007" : "1031",
    "BT24CS1008" : "1032",
    "BT24CS1009" : "1033",
    "BT24CS1010" : "1034",
}


def get_gmt_time():
    """Fetch the current GMT time from Google's time API, with a fallback to the system clock."""
    try:
        # Use Google's time API to fetch the current UTC time
        response = requests.get("https://timeapi.io/api/Time/current/zone?timeZone=UTC", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data["dateTime"]  # ISO 8601 format, e.g., "2025-04-13T12:34:56.789Z"
        else:
            raise Exception("Failed to fetch GMT time from Google's time API")
    except Exception as e:
        print(f"Server: Error fetching GMT time from Google's time API - {e}")
        # Fallback to system clock
        print("Server: Falling back to system clock for GMT time.")
        return datetime.now(timezone.utc).isoformat()

def sign_data(data):
    """Sign the hash of the data using the server's private key."""
    hash_value = hashes.Hash(hashes.SHA256())
    hash_value.update(data)
    digest = hash_value.finalize()

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def handle_client(client_socket):
    try:
        # Receive the encrypted message from the client
        encrypted_message = client_socket.recv(4096)
        print(f"Server: Received encrypted message.")

        # Decrypt the message using the server's private key
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decode the decrypted message
        request = json.loads(decrypted_message.decode())
        roll_no = request["roll_no"]
        user_name = request["user_name"]
        pin = request["pin"]

        if(pin!= passwords[roll_no]):
            error_message = "Error: Invalid PIN."
            client_socket.sendall(error_message.encode())
            print(f"Server: {error_message}")
            return
        
        print(f"Server: Decrypted request from '{user_name}' with roll number '{roll_no}'")

        # Fetch the current GMT time
        gmt_time = get_gmt_time()
        if not gmt_time:
            client_socket.sendall("Error: Unable to fetch GMT time.".encode())
            return

        # Check if the requested file exists
        gradesheet_name = f"{roll_no}_gradesheet.pdf"
        certificate_name = f"{roll_no}_certificate.pdf"
        if gradesheet_name in os.listdir(GRADESHEET_DIRECTORY) and certificate_name in os.listdir(CERTIFICATE_DIRECTORY):
            # Construct the file paths
            gradesheet_path = os.path.join(GRADESHEET_DIRECTORY, gradesheet_name)
            certificate_path = os.path.join(CERTIFICATE_DIRECTORY, certificate_name)

            with open(gradesheet_path, "rb") as f:
                gradesheet_data = f.read() + gmt_time.encode()  # Embed timestamp
            
            with open(certificate_path, "rb") as f:
                certificate_data = f.read() + gmt_time.encode()  # Embed timestamp
            
            # Sign the hashes of the files
            gradesheet_signature = sign_data(gradesheet_data)
            certificate_signature = sign_data(certificate_data)

            # Encode binary data as Base64 strings
            response = {
                "gradesheet": base64.b64encode(gradesheet_data).decode("utf-8"),
                "certificate": base64.b64encode(certificate_data).decode("utf-8"),
                "gmt_time": gmt_time,
                "gradesheet_signature": base64.b64encode(gradesheet_signature).decode("utf-8"),
                "certificate_signature": base64.b64encode(certificate_signature).decode("utf-8")
            }

            # Send the response as JSON
            client_socket.sendall(json.dumps(response).encode())
            print(f"Server: Sent files and signatures to the client.")
        else:
            # Send an error message if the file is not found
            error_message = "Error: Requested file not found."
            client_socket.sendall(error_message.encode())
            print(f"Server: {error_message}")
    except Exception as e:
        print(f"Server: Error handling client - {e}")
    finally:
        # Close the connection
        client_socket.close()

def start_server():
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server: Listening on {HOST}:{PORT}")

    try:
        while True:
            # Accept a new client connection
            client_socket, client_address = server_socket.accept()
            print(f"Server: Connection from {client_address}")

            # Handle the client in a separate function
            handle_client(client_socket)
    except KeyboardInterrupt:
        print("\nServer: Shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()