import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Server configuration
HOST = '127.0.0.1'  # Server's hostname or IP address
PORT = 5000         # Port used by the server
PUBLIC_KEY_FILE = "server_public_key.pem"

def load_server_public_key():
    """Load the server's public key from the file."""
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_signature(data, decrypted_signature, public_key):
    """Verify the signature of the data using the server's public key."""
    hash_value = hashes.Hash(hashes.SHA256())
    hash_value.update(data)
    digest = hash_value.finalize()

    try:
        # Compare the decrypted signature with the computed hash
        public_key.verify(
            decrypted_signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Client: Signature verification failed - {e}")
        return False

def request_files(roll_no, user_name, pin):
    try:
        # Load the server's public key
        server_public_key = load_server_public_key()

        # Create the request payload
        request = {
            "roll_no": roll_no,
            "user_name": user_name,
            "pin": pin
        }
        request_data = json.dumps(request).encode()

        # Encrypt the request using the server's public key
        encrypted_request = server_public_key.encrypt(
            request_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Create a socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))

        # Send the encrypted request to the server
        client_socket.sendall(encrypted_request)
        print(f"Client: Sent encrypted request for roll_no '{roll_no}' and user_name '{user_name}'.")

        # Receive the response from the server
        response_data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            response_data += chunk

        # Decode the response
        response_data = response_data.decode()
        if response_data.startswith("Error:"):
            print(f"Client: {response_data}")
        else:
            # Parse the JSON response
            response = json.loads(response_data)
            gradesheet_data = base64.b64decode(response["gradesheet"])
            certificate_data = base64.b64decode(response["certificate"])
            gmt_time = response["gmt_time"].encode()  # Convert timestamp to bytes
            gradesheet_signature = base64.b64decode(response["gradesheet_signature"])
            certificate_signature = base64.b64decode(response["certificate_signature"])

            try:
                # Verify the gradesheet signature
                if verify_signature(gradesheet_data, gradesheet_signature, server_public_key):
                    print("Client: Gradesheet signature is valid.")
                    gradesheet_file = f"{roll_no}_gradesheet.pdf"
                    with open(gradesheet_file, "wb") as f:
                        f.write(gradesheet_data)
                    print(f"Client: Saved gradesheet as '{gradesheet_file}'.")
                else:
                    print("Client: Gradesheet signature is invalid.")
            except Exception as e:
                print(f"Client: Error decrypting gradesheet signature - {e}")

            try:
               
                # Verify the certificate signature
                if verify_signature(certificate_data, certificate_signature, server_public_key):
                    print("Client: Certificate signature is valid.")
                    certificate_file = f"{roll_no}_certificate.pdf"
                    with open(certificate_file, "wb") as f:
                        f.write(certificate_data)
                    print(f"Client: Saved certificate as '{certificate_file}'.")
                else:
                    print("Client: Certificate signature is invalid.")
            except Exception as e:
                print(f"Client: Error decrypting certificate signature - {e}")

            # Print the GMT time
            print(f"Client: Verified GMT Time: {gmt_time.decode()}")
    except Exception as e:
        print(f"Client: Error - {e}")
    finally:
        # Close the connection
        client_socket.close()

if __name__ == "__main__":
    # Get user input
    roll_no = "BT24CS1001"
    user_name = "saloni"
    pin = "1025"
    # Request files from the server
    request_files(roll_no, user_name, pin)