import subprocess
import time
import threading

# Function to run the Certificate Authority (CA)
def run_certificate_authority():
    print("[+] Starting Certificate Authority...")
    subprocess.run(["python3", "Certificate_Authority.py"])

# Function to run Client_A
def run_client_a():
    print("[+] Starting Client_A...")
    subprocess.run(["python3", "Client_A.py"])

# Function to run Client_B
def run_client_b():
    print("[+] Starting Client_B...")
    subprocess.run(["python3", "Client_B.py"])

if __name__ == "__main__":
    # Start the Certificate Authority in a separate thread
    ca_thread = threading.Thread(target=run_certificate_authority, daemon=True)
    ca_thread.start()

    # Wait for the CA to start
    time.sleep(2)

    # Start Client_B in a separate thread
    client_b_thread = threading.Thread(target=run_client_b, daemon=True)
    client_b_thread.start()

    # Wait for Client_B to start
    time.sleep(2)

    # Start Client_A in a separate thread
    client_a_thread = threading.Thread(target=run_client_a, daemon=True)
    client_a_thread.start()

    # Wait for all threads to complete
    ca_thread.join()
    client_b_thread.join()
    client_a_thread.join()