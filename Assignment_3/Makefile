# Variables
PYTHON = python3
CA_SCRIPT = Certificate_Authority.py
CLIENT_A_SCRIPT = Client_A.py
CLIENT_B_SCRIPT = Client_B.py

# Default target
all:	run

# Start the Certificate Authority
start_ca:
	@echo "[+] Starting Certificate Authority..."
	$(PYTHON) $(CA_SCRIPT) &

# Start Client_B
start_client_b:
	@echo "[+] Starting Client_B..."
	$(PYTHON) $(CLIENT_B_SCRIPT) &

# Start Client_A
start_client_a:
	@echo "[+] Starting Client_A..."
	$(PYTHON) $(CLIENT_A_SCRIPT)

# Run all processes
run:	start_ca
	@sleep 5
	@$(MAKE) start_client_b
	@sleep 5
	@$(MAKE) start_client_a

# Kill all processes running on ports 5000 and 5001
clean:
	@echo "[+] Cleaning up processes on ports 5000 and 5001..."
	@sudo lsof -t -i:5000 -sTCP:LISTEN | xargs -r kill -9 || true
	@sudo lsof -t -i:5001 -sTCP:LISTEN | xargs -r kill -9 || true
	@echo "[+] Cleanup complete."

# Help target
help:
	@echo "Makefile for running the Certificate Authority and Clients"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Run the CA, Client_B, and Client_A in sequence"
	@echo "  start_ca       - Start the Certificate Authority"
	@echo "  start_client_b - Start Client_B"
	@echo "  start_client_a - Start Client_A"
	@echo "  clean          - Kill processes running on ports 5000 and 5001"
	@echo "  help           - Show this help message"