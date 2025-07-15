import requests
import time

esp32_ip = "ip-address of ESP32"
interval = 1.5

print(f"Starting continuous data retrieval from ESP32 at {esp32_ip}...")

while True:
    try:
        # Send an HTTP GET request to the ESP32
        response = requests.get(f"http://{esp32_ip}/", timeout=5)

        if response.status_code == 200:
            print(f"Data from ESP32 at {time.ctime()}:")
            print(response.text)
        else:
            print(f"Failed to get data. Status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    time.sleep(interval)