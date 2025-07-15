#include <WiFi.h>
#include <DHT.h>

// Wi-Fi credentials
const char* ssid = "Your-SSID";
const char* password = "Your-Password";

// DHT sensor setup
#define DHTPIN 4
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// HTTP server on port 80
WiFiServer server(80);

void setup() {
  Serial.begin(115200);
  dht.begin();

  // Connect to Wi-Fi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
  Serial.println(WiFi.localIP());

  // Start the server
  server.begin();
}

void loop() {
  WiFiClient client = server.available();
  if (client) {
    String request = client.readStringUntil('\r');
    client.flush();

    // Read sensor data
    float humidity = dht.readHumidity();
    float temperature = dht.readTemperature();

    // Prepare the HTTP response
    client.println("HTTP/1.1 200 OK");
    client.println("Content-type:text/plain");
    client.println();
    client.print("Humidity: ");
    client.print(humidity);
    client.print("%\nTemperature: ");
    client.print(temperature);
    client.println("C");
    client.println();

    delay(1);
    client.stop();
  }
}