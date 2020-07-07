#include <Arduino.h>
#include <EEPROM.h>

#include <config.h>

#include <WiFi.h>
#include <WiFiUdp.h>
WiFiUDP mcast;
WiFiUDP ntpUDP;

#include <NTPClient.h>
NTPClient timeClient(ntpUDP, "europe.pool.ntp.org", 0, 300 * 1000);

#include <ArduinoJson.h>
StaticJsonDocument<1024> xAALMessage;
StaticJsonDocument<1024> xAALPayload;

#include <Crypto.h>
#include <ChaChaPoly.h>
ChaChaPoly chacha;

#include <byteswap.h>
#include <libb64/cencode.h>

#include <HX711.h>

const int LOADCELL_DOUT_PIN = 13;
const int LOADCELL_SCK_PIN = 12;

HX711 scale;
float calibration_factor = 2400 ; // Defines calibration factor we'll use for calibrating.

#define IETF_ABITES  16
typedef union {
  unsigned char buf[12];
  struct {
    uint64_t sec;
    uint32_t usec; };
} nonce_t;

void wifiInit() {
  Serial.print("# Init WiFi\n");
  WiFi.begin(SSID, PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  Serial.print("# WiFi connected\n");
  Serial.print("# IP address: ");
  Serial.println(WiFi.localIP());
  mcast.beginMulticast(IPAddress(224,0,29,200),PORT);
}

void xAALSend() {
  unsigned long sec,usec;
  char buf[1024];
  nonce_t nonce;
  uint8_t *cypher; 
  uint16_t size;
  int b64_len;
  char *b64;
  base64_encodestate b64_state;
  
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("# Error: no network\n");
    return;
  }
  sec = timeClient.getEpochTime();
  usec = millis();
  // load the payload
  serializeJson(xAALPayload, buf);
  printf("%s",buf);
  // Init chacha cipher 
  chacha.clear();
  chacha.setKey(XAAL_KEY,32);
  // Nonce 
  nonce.sec =  __bswap_64(sec);
  nonce.usec = __bswap_32(usec);
  chacha.setIV(nonce.buf,12);
  // additionnal data
  chacha.addAuthData("[]",2);
  // let's cipher & tag the buf
  size = strlen(buf);
  cypher = (uint8_t *) malloc(sizeof(uint8_t) * (size + IETF_ABITES));
  chacha.encrypt(cypher,(const uint8_t*)buf,size);
  // in combined mode ChachaPoly provide auth tag after ciphered data
  chacha.computeTag(cypher+size,IETF_ABITES);
  size = size + IETF_ABITES;
  // let's base64 encode the payload
  // add one byte for NULL end, if not free() will crash.
  b64_len = base64_encode_expected_len(size) + 1 ; 
  b64 = (char *) malloc(b64_len);
  base64_init_encodestate(&b64_state);
  b64_len = base64_encode_block((const char*)cypher, size, b64, &b64_state);
  b64_len += base64_encode_blockend(b64+b64_len, &b64_state);
  // xAAL header
  xAALMessage.clear();
  xAALMessage["version"] = "0.5";
  xAALMessage["targets"] = "[]";
  JsonArray timestamp = xAALMessage.createNestedArray("timestamp");
  timestamp.add(sec);
  timestamp.add(usec);
  xAALMessage["payload"] = b64;
  // forge the packet & send it
  serializeJson(xAALMessage, buf);
  Serial.println(buf);
  mcast.beginMulticastPacket();
  mcast.write((uint8_t *) &buf,strlen((char *) &buf));
  mcast.endPacket();
  free(b64);
  free(cypher);
}

void ntpInit() {
  timeClient.update();
  Serial.println("# Time : " + timeClient.getFormattedTime());
}

void HX711Init() {
  Serial.print("\n# Init HX711\n");
  Serial.println("Initializing scale calibration.");  // Prints user commands.
  Serial.println("Please remove all weight from scale.");
  Serial.println("Place known weights on scale one by one.");
  scale.begin(LOADCELL_DOUT_PIN, LOADCELL_SCK_PIN);   // Initializes the scaling process.
  scale.set_scale();
  scale.tare();          // Resets the scale to 0.
}

void sendAlive() {
  xAALPayload.clear();
  xAALPayload["header"]["source"] = UUID;
  xAALPayload["header"]["devType"] = "HX711.basic";
  xAALPayload["header"]["msgType"] = "notify";
  xAALPayload["header"]["action"] = "alive";
  xAALPayload["body"]["timeout"] = 600;
  xAALSend();
}
void sendDescription() {
  xAALPayload.clear();
  xAALPayload["header"]["source"] = UUID;
  xAALPayload["header"]["devType"] = "HX711.basic";
  xAALPayload["header"]["msgType"] = "reply";
  xAALPayload["header"]["action"] = "getDescription";
  xAALPayload["body"]["vendorId"] = "Arduino";
  xAALPayload["body"]["productId"] = "esp32dev";
  xAALPayload["body"]["info"] = "ESP-WROOM-32";
  xAALSend();
}
void sendStatus() {
  
  scale.set_scale(calibration_factor);  // Adjusts the calibration factor.
  scale.wait_ready();
  Serial.print("Reading: ");            // Prints weight readings in .2 decimal kg units.
  Serial.print(scale.get_units(), 4);
  Serial.println(" kg");

  xAALPayload.clear();
  xAALPayload["header"]["source"] = UUID;
  xAALPayload["header"]["devType"] = "HX711.basic";
  xAALPayload["header"]["msgType"] = "notify";
  xAALPayload["header"]["action"] = "attributesChange";
  xAALPayload["body"]["HX711"] = scale.get_units();
  xAALSend();


  // scale.power_down();    // Puts the scale to sleep mode for 3 seconds.
  delay(100);
  // scale.power_up();
}

void setup()
{
  Serial.begin(115200);   // Starts serial communication in 9600 baud rate.
  HX711Init();
  wifiInit();
  ntpInit();
}

void loop(){
  static unsigned long last_alive,last_attribute = 0;
  unsigned long now;
  timeClient.update();
  now = timeClient.getEpochTime();
  if (now > (last_alive + 300)) {
    sendAlive();
    sendDescription();
    last_alive = now;
  }
  if (now > (last_attribute + 10)) {
    sendStatus();
    last_attribute = now;
  }
  delay(1000);
}


