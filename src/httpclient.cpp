#include <ArduinoJson.h>
#include <ArduinoJson.hpp>
#include <WiFi.h>
#include <WiFiClient.h>
#include <string.h>
#include <stdio.h>
#include "./httpclient.h"

HttpChunkedReader::HttpChunkedReader(const std::string &url) {
  memset(buffer_, 0, 1024);
  url_ = url;

  line_ = buffer_;
}

HttpChunkedReader::~HttpChunkedReader() {
  if (client_) {
    delete client_;
    client_ = nullptr;
  }
}

bool HttpChunkedReader::connect() {
  gotHeader_ = false;
  requestSent_ = false;
  if (millis() - lastConnectAttempt < 60000 && lastConnectAttempt > 0) {
    return false;
  }
  lastConnectAttempt = millis();

  if (connected_)
    return true;

  if (client_) {
    delete client_;
    client_ = nullptr;
  }

  size_t slashIndex = url_.find('/');
  std::string hostname = url_.substr(0, slashIndex);

  client_ = new WiFiClient();
  if (!client_->connect(hostname.c_str(), 80)) {
    Serial.println("Can't");

    delete client_;
    client_ = nullptr;
    return false;
  }

  connected_ = true;
  return true;
}

void HttpChunkedReader::sendRequest() {
  // Serial.println("Sending dht req");

  size_t slashIndex = url_.find('/');
  std::string hostname = url_.substr(0, slashIndex);
  std::string path = url_.substr(slashIndex);

  // Serial.println(hostname.c_str());
  //     Serial.println(path.c_str());


  // Send HTTP request header
  client_->print("GET ");
  client_->print(path.c_str());
  client_->print(" HTTP/1.1\r\n");
  client_->print("Host: ");
  client_->print(hostname.c_str());
  client_->print("\r\n");
  client_->print("\r\n");
  requestSent_ = true;
}

char *HttpChunkedReader::poll() {
  if (shouldEndLine_) {
    shouldEndLine_ = false;
    buffer_[0] = '\0';
    ptr = 0;
  }

  if (!connected_) {
    if (!connect())
      return nullptr;
  }

  if (!requestSent_) {
    sendRequest();
  }

  if (client_->available() > 0) {
    char c = client_->read();  //flawfinder: ignore
    if (responseCode_ == 0 || gotHeader_ == false) {
      // Read HTTP response header
      if (c == '\n') {
        // Got a full line, parse it
        char *line = buffer_;
        if (strstr(line, "HTTP/1.1") != nullptr) {
          // Parse response code
          const char *codeStr = strtok(line, " ");
          codeStr = strtok(nullptr, " ");
          responseCode_ = atoi(codeStr);  //flawfinder: ignore
        }

        // Assume header is done, account for \r\n or other whitespace
        // bugs
        if (ptr < 5) {
          gotHeader_ = true;
        }

        // Reset buffer
        buffer_[0] = '\0';
        ptr = 0;
      } else {
        // Add char to buffer
        if (ptr < 1020 - 1) {
          buffer_[ptr] = c;
          buffer_[ptr + 1] = '\0';
          ptr += 1;
        }
      }
    } else {

      // Read / body
      if (c == '\n') {
        // Got a full line, return it
        line_ = buffer_;
        shouldEndLine_ = true;
        return line_;
      } else {
        if (!(c == '\r')) {
          // Add char to buffer
          if (ptr < 1020 - 1) {
            buffer_[ptr] = c;
            buffer_[ptr + 1] = '\0';
            ptr += 1;
          }
        }
      }
    }
  }

  // Check for connection failure
  if (!client_->connected()) {
    Serial.print("Fail");
    connected_ = false;
    delete client_;
    client_ = nullptr;
  }

  return nullptr;
}

int HttpChunkedReader::getResponseCode() {
  return responseCode_;
}

bool sendPostRequest(const std::string &url, const std::string &postData) {
  size_t slashIndex = url.find('/');
  std::string hostname = url.substr(0, slashIndex);
  std::string path = url.substr(slashIndex);

  // Connect to hostname
  WiFiClient client;
  if (!client.connect(hostname.c_str(), 80)) {
    Serial.println("Connection failed");
    return false;
  }

  // Send HTTP POST request header
  client.print("POST ");
  client.print(path.c_str());
  client.print(" HTTP/1.1\r\n");
  client.print("Host: ");
  client.print(hostname.c_str());
  client.print("\r\n");
  client.print("Content-Type: application/json\r\n");
  client.print("Content-Length: ");
  client.print(postData.size());
  client.print("\r\n");
  client.print("\r\n");

  // Send POST data
  client.print(postData.c_str());
  // LAZYMESH_DEBUG("Done sending dhtproxy request");

  bool success = false;
  // Read response
  while (client.available() > 0) {
    char _c = client.read();
    // LAZYMESH_DEBUG(c);
    success = true;
  }
  // Close connection
  client.stop();

  // Assume success if we got any response
  return success;
}

uint8_t makePathLossByte(int total, int lastHop) {
  if (total > 31) {
    total = 31;
  }
  if (total < 0) {
    total = 0;
  }

  if (lastHop > 7) {
    lastHop = 7;
  }
  if (lastHop < 0) {
    lastHop = 0;
  }


  uint8_t b = total << 3;

  b += lastHop;

  return b;
}