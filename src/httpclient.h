#pragma once
#include <ArduinoJson.h>
#include <ArduinoJson.hpp>
#include <WiFi.h>
#include <WiFiClient.h>
#include <string.h>
#include <stdio.h>
#include "./httpclient.h"

class HttpChunkedReader {

private:
  std::string url_;
  WiFiClient *client_ = nullptr;
  bool connected_ = false;
  bool requestSent_ = false;
  char buffer_[1024];
  int ptr = 0;
  bool gotHeader_ = false;
  bool shouldEndLine_ = false;
  char *line_ = buffer_;
  int responseCode_ = 0;

  unsigned long lastConnectAttempt = 0;

public:
  explicit HttpChunkedReader(const std::string & url);
  ~HttpChunkedReader();
  bool connect();

  void sendRequest();
  char *poll();

  int getResponseCode();
};

extern bool sendPostRequest(const std::string &url, const std::string &postData);
