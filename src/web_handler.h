#pragma once

#include <Arduino.h>
#include <WebServer.h>
#include <Preferences.h>

// -------- Firmware version (shown on serial monitor and Firmware Update page) --------
#define FIRMWARE_VERSION "REV_1.0.0 - Safety control - Mini PLC"

// -------- Web admin credentials (mutable, stored in NVS namespace "webadmin") --------
// Defaults used on first boot; changed via the Account tab in the web UI.

// -------- BLE user store --------
#define MAX_USERS 30

struct User {
  char name[64];
  char email[64];
  char password[64];
  char role[32];
  uint8_t  accessType; // ACCESS_PERPETUAL or ACCESS_TIMED
  uint32_t startTs;    // Timed only: access starts at this date/time (seconds since 1970, in RTC time)
  uint32_t endTs;      // Timed only: access ends at this date/time (exclusive)
};

// User access type: perpetual users may log in at any time; timed users only
// between their start and end date/time, [startTs, endTs), compared against
// the RTC clock.
#define ACCESS_PERPETUAL 0
#define ACCESS_TIMED     1

// Registered mobile devices
#define MAX_DEVICES 20
struct Device {
  char id[41]; // up to 40 chars + NUL
  char owner[64]; // optional owner email
};

// Shared globals defined in main.cpp
extern User        users[MAX_USERS];
extern int         userCount;
extern WebServer   webServer;
extern Preferences prefs;



// BLE connection state — defined in main.cpp
extern bool deviceConnected;
extern bool authenticated;
extern char connectedUserEmail[64];

// Current motion output state — defined in main.cpp, updated by BLE callback
extern bool motionEstop;
extern bool motionUp;
extern bool motionDown;
extern bool motionLeft;
extern bool motionRight;

// Output pin configuration — defined in main.cpp
#define NUM_OUTPUT_PINS 5
#define MOTION_NONE   0
#define MOTION_ESTOP  1
#define MOTION_UP     2
#define MOTION_DOWN   3
#define MOTION_LEFT   4
#define MOTION_RIGHT  5

struct OutPin {
  const char* label;
  int         pin;
};

// Output configuration for each output pin
struct PinMotion {
  uint8_t function; // 0=DF1, 1=DF2, 2=DF3, 3=DF4, 4=DF5
  uint8_t motion;   // 0=None, 1=ESTOP, 2=UP, 3=DOWN, 4=LEFT, 5=RIGHT
};

extern const OutPin OUTPUT_PINS[NUM_OUTPUT_PINS];
extern const char* OUTPUT_FUNCTIONS[NUM_OUTPUT_PINS];
extern PinMotion pinMotionConfig[NUM_OUTPUT_PINS];  // Maps each output pin to a digital function and motion

// Input pin configuration — defined in main.cpp
// I0.0-I0.6 are digital-only. I0.7/I0.8 are dual-purpose: in Digital mode they
// read GPIO32/33 (I0.7/I0.8); in Analog mode they read the board's dedicated
// analog-only pins GPIO34/35 (A0.7/A0.8) instead.
#define NUM_INPUT_PINS      9
#define INPUT_MODE_DIGITAL  0
#define INPUT_MODE_ANALOG   1

struct InPin {
  const char* label;       // digital label, e.g. "I0.7"
  const char* analogLabel; // analog label, e.g. "A0.7"; nullptr when not switchable
  int         pin;         // digital-mode pin
  int         analogPin;   // analog-mode pin; -1 when not switchable
  bool        switchable;  // true only for I0.7 / I0.8
};

extern const InPin INPUT_PINS[NUM_INPUT_PINS];
extern uint8_t inputMode[NUM_INPUT_PINS]; // 0=digital,1=analog — only meaningful when switchable

// Hoist configuration — defined in main.cpp
#define HOIST_NONE  0
#define HOIST_ONE   1
#define HOIST_TWO   2
#define HOIST_BOTH  3

extern uint8_t hoistConfig;
extern int8_t  hoistOneInputIdx; // index into INPUT_PINS feeding Hoist 1, -1 = unassigned
extern int8_t  hoistTwoInputIdx; // index into INPUT_PINS feeding Hoist 2, -1 = unassigned

// index into INPUT_PINS used as the mobile remote-control E-STOP interlock, -1 = unassigned
extern int8_t  remoteInputIdx;

void loadInputConfig();
void saveInputConfig();
void applyInputConfig();
void loadHoistConfig();
void saveHoistConfig();
const char* getInputLabel(int idx); // mode-aware label, e.g. "I0.7" or "A0.7"
void forceAllOutputsOff(); // drives every output LOW and latches E-STOP; defined in main.cpp

// BLE / WiFi credentials — defined in main.cpp
extern char bleName[32];
extern char wifiSsid[32];
extern char wifiPassword[64];

// NVS helpers defined in main.cpp, called from web handlers
bool saveUsers(); // false if any NVS write failed (e.g. storage full)
int  findUserIndexByEmail(const char* email); // case-insensitive; -1 if not found
bool isUserAccessAllowed(const User& u);      // false = timed user outside their window (or clock unavailable)
void saveOutputConfig();
void applyOutputConfig();
void saveNetworkConfig();
void loadNetworkConfig();

// Web route registration — call once in setup()
void setupWebRoutes();

// Device registry helpers
extern Device devices[MAX_DEVICES];
extern int deviceCount;
void loadDevices();
void saveDevices();
bool isDeviceRegistered(const char* id);
bool registerDevice(const char* id, const char* owner);
bool unregisterDevice(const char* id);

// Motion helpers
const char* getMotionLabel(uint8_t motionId);
uint8_t getMotionIdForLabel(const char* label);

// RTC + SD event logging — defined in main.cpp
extern bool rtcOk;
extern bool sdOk;
String currentTimestamp(); // "YYYY-MM-DD HH:MM:SS", or "N/A" if RTC unavailable
bool setRtcDateTime(int year, int month, int day, int hour, int minute, int second); // false if RTC unavailable
