
#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include "rtc10.h"
#include "mbedtls/gcm.h"
#include "web_handler.h"
#include "esp_gap_ble_api.h"
#include "esp_log.h"
#include "esp_bt.h"
#include <time.h>

#define SERVICE_UUID        "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define DIGITAL_CHAR_UUID   "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
#define AUTH_CHAR_UUID      "6e400004-b5a3-f393-e0a9-e50e24dcca9e"
#define STATUS_CHAR_UUID    "6e400005-b5a3-f393-e0a9-e50e24dcca9e"
#define HEARTBEAT_CHAR_UUID "6e400006-b5a3-f393-e0a9-e50e24dcca9e"
#define ANALOG_CHAR_UUID     "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
#define BLE_SERVICE_HANDLE_COUNT 24

#define AUTH_TIMEOUT_MS  60000

#define NET_NAME_MIN_LEN 6
#define NET_NAME_MAX_LEN 10
#define WIFI_PASS_MIN_LEN 8
#define WIFI_PASS_MAX_LEN 10

#define DEFAULT_WIFI_SSID "RRC_PLC"
#define DEFAULT_WIFI_PASSWORD  "12345678"
#define DEFAULT_BLE_NAME       "RRC_PLC"

#define WIFI_RETRY_INTERVAL_MS  10000

char bleName[32]       = DEFAULT_BLE_NAME;
char wifiSsid[32]      = DEFAULT_WIFI_SSID;
char wifiPassword[64]  = DEFAULT_WIFI_PASSWORD;

User        users[MAX_USERS];
int         userCount    = 0;
Preferences prefs;
WebServer   webServer(80);

// Output pin lookup table — order must match the web UI dropdowns (index 0-4)
const OutPin OUTPUT_PINS[NUM_OUTPUT_PINS] = {
  { "R0_0", R0_0 },
  { "Q0_0", Q0_0 },
  { "Q0_1", Q0_1 },
  { "Q0_2", Q0_2 },
  { "Q0_3", Q0_3 }
};

// Logical output functions for the 5 outputs
const char* OUTPUT_FUNCTIONS[NUM_OUTPUT_PINS] = {
  "DF1",
  "DF2",
  "DF3",
  "DF4",
  "DF5"
};

// Input pin lookup table. I0.7/I0.8 are dual-purpose: Digital mode reads
// GPIO32/33 (I0_7/I0_8), while Analog mode reads the board's dedicated
// analog-only pins GPIO34/35 instead — selectable via the web UI's Input
// Configuration page.
const InPin INPUT_PINS[NUM_INPUT_PINS] = {
  { "I0.0", nullptr, I0_0, -1, false },
  { "I0.1", nullptr, I0_1, -1, false },
  { "I0.2", nullptr, I0_2, -1, false },
  { "I0.3", nullptr, I0_3, -1, false },
  { "I0.4", nullptr, I0_4, -1, false },
  { "I0.5", nullptr, I0_5, -1, false },
  { "I0.6", nullptr, I0_6, -1, false },
  { "I0.7", "A0.7",  I0_7, 34, true  },
  { "I0.8", "A0.8",  I0_8, 35, true  },
};

uint8_t inputMode[NUM_INPUT_PINS] = {0,0,0,0,0,0,0,0,0};

uint8_t hoistConfig      = HOIST_NONE;
int8_t  hoistOneInputIdx = -1;
int8_t  hoistTwoInputIdx = -1;

// Index into INPUT_PINS used as the mobile remote-control E-STOP interlock
// input, configurable from the web UI's Input Configuration page. Defaults
// to I0.1 (index 1), matching the pin this interlock used before it became
// configurable. -1 means no pin is assigned.
int8_t  remoteInputIdx   = 1;

// ---------------- RTC + SD event logging ----------------
// Both are optional peripherals: a missing/failed RTC or SD card must never
// block PLC operation, so every access below degrades gracefully (Serial
// message + skip) instead of halting.
bool             rtcOk = false;
bool             sdOk  = false;
static const int SD_CS_PIN = 5; // onboard microSD slot, default VSPI SS
// Events are logged to one file per month, "/events_YYYY-MM.log", chosen from
// the event's own timestamp — a new month's first event starts a new file.
// Events with no valid RTC time go to "/events_undated.log".

// Software clock cache: the last known-good RTC reading, plus the millis()
// at which it was taken. currentTimestamp() derives "now" from this by
// adding elapsed time, instead of doing a live I2C read every time it's
// called. The cache itself is refreshed periodically by syncTimeCache()
// (see below), from a spot in loop() that isn't on any event's critical
// path — an event (a login, an E-STOP trip) and I2C bus noise (from the
// very relay/output switching that often triggers the event) tend to land
// at the same instant, which is the worst possible moment to need a live
// RTC read for that event's own timestamp. Caching means a transient I2C
// fault right then costs nothing — the logged entry just uses whatever was
// last successfully read, carried forward — instead of either blocking
// loop() or falling back to "N/A".
static time_t        cachedEpoch     = 0;
static unsigned long cachedEpochAtMs = 0;
static bool          timeCacheValid  = false;

// I0.0-I0.6, the E-STOP relay (R0_0) and the 24V enable pins are not real
// GPIOs on this board — they're read/written over the same I2C (Wire) bus
// as the RTC, via an onboard MCP23017 expander. The Arduino TwoWire object
// is not safe for concurrent use from more than one FreeRTOS task, but BLE
// characteristic callbacks (login, motion/E-STOP commands, disconnect) run
// on the BLE stack's own task while loop() runs on another — both touch
// this same I2C bus. Without serializing them, concurrent access corrupts
// TwoWire's internal buffers, producing I2C bus timeouts, garbage RTC
// reads, and (observed in practice) a hard crash. i2cMutex serializes every
// I2C-touching call in this file, regardless of which task makes it.
SemaphoreHandle_t i2cMutex = nullptr;
struct I2CGuard {
  I2CGuard()  { xSemaphoreTake(i2cMutex, portMAX_DELAY); }
  ~I2CGuard() { xSemaphoreGive(i2cMutex); }
};

// Bounded-wait variant, used only by the safety-critical I0.1 read and
// output pin writes in loop() (updateEstopState(), updateOutputPinsFromState(),
// applyOutputsDisconnected()). Those used to block on I2CGuard's unbounded
// portMAX_DELAY like everything else — fine as long as every I2C user is
// well-behaved, but it meant a single stuck/slow transaction on the RTC's
// side (an optional peripheral, per the comment above) could hold the
// mutex for hundreds of ms and, transitively, freeze the entire safety
// loop for that long — observed in practice as heartbeat checks stalling
// past the 500ms trip threshold in one jump, with no chance to even see
// the 100/200/300/400ms readings in between. Capping the wait here means
// a hung RTC transaction can delay one safety I/O cycle by at most this
// timeout, never longer — the caller checks acquired() and holds the
// previous known-good state for that cycle rather than block.
struct TryI2CGuard {
  bool ok;
  explicit TryI2CGuard(uint32_t timeoutMs) {
    ok = (xSemaphoreTake(i2cMutex, pdMS_TO_TICKS(timeoutMs)) == pdTRUE);
  }
  ~TryI2CGuard() { if (ok) xSemaphoreGive(i2cMutex); }
  bool acquired() const { return ok; }
};

// Human-readable reason for the most recent motionEstop change, set at each
// trigger site (I0.1 interlock trip, app command, BLE disconnect, heartbeat
// loss) purely so the SD event log can record *why* E-STOP changed.
String estopChangeReason = "boot";

// Standard Sakamoto's algorithm, returned as 1=Monday..7=Sunday to match
// rtc10_set_day_of_the_week()'s convention. Nothing in this app actually
// reads the weekday back, but the register still needs a sane value.
static uint8_t computeDayOfWeek(int year, int month, int day) {
  static const int t[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};
  int y = year;
  if (month < 3) y -= 1;
  int dow0 = (y + y / 4 - y / 100 + y / 400 + t[month - 1] + day) % 7; // 0=Sunday
  return dow0 == 0 ? 7 : (uint8_t)dow0;
}

// Attempts one bounded, direct RTC read — the only place in this file that
// actually touches the RTC over I2C for the time-of-day fields. Used by
// syncTimeCache() below (periodic, off the critical path) and nowhere
// else; every other caller goes through the cache via currentTimestamp().
//
// A flaky RTC connection (e.g. an interrupted I2C bus, or a wiring issue)
// can silently return a corrupted register read as if it succeeded, so
// each read's fields are range-checked and retried a few times, each as
// its own short-held lock, rather than ever accepting garbage like
// "2110-84-141". The whole attempt is also capped on real elapsed time
// (not just attempt count) so a single slow/stuck transaction can't block
// its caller indefinitely.
static bool readRtcFieldsDirect(uint8_t &h, uint8_t &mi, uint8_t &s,
                                 uint8_t &d, uint8_t &mo, uint8_t &y2) {
  if (!rtcOk) return false;
  const unsigned long budgetStart = millis();
  const unsigned long MAX_BUDGET_MS = 80;
  for (int attempt = 0; attempt < 3; attempt++) {
    uint8_t wd = 0;
    bool readOk;
    {
      I2CGuard _i2cGuard;
      rtc10_clear_read_error();
      rtc10_getTime(&h, &mi, &s);
      rtc10_getDate(&wd, &d, &mo, &y2);
      readOk = !rtc10_had_read_error();
    }
    if (readOk && h <= 23 && mi <= 59 && s <= 59 && d >= 1 && d <= 31 && mo >= 1 && mo <= 12 && y2 <= 99) {
      return true;
    }
    if (millis() - budgetStart >= MAX_BUDGET_MS) break;
    delay(5); // let a flaky bus settle before retrying
  }
  return false;
}

// Refreshes the software clock cache from one direct RTC read. Call this
// only from a non-blocking context (periodically from loop(), and once
// right after boot / right after a verified RTC write) — never from
// logEvent() or anywhere else an event's own timestamp is needed right
// now. A failed read here just leaves the existing cache in place; the
// next periodic call tries again. Returns whether this attempt succeeded,
// so a repeat caller (loop()'s periodic resync) can stop retrying after
// enough consecutive misses instead of hitting a genuinely dead RTC
// forever.
bool syncTimeCache() {
  uint8_t h, mi, s, d, mo, y2;
  if (!readRtcFieldsDirect(h, mi, s, d, mo, y2)) return false;

  struct tm t = {};
  t.tm_year  = (2000 + y2) - 1900;
  t.tm_mon   = mo - 1;
  t.tm_mday  = d;
  t.tm_hour  = h;
  t.tm_min   = mi;
  t.tm_sec   = s;
  t.tm_isdst = 0;
  // This project never configures a timezone (no configTzTime/setenv
  // "TZ" call anywhere), so the default is UTC — mktime() here is a plain
  // calendar-to-epoch conversion with no offset applied, matching the
  // previous code's behavior of treating the RTC's fields as literal,
  // zone-less wall-clock values.
  time_t epoch = mktime(&t);
  if (epoch == (time_t)-1) return false; // shouldn't happen for range-checked fields

  cachedEpoch     = epoch;
  cachedEpochAtMs = millis();
  timeCacheValid  = true;
  return true;
}

// Returns "YYYY-MM-DD HH:MM:SS" derived from the cached RTC reading
// (advanced by elapsed time since it was taken), or "N/A" if no reading
// has ever succeeded. See the cache comment above for why this doesn't do
// a live I2C read.
String currentTimestamp() {
  if (!timeCacheValid) return "N/A";
  time_t now = cachedEpoch + (time_t)((millis() - cachedEpochAtMs) / 1000);
  struct tm tmNow;
  gmtime_r(&now, &tmNow);
  char buf[20];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
           tmNow.tm_year + 1900, tmNow.tm_mon + 1, tmNow.tm_mday,
           tmNow.tm_hour, tmNow.tm_min, tmNow.tm_sec);
  return String(buf);
}

// Case-insensitive lookup of a user by email; -1 if not found.
int findUserIndexByEmail(const char* email) {
  for (int i = 0; i < userCount; i++) {
    if (String(users[i].email).equalsIgnoreCase(email)) return i;
  }
  return -1;
}

// Perpetual users are always allowed. Timed users are allowed only while the
// RTC date/time is inside [startTs, endTs). If the clock has never been read
// successfully the time can't be verified, so a timed user is denied.
// (The RTC fields are treated as literal date/time values — the same
// convention currentTimestamp() uses — so startTs/endTs are in that same
// clock, with no time-zone conversion.)
bool isUserAccessAllowed(const User& u) {
  if (u.accessType != ACCESS_TIMED) return true;
  if (!timeCacheValid) return false;
  int64_t now = (int64_t)cachedEpoch + (int64_t)((millis() - cachedEpochAtMs) / 1000);
  return now >= (int64_t)u.startTs && now < (int64_t)u.endTs;
}

// Sets the RTC to the given date/time (used by the web "Time & Date" page).
// Returns false if the RTC isn't available, OR if the write doesn't verify
// — reading the chip back afterward and confirming it actually moved to
// the requested time. Without this check, a dropped write on a flaky I2C
// bus would silently leave the old time in place while still reporting
// success, which is exactly what looked like "the time reverts a second
// later": the page briefly showed the value that had just been typed, but
// the chip itself was never actually updated.
bool setRtcDateTime(int year, int month, int day, int hour, int minute, int second) {
  if (!rtcOk) return false;
  uint8_t weekday = computeDayOfWeek(year, month, day);
  {
    I2CGuard _i2cGuard;
    rtc10_setDate(weekday, (uint8_t)day, (uint8_t)month, (uint16_t)year);
    rtc10_setTime((uint8_t)hour, (uint8_t)minute, (uint8_t)second);
    rtc10_clear_lost_power();
  }

  int targetYear2 = year % 100;
  for (int attempt = 0; attempt < 3; attempt++) {
    delay(5);
    uint8_t h = 0, mi = 0, s = 0, wd = 0, d = 0, mo = 0, y2 = 0;
    {
      I2CGuard _i2cGuard;
      rtc10_getTime(&h, &mi, &s);
      rtc10_getDate(&wd, &d, &mo, &y2);
    }
    bool dateOk = (y2 == targetYear2 && mo == month && d == day && h == hour && mi == minute);
    int secDiff = (int)s - second;
    if (dateOk && secDiff >= -3 && secDiff <= 3) {
      // Refresh the cache immediately from the reading we just verified,
      // instead of leaving the web panel showing the pre-write time until
      // the next periodic sync.
      syncTimeCache();
      return true;
    }
  }
  Serial.println("setRtcDateTime: write did not verify — RTC did not accept the new time (check wiring)");
  return false;
}

// Appends one CSV line ("timestamp,category,detail") to the current month's
// SD event log (see the file-naming note above).
// Opens, writes and closes the file immediately on every call so an entry
// is never lost to a power cut, and so a card that was reinserted after a
// failure is picked back up on the very next call (no persistent flag).
void logEvent(const char* category, const String& detail) {
  String ts = currentTimestamp();
  Serial.printf("[EVENT] %s: %s | %s\n", ts.c_str(), category, detail.c_str());

  // SD.open() allocates a C++ object (make_shared<VFSFileImpl>) internally,
  // which throws std::bad_alloc if heap is too low/fragmented at the
  // moment — observed in practice happening right around a BLE login, when
  // BLE + WiFi AP + SD + the web server's own allocations all peak
  // together. Nothing upstream of logEvent() catches C++ exceptions, so an
  // uncaught throw here used to take the whole safety controller down via
  // abort(). SD logging is an optional peripheral (see the block comment
  // above) — a failed open must degrade to "entry not persisted", the same
  // as every other SD failure here, never a reboot.
  // ts is "YYYY-MM-DD HH:MM:SS", so its first 7 characters are the month.
  String logPath = (ts.length() >= 7 && ts != "N/A")
                     ? "/events_" + ts.substring(0, 7) + ".log"
                     : String("/events_undated.log");
  File f;
  try {
    f = SD.open(logPath, FILE_APPEND);
  } catch (...) {
    Serial.printf("logEvent: SD open failed (likely low memory, %u bytes free) — entry not persisted\n",
                  (unsigned)ESP.getFreeHeap());
    return;
  }
  if (!f) {
    Serial.println("logEvent: SD card unavailable — entry not persisted");
    return;
  }
  f.print(ts);
  f.print(",");
  f.print(category);
  f.print(",");
  f.println(detail);
  f.close();
}

// aes key must be 16 bytes for AES-128
static const uint8_t aesKey[16] = {
  0x54, 0x55, 0x53, 0x4B,
  0x45, 0x52, 0x5F, 0x52,
  0x52, 0x43, 0x5F, 0x44,
  0x45, 0x56, 0x5F, 0x31
};

void updateConnectionParams()
{
  esp_ble_conn_update_params_t params;

  params.min_int = 0x06;
  params.max_int = 0x06;
  params.latency = 0;
  params.timeout = 400;

  esp_ble_gap_update_conn_params(&params);
}

// AES-GCM decryption helper — accepts either hex text or raw bytes
static bool decryptAESGCM_from_bytes(const uint8_t *encrypted, size_t encryptedLen, uint8_t *decrypted, size_t *decryptedLen) {
  if (encryptedLen < 12 + 16) return false; // need IV(12) + TAG(16)

  const uint8_t *iv = encrypted; // first 12 bytes
  const uint8_t *tag = encrypted + encryptedLen - 16; // last 16 bytes
  const uint8_t *cipher = encrypted + 12;
  size_t cipherLen = encryptedLen - 12 - 16;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128) != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  int res = mbedtls_gcm_auth_decrypt(
    &gcm,
    cipherLen,
    iv, 12,
    NULL, 0,
    tag, 16,
    cipher,
    decrypted
  );

  mbedtls_gcm_free(&gcm);

  if (res != 0) return false;
  *decryptedLen = cipherLen;
  return true;
}

// forward declare helpers defined later
static bool decodeHexText(const std::string& text, uint8_t *output, size_t outputSize, size_t *outputLen);
static uint64_t read48be(const uint8_t *buf);
static bool isCounterFresh(uint64_t sessionId, uint64_t counter);
static void updateLastCounter(uint64_t sessionId, uint64_t counter);

// Global IV counter for encrypting replies (12 bytes)
static uint8_t replyIvCounter[12] = {0};

static void incrementReplyIv() {
  for (int i = 11; i >= 0; --i) {
    replyIvCounter[i]++;
    if (replyIvCounter[i] != 0) break;
  }
}

static std::string bytesToHex(const uint8_t *data, size_t len) {
  static const char hexDigits[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(hexDigits[(data[i] >> 4) & 0xF]);
    out.push_back(hexDigits[data[i] & 0xF]);
  }
  return out;
}

// Encrypt plaintext into IV(12)|CIPHER|TAG(16) hex string (IV is replyIvCounter, incremented)
static bool encryptAESGCM_packet(const std::string &plain, std::string &outHex) {
  size_t len = plain.size();
  if (len > 200) return false;

  uint8_t ciphertext[256];
  uint8_t tag[16];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128) != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  incrementReplyIv();

  int res = mbedtls_gcm_crypt_and_tag(
    &gcm,
    MBEDTLS_GCM_ENCRYPT,
    len,
    replyIvCounter, 12,
    NULL, 0,
    (const uint8_t*)plain.data(),
    ciphertext,
    16,
    tag
  );

  mbedtls_gcm_free(&gcm);
  if (res != 0) return false;

  // Build final hex: IV + ciphertext + tag
  outHex.clear();
  outHex += bytesToHex(replyIvCounter, 12);
  outHex += bytesToHex(ciphertext, len);
  outHex += bytesToHex(tag, 16);
  return true;
}

static bool decodePayload(const std::string &data, uint8_t *output, size_t outputSize, size_t *outputLen) {
  if (decodeHexText(data, output, outputSize, outputLen)) {
    return true;
  }

  std::string hexed;
  hexed.reserve(data.size() * 2);
  const char hexDigits[] = "0123456789ABCDEF";
  for (unsigned char c : data) {
    hexed.push_back(hexDigits[(c >> 4) & 0xF]);
    hexed.push_back(hexDigits[c & 0xF]);
  }

  if (decodeHexText(hexed, output, outputSize, outputLen)) {
    return true;
  }

  if (data.size() > outputSize) return false;
  memcpy(output, data.data(), data.size());
  *outputLen = data.size();
  return true;
}

struct SessionCounterEntry {
  uint64_t sessionId;
  uint64_t lastCounter;
  bool used;
};

static const int MAX_SESSION_COUNTER_ENTRIES = 8;
static SessionCounterEntry sessionCounters[MAX_SESSION_COUNTER_ENTRIES] = {};

static uint64_t read48be(const uint8_t *buf) {
  return ((uint64_t)buf[0] << 40) | ((uint64_t)buf[1] << 32) |
         ((uint64_t)buf[2] << 24) | ((uint64_t)buf[3] << 16) |
         ((uint64_t)buf[4] << 8)  | (uint64_t)buf[5];
}

static bool isCounterFresh(uint64_t sessionId, uint64_t counter) {
  for (int i = 0; i < MAX_SESSION_COUNTER_ENTRIES; ++i) {
    if (sessionCounters[i].used && sessionCounters[i].sessionId == sessionId) {
      return counter > sessionCounters[i].lastCounter;
    }
  }
  return true;
}

static void updateLastCounter(uint64_t sessionId, uint64_t counter) {
  int freeIndex = -1;
  int replaceIndex = 0;
  uint64_t oldestCounter = UINT64_MAX;

  for (int i = 0; i < MAX_SESSION_COUNTER_ENTRIES; ++i) {
    if (!sessionCounters[i].used) {
      freeIndex = i;
      break;
    }
    if (sessionCounters[i].sessionId == sessionId) {
      sessionCounters[i].lastCounter = counter;
      return;
    }
    if (sessionCounters[i].lastCounter < oldestCounter) {
      oldestCounter = sessionCounters[i].lastCounter;
      replaceIndex = i;
    }
  }

  int target = (freeIndex >= 0) ? freeIndex : replaceIndex;
  sessionCounters[target].used = true;
  sessionCounters[target].sessionId = sessionId;
  sessionCounters[target].lastCounter = counter;
}

static bool decryptAndValidateEncryptedPayload(const std::string &value, uint8_t *decrypted, size_t *decryptedLen, uint64_t &sessionId, uint64_t &counter) {
  uint8_t encrypted[256];
  size_t encryptedLen = 0;

  if (!decodePayload(value, encrypted, sizeof(encrypted), &encryptedLen)) {
    return false;
  }

  if (encryptedLen < 12 + 16) {
    return false;
  }

  sessionId = read48be(encrypted);
  counter   = read48be(encrypted + 6);

  if (!isCounterFresh(sessionId, counter)) {
    return false;
  }

  if (!decryptAESGCM_from_bytes(encrypted, encryptedLen, decrypted, decryptedLen)) {
    return false;
  }

  updateLastCounter(sessionId, counter);
  return true;
}

static bool decryptAESGCM_hex_or_raw(const std::string &data, uint8_t *decrypted, size_t *decryptedLen) {
  uint8_t buf[256];
  size_t bufLen = 0;

  if (!decodePayload(data, buf, sizeof(buf), &bufLen)) {
    return false;
  }

  if (bufLen >= 12 + 16) {
    Serial.print("Detected HEX payload — IV=");
    for (size_t i = 0; i < 12; ++i) Serial.printf("%02X", buf[i]);
    Serial.print(" CIPHER=");
    size_t cipherEnd = bufLen - 16;
    for (size_t i = 12; i < cipherEnd; ++i) Serial.printf("%02X", buf[i]);
    Serial.print(" TAG=");
    for (size_t i = cipherEnd; i < bufLen; ++i) Serial.printf("%02X", buf[i]);
    Serial.println();
  }

  return decryptAESGCM_from_bytes(buf, bufLen, decrypted, decryptedLen);
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool decodeHexText(const std::string& text, uint8_t *output, size_t outputSize, size_t *outputLen) {
  int highNibble = -1;
  size_t len = 0;
  bool sawHex = false;

  for (char c : text) {
    if (c == ' ' || c == ':' || c == '-' || c == '\r' || c == '\n' || c == '\t') {
      continue;
    }

    int nibble = hexNibble(c);
    if (nibble < 0) {
      return false;
    }

    sawHex = true;
    if (highNibble < 0) {
      highNibble = nibble;
    } else {
      if (len >= outputSize) {
        return false;
      }
      output[len++] = (uint8_t)((highNibble << 4) | nibble);
      highNibble = -1;
    }
  }

  if (!sawHex || highNibble >= 0) {
    return false;
  }

  *outputLen = len;
  return true;
}

static void logBLEReceivedData(const char *label, const std::string &data) {
  Serial.printf("%s: length=%u\n", label, (unsigned)data.length());
  if (data.empty()) return;

  Serial.print("  RAW HEX: ");
  for (unsigned char c : data) {
    Serial.printf("%02X", c);
  }
  Serial.println();

  // Serial.print("  RAW ASCII: ");
  // for (unsigned char c : data) {
  //   if (isprint(c)) {
  //     Serial.write(c);
  //   } else {
  //     Serial.print('.');
  //   }
  // }
  // Serial.println();
}

// Pin configuration: for each output pin, which digital function and motion it controls
// Defaults match the legacy hardcoded assignments: pin 0 → DF1/ESTOP, pin 1 → DF2/UP, pin 2 → DF3/DOWN, pin 3 → DF4/LEFT, pin 4 → DF5/RIGHT
PinMotion pinMotionConfig[NUM_OUTPUT_PINS] = {
  { 0, MOTION_ESTOP },
  { 1, MOTION_UP    },
  { 2, MOTION_DOWN  },
  { 3, MOTION_LEFT  },
  { 4, MOTION_RIGHT }
};

// Helper to get motion label from motion ID
const char* getMotionLabel(uint8_t motionId) {
  switch (motionId) {
    case MOTION_ESTOP:  return "&#9888; E-STOP";
    case MOTION_UP:     return "&#9650; UP";
    case MOTION_DOWN:   return "&#9660; DOWN";
    case MOTION_LEFT:   return "&#9664; LEFT";
    case MOTION_RIGHT:  return "&#9654; RIGHT";
    default:            return "&#8212; None &#8212;";
  }
}

// Helper to get motion ID from label (for parsing)
uint8_t getMotionIdForLabel(const char* label) {
  if (!label) return MOTION_NONE;
  if (strcmp(label, "estop") == 0)  return MOTION_ESTOP;
  if (strcmp(label, "up") == 0)     return MOTION_UP;
  if (strcmp(label, "down") == 0)   return MOTION_DOWN;
  if (strcmp(label, "left") == 0)   return MOTION_LEFT;
  if (strcmp(label, "right") == 0)  return MOTION_RIGHT;
  return MOTION_NONE;
}

// Write output based on current motion states and pin-motion configuration
// E-STOP is inverted: LOW = active (emergency), HIGH = inactive (normal)
// Other motions are normal: HIGH = active, LOW = inactive
#define DOUT(pinIdx, val) \
  do { if ((pinIdx) < NUM_OUTPUT_PINS) digitalWrite(OUTPUT_PINS[(pinIdx)].pin, (val)); } while(0)

// E-STOP interlock inputs.
// mobileEstopSignal: last E-STOP bit received from the mobile app (1 = stop
// requested, 0 = cleared). Latches back to true on the falling edge of I0.1
// (the instant the interlock opens) — not merely because I0.1 is currently
// LOW — so the app must explicitly clear it again (a fresh estop=0) to
// resume after a real trip; I0.1 recovering on its own never restarts the
// machine. But if the app clears it while I0.1 already reads LOW (no trip
// has happened yet — nothing was ever running), that clear sticks and the
// output comes on by itself the moment I0.1 goes HIGH.
// estopInputHigh: live read of the I0.1 physical interlock input.
bool mobileEstopSignal = true;
bool estopInputHigh    = false;
bool prevEstopInputHigh = true;  // previous I0.1 level, for falling-edge detection

// Tracks the last mobileEstopSignal value that was reported to the app, so
// loop() can detect real changes to it (whether from an app command or from
// an I0.1 falling-edge trip) and notify immediately, independent of BLE
// command traffic.
bool lastNotifiedMobileEstopSignal = true;

// Tracks the last motionEstop value written to the SD event log, so loop()
// can detect real ON/OFF transitions of the final gated relay state
// (whatever caused them — I0.1, app command, disconnect, or heartbeat
// loss) and log each one exactly once.
bool lastLoggedMotionEstop = true;

// LOGIN/LOGOUT events are detected inside BLE callbacks (a different
// FreeRTOS task from loop()), but the actual SD card write must happen
// from loop() only — SD's File API is no safer for concurrent multi-task
// use than the I2C bus is, and unlike the I2C bus it isn't behind a mutex.
// So BLE callbacks just record the event here; loop() drains and logs it.
volatile bool pendingLoginEvent  = false;
volatile bool pendingLogoutEvent = false;
String        pendingLoginDetail;
String        pendingLogoutDetail;

void forceAllOutputsOff() {
  I2CGuard _i2cGuard;
  motionEstop       = true;   // emergency mode: E-STOP output LOW
  mobileEstopSignal = true;   // require the app to explicitly clear E-STOP again
  motionUp    = false;
  motionDown  = false;
  motionLeft  = false;
  motionRight = false;
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    digitalWrite(OUTPUT_PINS[i].pin, LOW);
  }
}

bool motionEstop = true;
bool motionUp    = false;
bool motionDown  = false;
bool motionLeft  = false;
bool motionRight = false;

bool          wifiConnected  = false;
unsigned long wifiRetryTime  = 0;

// BLE
BLEServer         *pBLEServer    = nullptr;
BLECharacteristic *digitalChar   = nullptr;
BLECharacteristic *authChar      = nullptr;
BLECharacteristic *statusChar    = nullptr;
BLECharacteristic *heartbeatChar = nullptr;
BLECharacteristic *analogChar     = nullptr;

bool     deviceConnected  = false;
bool     authenticated    = false;
char     connectedUserEmail[64] = "";
uint16_t connId           = 0;        
unsigned long connectTime = 0;

bool          heartbeatAlive     = false;
unsigned long lastHeartbeatTime  = 0;
int           heartbeatMissCount = 0;

// E-STOP trips when no heartbeat has arrived for this long. The warning
// log steps are HEARTBEAT_TIMEOUT_MS / 5 apart (2s, 4s, 6s, 8s, 10s).
static const unsigned long HEARTBEAT_TIMEOUT_MS = 10000;


// Users are stored one NVS string per user, key "u_<i>", with the fields
// joined by the ASCII Unit Separator (0x1F):
//   name US email US password US role US accessType US startTs US endTs
// Packing a user into a single string takes ~3-4 NVS entries instead of the
// 11 the old one-key-per-field layout needed, which is what lets this fit
// 30 users in the board's small (20KB) NVS partition. Records written by
// older firmware (email_i/pass_i/... keys) are still read, and are migrated
// to this format (and their old keys removed) on the next saveUsers().
#define USER_FIELD_SEP '\x1F'
static bool legacyUserKeysPresent = false;

static void userKey(char *buf, size_t n, int i) { snprintf(buf, n, "u_%d", i); }

static String userFieldClean(const char *s) {
  String o = s;
  o.replace(String(USER_FIELD_SEP), " ");
  return o;
}

static void removeLegacyUserKeys(int i) {
  char key[12];
  sprintf(key, "email_%d", i); prefs.remove(key);
  sprintf(key, "pass_%d",  i); prefs.remove(key);
  sprintf(key, "name_%d",  i); prefs.remove(key);
  sprintf(key, "role_%d",  i); prefs.remove(key);
  sprintf(key, "acc_%d",   i); prefs.remove(key);
  sprintf(key, "fts_%d",   i); prefs.remove(key);
  sprintf(key, "tts_%d",   i); prefs.remove(key);
}

bool saveUsers() {
  bool ok = true;
  prefs.begin("bleusers", false);
  int oldCount = prefs.getInt("count", 0);
  if (prefs.putInt("count", userCount) == 0) ok = false;
  for (int i = 0; i < userCount; i++) {
    char key[12];
    userKey(key, sizeof(key), i);
    String rec;
    rec.reserve(160);
    rec += userFieldClean(users[i].name);     rec += USER_FIELD_SEP;
    rec += userFieldClean(users[i].email);    rec += USER_FIELD_SEP;
    rec += userFieldClean(users[i].password); rec += USER_FIELD_SEP;
    rec += userFieldClean(users[i].role);     rec += USER_FIELD_SEP;
    rec += String((unsigned)users[i].accessType); rec += USER_FIELD_SEP;
    rec += String((unsigned long)users[i].startTs); rec += USER_FIELD_SEP;
    rec += String((unsigned long)users[i].endTs);
    if (prefs.putString(key, rec) == 0) ok = false;
  }
  // Drop records of users that no longer exist (deleted from the end of the list).
  for (int i = userCount; i < oldCount && i < MAX_USERS; i++) {
    char key[12];
    userKey(key, sizeof(key), i);
    prefs.remove(key);
  }
  // Only once everything above was stored, remove the old-format keys.
  if (ok && legacyUserKeysPresent) {
    for (int i = 0; i < MAX_USERS; i++) removeLegacyUserKeys(i);
    legacyUserKeysPresent = false;
  }
  prefs.end();
  if (!ok) Serial.println("saveUsers: NVS write FAILED (storage full?) - changes may not persist");
  return ok;
}

// Splits `rec` on USER_FIELD_SEP into exactly 7 fields; false if malformed.
static bool parseUserRecord(const String &rec, String f[7]) {
  int start = 0;
  for (int k = 0; k < 7; k++) {
    int end = (k < 6) ? rec.indexOf(USER_FIELD_SEP, start) : (int)rec.length();
    if (end < 0) return false;
    f[k] = rec.substring(start, end);
    start = end + 1;
  }
  return true;
}

void loadUsers() {
  prefs.begin("bleusers", true);
  userCount = prefs.getInt("count", 0);
  if (userCount > MAX_USERS) userCount = MAX_USERS;
  legacyUserKeysPresent = false;
  int loaded = 0;
  for (int i = 0; i < userCount; i++) {
    User &u = users[loaded];
    memset(&u, 0, sizeof(u));
    char key[12];
    userKey(key, sizeof(key), i);
    String f[7];
    if (prefs.isKey(key) && parseUserRecord(prefs.getString(key, ""), f)) {
      f[0].toCharArray(u.name,     sizeof(u.name));
      f[1].toCharArray(u.email,    sizeof(u.email));
      f[2].toCharArray(u.password, sizeof(u.password));
      f[3].toCharArray(u.role,     sizeof(u.role));
      u.accessType = (uint8_t)f[4].toInt();
      u.startTs    = (uint32_t)strtoul(f[5].c_str(), nullptr, 10);
      u.endTs      = (uint32_t)strtoul(f[6].c_str(), nullptr, 10);
    } else {
      // Old one-key-per-field format.
      char ekey[12], pkey[12], nkey[12], rkey[12], akey[12], fkey[12], tkey[12];
      sprintf(ekey, "email_%d", i);
      sprintf(pkey, "pass_%d",  i);
      sprintf(nkey, "name_%d",  i);
      sprintf(rkey, "role_%d",  i);
      sprintf(akey, "acc_%d",   i);
      sprintf(fkey, "fts_%d",   i);
      sprintf(tkey, "tts_%d",   i);
      if (!prefs.isKey(ekey)) continue; // no record for this slot - skip it
      legacyUserKeysPresent = true;
      prefs.getString(ekey, u.email,    sizeof(u.email));
      prefs.getString(pkey, u.password, sizeof(u.password));
      prefs.getString(nkey, u.name,     sizeof(u.name));
      prefs.getString(rkey, u.role,     sizeof(u.role));
      // Users saved by older firmware have no access keys: default to Perpetual
      // so an upgrade never locks anyone out.
      u.accessType = prefs.getUChar(akey, ACCESS_PERPETUAL);
      u.startTs    = prefs.getUInt(fkey, 0);
      u.endTs      = prefs.getUInt(tkey, 0);
    }
    if (u.accessType > ACCESS_TIMED) u.accessType = ACCESS_PERPETUAL;
    // backward compat: if name/role empty, fill defaults
    if (u.name[0] == '\0') strncpy(u.name, u.email, sizeof(u.name) - 1);
    if (u.role[0] == '\0') strncpy(u.role, "Operator", sizeof(u.role) - 1);
    // Only "Admin" and "Operator" are valid stored roles; the Super Admin is
    // the separate web account, so anything else falls back to Operator.
    if (strcmp(u.role, "Admin") != 0 && strcmp(u.role, "Operator") != 0)
      strncpy(u.role, "Operator", sizeof(u.role) - 1);
    loaded++;
  }
  userCount = loaded;
  prefs.end();

  // Migrate old-format records to the compact format right away.
  if (legacyUserKeysPresent && userCount > 0) {
    if (saveUsers()) Serial.println("Users migrated to compact NVS format");
  }

  // Always ensure at least one Admin user exists in the list.
  // Handles both fresh NVS (userCount==0) and stale NVS from older firmware
  // that did not include the admin@plc.com account.
  bool hasAdmin = false;
  for (int i = 0; i < userCount; i++) {
    if (String(users[i].role) == "Admin") { hasAdmin = true; break; }
  }
  if (!hasAdmin && userCount < MAX_USERS) {
    memset(&users[userCount], 0, sizeof(User));
    strncpy(users[userCount].name,     "Admin",         sizeof(users[0].name) - 1);
    strncpy(users[userCount].email,    "admin@plc.com", sizeof(users[0].email) - 1);
    strncpy(users[userCount].password, "admin123",      sizeof(users[0].password) - 1);
    strncpy(users[userCount].role,     "Admin",         sizeof(users[0].role) - 1);
    users[userCount].accessType = ACCESS_PERPETUAL;
    users[userCount].startTs    = 0;
    users[userCount].endTs      = 0;
    userCount++;
    saveUsers();
    Serial.println("Default admin user created/restored (admin@plc.com / admin123)");
  }
}

// Sets all 5 output GPIOs to OUTPUT mode and updates their states based on current motion states.
// Called on startup and whenever the configuration is changed.
void applyOutputConfig() {
  I2CGuard _i2cGuard;
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    uint8_t motion = pinMotionConfig[i].motion;
    bool active = false;
    
    // Determine if this pin's assigned motion is currently active
    switch (motion) {
      case MOTION_ESTOP:
        active = motionEstop;
        break;
      case MOTION_UP:
        active = motionUp;
        break;
      case MOTION_DOWN:
        active = motionDown;
        break;
      case MOTION_LEFT:
        active = motionLeft;
        break;
      case MOTION_RIGHT:
        active = motionRight;
        break;
      case MOTION_NONE:
      default:
        active = false;
        break;
    }
    
    int outputValue;
    if (motion == MOTION_ESTOP) {
      outputValue = active ? LOW : HIGH;
    } else if (motion != MOTION_NONE) {
      outputValue = active ? HIGH : LOW;
    } else {
      outputValue = LOW;  // No motion assigned, keep low
    }

    DOUT(i, outputValue);
  }
}

// Reads pin configuration from NVS namespace "outconfig".
// Falls back to defaults if keys are missing or out of range.
void loadOutputConfig() {
  prefs.begin("outconfig", true);
  
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    char key[16];
    sprintf(key, "pin_%d_function", i);
    int functionId = prefs.getInt(key, -1);
    if (functionId < 0 || functionId >= NUM_OUTPUT_PINS) {
      functionId = i; // default to DF1..DF5 for each pin
    }

    sprintf(key, "func_%d_motion", i);
    int motion = prefs.getInt(key, -1);
    if (motion == -1) {
      sprintf(key, "pin_%d_motion", i);
      motion = prefs.getInt(key, i + 1);
    }

    // Clamp function and motion to valid range
    if (functionId < 0 || functionId >= NUM_OUTPUT_PINS) {
      functionId = i;
    }
    if (motion < MOTION_NONE || motion > MOTION_RIGHT) {
      motion = (i < NUM_OUTPUT_PINS) ? (i + 1) : MOTION_NONE;
    }

    pinMotionConfig[i].function = (uint8_t)functionId;
    pinMotionConfig[i].motion   = (uint8_t)motion;
  }
  
  prefs.end();
  applyOutputConfig();
  
  // Log the loaded configuration
  Serial.println("Output config loaded:");
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    Serial.printf("  %s (%s) → %s\n", OUTPUT_FUNCTIONS[pinMotionConfig[i].function], OUTPUT_PINS[i].label, getMotionLabel(pinMotionConfig[i].motion));
  }
}

// Persists the current pin configuration to NVS and re-initializes pin modes.
void saveOutputConfig() {
  prefs.begin("outconfig", false);
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    char key[16];
    sprintf(key, "pin_%d_function", i);
    prefs.putInt(key, pinMotionConfig[i].function);
    sprintf(key, "pin_%d_motion", i);
    prefs.putInt(key, pinMotionConfig[i].motion);
  }
  prefs.end();
  applyOutputConfig();
  
  // Log the saved configuration
  Serial.println("Output config saved:");
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    Serial.printf("  %s (%s) → %s\n", OUTPUT_FUNCTIONS[pinMotionConfig[i].function], OUTPUT_PINS[i].label, getMotionLabel(pinMotionConfig[i].motion));
  }
}

// Returns the label reflecting each input's currently configured mode,
// e.g. "I0.7" in digital mode or "A0.7" in analog mode.
const char* getInputLabel(int idx) {
  if (idx < 0 || idx >= NUM_INPUT_PINS) return "—";
  if (INPUT_PINS[idx].switchable && inputMode[idx] == INPUT_MODE_ANALOG) {
    return INPUT_PINS[idx].analogLabel;
  }
  return INPUT_PINS[idx].label;
}

// Returns the pin to actually read from for an input's currently configured
// mode: the dedicated analog pin (GPIO34/35) in Analog mode, or the digital
// pin (GPIO32/33 etc.) otherwise.
static int getActiveInputPin(int idx) {
  if (idx < 0 || idx >= NUM_INPUT_PINS) return -1;
  if (INPUT_PINS[idx].switchable && inputMode[idx] == INPUT_MODE_ANALOG) {
    return INPUT_PINS[idx].analogPin;
  }
  return INPUT_PINS[idx].pin;
}

// Sets all input pins to INPUT mode. For switchable inputs, both the digital
// pin and the dedicated analog pin are configured, since either may be read
// depending on the selected mode.
void applyInputConfig() {
  I2CGuard _i2cGuard;
  for (int i = 0; i < NUM_INPUT_PINS; i++) {
    pinMode(INPUT_PINS[i].pin, INPUT);
    if (INPUT_PINS[i].switchable && INPUT_PINS[i].analogPin >= 0) {
      pinMode(INPUT_PINS[i].analogPin, INPUT);
    }
  }
}

// Reads input pin modes and hoist-input mapping from NVS namespace "inconfig".
void loadInputConfig() {
  prefs.begin("inconfig", true);
  for (int i = 0; i < NUM_INPUT_PINS; i++) {
    char key[16];
    sprintf(key, "mode_%d", i);
    int m = prefs.getInt(key, INPUT_MODE_DIGITAL);
    inputMode[i] = (INPUT_PINS[i].switchable && m == INPUT_MODE_ANALOG) ? INPUT_MODE_ANALOG : INPUT_MODE_DIGITAL;
  }
  hoistOneInputIdx = (int8_t)prefs.getInt("hoist1_in", -1);
  hoistTwoInputIdx = (int8_t)prefs.getInt("hoist2_in", -1);
  remoteInputIdx   = (int8_t)prefs.getInt("remote_in", 1);
  prefs.end();

  if (hoistOneInputIdx < -1 || hoistOneInputIdx >= NUM_INPUT_PINS) hoistOneInputIdx = -1;
  if (hoistTwoInputIdx < -1 || hoistTwoInputIdx >= NUM_INPUT_PINS) hoistTwoInputIdx = -1;
  if (remoteInputIdx < -1 || remoteInputIdx >= NUM_INPUT_PINS) remoteInputIdx = 1;

  applyInputConfig();

  Serial.println("Input config loaded:");
  for (int i = 0; i < NUM_INPUT_PINS; i++) {
    Serial.printf("  %s\n", getInputLabel(i));
  }
}

// Persists input pin modes and hoist-input mapping to NVS.
void saveInputConfig() {
  prefs.begin("inconfig", false);
  for (int i = 0; i < NUM_INPUT_PINS; i++) {
    char key[16];
    sprintf(key, "mode_%d", i);
    prefs.putInt(key, inputMode[i]);
  }
  prefs.putInt("hoist1_in", hoistOneInputIdx);
  prefs.putInt("hoist2_in", hoistTwoInputIdx);
  prefs.putInt("remote_in", remoteInputIdx);
  prefs.end();
  applyInputConfig();

  Serial.println("Input config saved:");
  for (int i = 0; i < NUM_INPUT_PINS; i++) {
    Serial.printf("  %s\n", getInputLabel(i));
  }
}

// Reads hoist mode (which hoists are enabled) from NVS namespace "hoistconfig".
void loadHoistConfig() {
  prefs.begin("hoistconfig", true);
  int h = prefs.getInt("mode", HOIST_NONE);
  prefs.end();
  if (h < HOIST_NONE || h > HOIST_BOTH) h = HOIST_NONE;
  hoistConfig = (uint8_t)h;
  Serial.printf("Hoist config loaded: mode=%d\n", hoistConfig);
}

// Persists hoist mode to NVS.
void saveHoistConfig() {
  prefs.begin("hoistconfig", false);
  prefs.putInt("mode", hoistConfig);
  prefs.end();
  Serial.printf("Hoist config saved: mode=%d\n", hoistConfig);
}

// Scales a raw ADC count into an engineering-unit hoist value: the
// 800-4095 raw range maps linearly to 0-5000, clamped at both ends.
static float scaleHoistAnalogValue(uint16_t raw) {
  const float IN_MIN  = 800.0f;
  const float IN_MAX  = 4095.0f;
  const float OUT_MAX = 5000.0f;
  if (raw <= IN_MIN) return 0.0f;
  if (raw >= IN_MAX) return OUT_MAX;
  return (raw - IN_MIN) * (OUT_MAX / (IN_MAX - IN_MIN));
}

float hoistA1Value = 0;
float hoistA2Value = 0;

// Sends the current hoist value(s) to the mobile app via the analog
// characteristic. Payload is "H1,<val>" / "H2,<val>" / "H1,<val>,H2,<val>"
// depending on which hoist(s) are enabled, AES-GCM encrypted the same way
// as the other characteristics.
static void notifyHoistValues() {
  if (!deviceConnected || !authenticated || !analogChar) return;

  char buf[64];
  switch (hoistConfig) {
    case HOIST_ONE:
      snprintf(buf, sizeof(buf), "H1,%u", (unsigned)hoistA1Value);
      break;
    case HOIST_TWO:
      snprintf(buf, sizeof(buf), "H2,%u", (unsigned)hoistA2Value);
      break;
    case HOIST_BOTH:
      snprintf(buf, sizeof(buf), "H1,%u,H2,%u", (unsigned)hoistA1Value, (unsigned)hoistA2Value);
      break;
    case HOIST_NONE:
    default:
      return; // Don't send anything if no hoist selected
  }

  std::string outHex;
  if (encryptAESGCM_packet(buf, outHex)) {
    analogChar->setValue(outHex);
    analogChar->notify();
    Serial.printf("BLE hoist notify (encrypted): %s\n", buf);
  } else {
    Serial.println("BLE hoist notify: encryption failed, notify skipped");
  }
}

static unsigned long lastHoistPrintTime = 0;
#define HOIST_PRINT_INTERVAL_MS 500

// Reads the input assigned to each enabled hoist and prints it to Serial.
// For analog inputs this prints both the raw ADC count and the scaled
// engineering value, so a stuck-at-zero raw count (no/low signal on the
// terminal, or the input's physical mode switch not set to Analog) is easy
// to tell apart from a scaling issue.
static void printHoistValues() {
  if (hoistConfig == HOIST_NONE) return;
  if (millis() - lastHoistPrintTime < HOIST_PRINT_INTERVAL_MS) return;
  lastHoistPrintTime = millis();
  I2CGuard _i2cGuard;

  bool wantHoist1 = (hoistConfig == HOIST_ONE || hoistConfig == HOIST_BOTH);
  bool wantHoist2 = (hoistConfig == HOIST_TWO || hoistConfig == HOIST_BOTH);

  if (wantHoist1) {
    if (hoistOneInputIdx >= 0) {
      bool isAnalog = INPUT_PINS[hoistOneInputIdx].switchable && inputMode[hoistOneInputIdx] == INPUT_MODE_ANALOG;
      if (isAnalog) {
        uint16_t raw = analogRead(getActiveInputPin(hoistOneInputIdx));
        hoistA1Value = scaleHoistAnalogValue(raw);
        Serial.printf("Hoist1 [%s, Analog]: raw=%u scaled=%.1f\n", getInputLabel(hoistOneInputIdx), raw, hoistA1Value);
      } else {
        int v = digitalRead(getActiveInputPin(hoistOneInputIdx));
        hoistA1Value = v;
        Serial.printf("Hoist1 [%s, Digital]: %d\n", getInputLabel(hoistOneInputIdx), v);
      }
    } else {
      hoistA1Value = 0;
      Serial.println("Hoist1: no input assigned");
    }
  }
  if (wantHoist2) {
    if (hoistTwoInputIdx >= 0) {
      bool isAnalog = INPUT_PINS[hoistTwoInputIdx].switchable && inputMode[hoistTwoInputIdx] == INPUT_MODE_ANALOG;
      if (isAnalog) {
        uint16_t raw = analogRead(getActiveInputPin(hoistTwoInputIdx));
        hoistA2Value = scaleHoistAnalogValue(raw);
        Serial.printf("Hoist2 [%s, Analog]: raw=%u scaled=%.1f\n", getInputLabel(hoistTwoInputIdx), raw, hoistA2Value);
      } else {
        int v = digitalRead(getActiveInputPin(hoistTwoInputIdx));
        hoistA2Value = v;
        Serial.printf("Hoist2 [%s, Digital]: %d\n", getInputLabel(hoistTwoInputIdx), v);
      }
    } else {
      hoistA2Value = 0;
      Serial.println("Hoist2: no input assigned");
    }
  }

  //notifyHoistValues();
}

// Reads BLE and WiFi credentials from NVS and applies defaults if missing.
void loadNetworkConfig() {
  prefs.begin("netconfig", true);
  String ssid = prefs.getString("wifi_ssid", DEFAULT_WIFI_SSID);
  String pwd  = prefs.getString("wifi_password", DEFAULT_WIFI_PASSWORD);
  String ble  = prefs.getString("ble_name", DEFAULT_BLE_NAME);
  prefs.end();

  if (ssid.length() < NET_NAME_MIN_LEN || ssid.length() > NET_NAME_MAX_LEN) ssid = DEFAULT_WIFI_SSID;
  if (pwd.length() < WIFI_PASS_MIN_LEN || pwd.length() > WIFI_PASS_MAX_LEN) pwd = DEFAULT_WIFI_PASSWORD;
  if (ble.length() < NET_NAME_MIN_LEN || ble.length() > NET_NAME_MAX_LEN || !ble.startsWith("RRC_")) ble = DEFAULT_BLE_NAME;

  if (ssid.length() >= sizeof(wifiSsid)) ssid = ssid.substring(0, sizeof(wifiSsid) - 1);
  if (pwd.length() >= sizeof(wifiPassword)) pwd = pwd.substring(0, sizeof(wifiPassword) - 1);
  if (ble.length() >= sizeof(bleName)) ble = ble.substring(0, sizeof(bleName) - 1);

  ssid.toCharArray(wifiSsid, sizeof(wifiSsid));
  pwd.toCharArray(wifiPassword, sizeof(wifiPassword));
  ble.toCharArray(bleName, sizeof(bleName));
}

void saveNetworkConfig() {
  prefs.begin("netconfig", false);
  prefs.putString("wifi_ssid", wifiSsid);
  prefs.putString("wifi_password", wifiPassword);
  prefs.putString("ble_name", bleName);
  prefs.end();
}

// Sends current motion state to the mobile app via the status characteristic.
// Payload is CSV "[estop],[up],[down],[left],[right]" (e.g. "0,1,0,0,0" = UP
// active), AES-GCM encrypted the same way as auth/command replies — the app
// treats every notification on this characteristic as an encrypted frame
// (IV(12) | CIPHER | TAG(16), min 28 bytes) and disconnects on anything else.
// The estop field reflects mobileEstopSignal (0 = cleared, 1 = stop
// requested/latched) — the app's own last request combined with any I0.1
// trip latch — not a readback of the physical output pin.
void notifyMotionStatus() {
  if (!deviceConnected || !authenticated || !statusChar) return;
  char buf[24];
  snprintf(buf, sizeof(buf), "%d,%d,%d,%d,%d",
    mobileEstopSignal ? 1 : 0,
    motionUp    ? 1 : 0,
    motionDown  ? 1 : 0,
    motionLeft  ? 1 : 0,
    motionRight ? 1 : 0);

  std::string outHex;
  if (!encryptAESGCM_packet(buf, outHex)) {
    Serial.println("BLE status notify: encryption failed, notify skipped");
    return;
  }
  statusChar->setValue(outHex);
  statusChar->notify();
  Serial.printf("BLE status notify (encrypted): %s\n", buf);
}

static bool isHeartbeatHealthy() {
  if (!deviceConnected || !authenticated || lastHeartbeatTime == 0) return false;
  return (millis() - lastHeartbeatTime) <= HEARTBEAT_TIMEOUT_MS;
}

// Samples the physical E-STOP interlock (I0.1) and combines it with the last
// E-STOP command from the mobile app to decide whether the E-STOP relay may
// be energized (motionEstop == false). Called every loop() cycle so the
// physical input is monitored continuously, independent of BLE traffic.
// - mobileEstopSignal latches to true only on the FALLING EDGE of I0.1 (the
//   instant it transitions HIGH -> LOW) — a real trip — not merely because
//   I0.1 is currently reading LOW. Once latched, it is a one-way trip that
//   persists even after I0.1 returns HIGH, until the app sends a fresh
//   estop=0 — I0.1 recovering on its own never restarts the machine. This
//   is the "two-step" interlock: the app and I0.1 must both independently
//   authorize the relay.
// - If instead the app clears mobileEstopSignal while I0.1 is already
//   sitting LOW (no edge — nothing has tripped yet, e.g. arming before
//   I0.1 first goes HIGH), that clear is not overwritten: no edge occurs
//   while I0.1 merely stays LOW, so the relay comes on by itself as soon
//   as I0.1 goes HIGH, with no second app command required.
// - The relay is only allowed ON when mobileEstopSignal == false (cleared)
//   AND I0.1 currently reads HIGH — the same rule whether or not the app is
//   connected. Actual pin writes additionally require authentication + a
//   healthy heartbeat while connected — enforced separately by
//   updateOutputPinsFromState().
void updateEstopState() {
  // Bounded, not portMAX_DELAY: see TryI2CGuard's comment. If the bus is
  // currently tied up (e.g. a stuck RTC transaction), skip this cycle and
  // hold the last known I0.1/motionEstop state rather than block — loop()
  // will retry on the next iteration, milliseconds later.
  TryI2CGuard _i2cGuard(20);
  if (!_i2cGuard.acquired()) return;
  // remoteInputIdx picks which physical input serves as this interlock
  // (default I0.1, configurable from the web UI's Input Configuration
  // page). No pin assigned (-1) fails safe: treat the interlock as open.
  bool newEstopInputHigh = (remoteInputIdx >= 0) && (digitalRead(getActiveInputPin(remoteInputIdx)) == HIGH);

  if (prevEstopInputHigh && !newEstopInputHigh) {
    // Falling edge: the interlock input just opened — latch the stop request.
    mobileEstopSignal = true;
    estopChangeReason = String(remoteInputIdx >= 0 ? getInputLabel(remoteInputIdx) : "remote") + " interlock opened";
  }
  prevEstopInputHigh = newEstopInputHigh;
  estopInputHigh     = newEstopInputHigh;

  motionEstop = !(mobileEstopSignal == false && estopInputHigh);
}

// Writes output pins while connected. This function itself only ever reads
// motionEstop for the E-STOP pin — it does not gate it on authentication or
// heartbeat health directly. Heartbeat loss instead trips E-STOP upstream,
// in loop(): once 10s of missed heartbeats latches mobileEstopSignal,
// updateEstopState() flips motionEstop to true before this function runs,
// so the E-STOP pin follows it here like any other trip. The mid-login
// window (connected but not yet authenticated) does NOT trip E-STOP by
// itself — only heartbeat loss, disconnect, or the I0.1 interlock do.
// Directional outputs (UP/DOWN/LEFT/RIGHT) are separately gated: they
// require authentication, a healthy heartbeat, and a cleared E-STOP.
static void updateOutputPinsFromState() {
  // Bounded, not portMAX_DELAY — see TryI2CGuard's comment. Skip this
  // cycle and leave the physical outputs exactly as they were last
  // successfully set, rather than block waiting for a stuck RTC
  // transaction to release the bus.
  TryI2CGuard _i2cGuard(20);
  if (!_i2cGuard.acquired()) return;
  if (!deviceConnected) {
    for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
      digitalWrite(OUTPUT_PINS[i].pin, LOW);
    }
    return;
  }

  if (!authenticated) {
    // Waiting for credentials — no authenticated command source yet, so
    // hold directional outputs off. The E-STOP pin is left untouched.
    for (int p = 0; p < NUM_OUTPUT_PINS; p++) {
      if (pinMotionConfig[p].motion == MOTION_ESTOP) continue;
      digitalWrite(OUTPUT_PINS[p].pin, LOW);
    }
    return;
  }

  bool heartbeatOk = isHeartbeatHealthy();

  for (int p = 0; p < NUM_OUTPUT_PINS; p++) {
    uint8_t motion = pinMotionConfig[p].motion;

    if (motion == MOTION_ESTOP) {
      // E-STOP pin is HIGH in normal operation (inactive/safe state),
      // LOW when motionEstop is true — never forced by heartbeat loss.
      DOUT(p, motionEstop ? LOW : HIGH);
      continue;
    }

    bool isActive = false;
    if (heartbeatOk && !motionEstop) {
      switch (motion) {
        case MOTION_UP:
          isActive = motionUp;
          break;
        case MOTION_DOWN:
          isActive = motionDown;
          break;
        case MOTION_LEFT:
          isActive = motionLeft;
          break;
        case MOTION_RIGHT:
          isActive = motionRight;
          break;
        case MOTION_NONE:
        default:
          isActive = false;
          break;
      }
    }
    DOUT(p, isActive ? HIGH : LOW);  // Other motions: HIGH when active
  }
}

// Writes output pins while no mobile app is connected. There is no command
// source for directional motion, so UP/DOWN/LEFT/RIGHT are held off. The
// E-STOP relay just reflects motionEstop (kept current by
// updateEstopState()) — but onDisconnect() latches mobileEstopSignal at the
// moment of disconnect, so by the time this runs motionEstop is already
// true and the relay is off. It stays off (and won't come back on merely
// because I0.1 is HIGH) until the app reconnects and sends a fresh
// estop=0.
static void applyOutputsDisconnected() {
  // Bounded, not portMAX_DELAY — see TryI2CGuard's comment.
  TryI2CGuard _i2cGuard(20);
  if (!_i2cGuard.acquired()) return;
  for (int p = 0; p < NUM_OUTPUT_PINS; p++) {
    uint8_t motion = pinMotionConfig[p].motion;
    if (motion == MOTION_ESTOP) {
      DOUT(p, motionEstop ? LOW : HIGH);
    } else {
      DOUT(p, LOW);
    }
  }
}

// Returns the matching user's index, or -1 if the credentials are wrong.
// Credentials are valid only when the email matches a stored user exactly and
// the password equals that user's stored password.
int checkCredentials(const std::string& email, const std::string& password) {
  for (int i = 0; i < userCount; i++) {
    // The Super Admin is a web-only role — never allowed on the BLE app.
    if (strcmp(users[i].role, "SuperAdmin") == 0) continue;
    if (email == users[i].email && password == users[i].password) {
      return i;
    }
  }
  return -1;
}

void startWiFi() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP(wifiSsid, wifiPassword);
  delay(100); // allow AP to start
  Serial.println("WiFi AP started");
  Serial.println("SSID: " + String(wifiSsid));
  Serial.println("Password: " + String(wifiPassword));
  Serial.println("Web panel: http://" + WiFi.softAPIP().toString() + "/");
}

void handleWiFi() {
  // No connection management needed in AP mode
}

// ---------------- SERVER CALLBACK ----------------
class MyServerCallbacks : public BLEServerCallbacks {
  // Extended onConnect gives us the connection handle
  void onConnect(BLEServer* pServer, esp_ble_gatts_cb_param_t *param) {
    deviceConnected = true;
    updateConnectionParams();
    authenticated   = false;
    connId          = param->connect.conn_id;
    connectTime     = millis();
    Serial.printf("Mobile connected — waiting for credentials (free heap: %u bytes)\n",
                  (unsigned)ESP.getFreeHeap());

    //forceAllOutputsOff();
    //Serial.println("Outputs forced OFF until authentication");

    authChar->setValue("AUTH_REQ:email|password|deviceid");
    authChar->notify();
  }

  void onDisconnect(BLEServer* pServer) {
    // Log the logout before clearing session state, and only if this
    // connection actually completed a login — an unauthenticated device
    // dropping mid-handshake never logged in, so it has nothing to log out.
    if (authenticated) {
      String userName = connectedUserEmail;
      for (int i = 0; i < userCount; i++) {
        if (String(users[i].email).equalsIgnoreCase(connectedUserEmail)) {
          userName = users[i].name;
          break;
        }
      }
      pendingLogoutDetail = userName + " (" + String(connectedUserEmail) + ") logged out";
      pendingLogoutEvent  = true;
    }

    deviceConnected = false;
    authenticated   = false;
    connectedUserEmail[0] = '\0';
    Serial.println("Mobile disconnected");

    // No command source for directional motion — stop it. E-STOP is also
    // tripped on disconnect now, the same as a physical I0.1 trip: latch
    // mobileEstopSignal so the relay de-energizes immediately and stays
    // off until the app reconnects and sends a fresh estop=0 — a stale
    // connection can never let the relay silently re-energize on its own.
    motionUp    = false;
    motionDown  = false;
    motionLeft  = false;
    motionRight = false;
    mobileEstopSignal = true;
    estopChangeReason = "App disconnected";
    updateEstopState();
    applyOutputsDisconnected();
    Serial.printf("Motion outputs OFF due to disconnect — E-STOP relay %s\n",
                  motionEstop ? "OFF" : "ON");

    delay(100);
    BLEDevice::startAdvertising();
  }
};

class AuthCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    try {
    // Accept encrypted auth payload: IV(12) | CIPHER | TAG(16) encoded as hex or raw
    std::string data = pCharacteristic->getValue();
    Serial.print("////Received AUTH write: ");
    Serial.println(data.c_str());
    logBLEReceivedData("AUTH write received", data);

    if (data.length() < 1) {
      Serial.println("Auth: empty payload");
      return;
    }

    // Decode encrypted packet
    uint8_t encrypted[512];
    size_t encryptedLen = 0;
    if (!decodePayload(data, encrypted, sizeof(encrypted), &encryptedLen)) {
      Serial.println("Auth: payload decode failed");
      // Reply encrypted FAIL
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
        Serial.println("Auth: sent AUTH_FAIL (encrypted)");
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    Serial.printf("Auth: decoded encrypted length=%u\n", (unsigned)encryptedLen);

    if (encryptedLen < 12 + 16) {
      Serial.println("Auth: encrypted payload too short");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    uint64_t sessionId = read48be(encrypted);
    uint64_t counter   = read48be(encrypted + 6);
    Serial.printf("Auth: IV sessionId=%012llX counter=%llu\n", (unsigned long long)sessionId, (unsigned long long)counter);

    if (!isCounterFresh(sessionId, counter)) {
      Serial.println("Auth: counter replay/stale");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    uint8_t decrypted[256];
    size_t decryptedLen = 0;
    if (!decryptAESGCM_from_bytes(encrypted, encryptedLen, decrypted, &decryptedLen)) {
      Serial.println("Auth: AES-GCM decryption failed");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    updateLastCounter(sessionId, counter);

    // Trim and NUL-terminate
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;
    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    Serial.print("Auth: decrypted ASCII: ");
    Serial.println(reinterpret_cast<char*>(decrypted));

    // Parse email|password|deviceid
    std::string s = reinterpret_cast<char*>(decrypted);
    size_t sep1 = s.find('|');
    size_t sep2 = (sep1 == std::string::npos) ? std::string::npos : s.find('|', sep1 + 1);
    if (sep1 == std::string::npos || sep2 == std::string::npos) {
      Serial.println("Auth: bad format — expected email|password|deviceid");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }
    std::string email = s.substr(0, sep1);
    std::string password = s.substr(sep1 + 1, sep2 - (sep1 + 1));
    std::string deviceId = s.substr(sep2 + 1);
    Serial.printf("Auth attempt — email: %s deviceId: %s\n", email.c_str(), deviceId.c_str());

    int userIdx = checkCredentials(email, password);
    bool okCreds = (userIdx >= 0);
    bool okTime = okCreds && isUserAccessAllowed(users[userIdx]);
    bool okDevice = (deviceId.length() > 0 && deviceId.length() <= 40 && isDeviceRegistered(deviceId.c_str()));
    bool ok = okCreds && okTime && okDevice;
    if (ok) {
      authenticated = true;
      strncpy(connectedUserEmail, email.c_str(), sizeof(connectedUserEmail) - 1);
      connectedUserEmail[sizeof(connectedUserEmail) - 1] = '\0';
      Serial.printf("Authentication SUCCESS — user: %s device: %s (free heap: %u bytes)\n",
                    email.c_str(), deviceId.c_str(), (unsigned)ESP.getFreeHeap());

      String userName = email.c_str();
      for (int i = 0; i < userCount; i++) {
        if (String(users[i].email).equalsIgnoreCase(email.c_str())) {
          userName = users[i].name;
          break;
        }
      }
      pendingLoginDetail = userName + " (" + String(email.c_str()) + ") logged in from device " + String(deviceId.c_str());
      pendingLoginEvent  = true;
    } else {
      authenticated = false;
      if (!okCreds) Serial.printf("Authentication FAILED (bad credentials) — user: %s\n", email.c_str());
      if (okCreds && !okTime) Serial.printf("Authentication FAILED (outside allowed access time) — user: %s\n", email.c_str());
      if (!okDevice) Serial.printf("Authentication FAILED (unregistered device) — device: %s\n", deviceId.c_str());
    }

    // Encrypt and send response
    std::string reply;
    if (ok) {
      // Success reply carries the logged-in user's role: "AUTH_OK| Admin" or "AUTH_OK| Operator"
      reply = std::string("AUTH_OK| ") + users[userIdx].role;
    } else if (okCreds && !okTime) {
      // Credentials valid but this timed user is outside their access window
      reply = "AUTH_FAIL:OUT_OF_TIME";
    } else if (okCreds && !okDevice) {
      // Credentials valid but device not registered
      reply = "AUTH_FAIL:UNTRUSTED_DEVICE";
    } else {
      reply = "AUTH_FAIL";
    }
    std::string outHex;
    if (encryptAESGCM_packet(reply, outHex)) {
      authChar->setValue(outHex);
      authChar->notify();
      Serial.print("Auth: sent encrypted reply HEX: ");
      Serial.println(outHex.c_str());
      Serial.print("Auth: sent encrypted reply ASCII (hex->bin shown as . if nonprintable): ");
      // print ascii-friendly view of reply hex
      for (char ch : outHex) Serial.write(ch);
      Serial.println();
    } else {
      Serial.println("Auth: failed to encrypt reply");
    }

    if (ok) {
      // Sync the app with the current real E-STOP output state right away —
      // it will otherwise not learn it until the next command or the next
      // physical change on I0.1.
      notifyMotionStatus();
    } else {
      delay(200);
      //pBLEServer->disconnect(connId);
    }
    } catch (...) {
      // A BLE GATT callback runs on the Bluedroid stack's own task — an
      // uncaught C++ exception here (e.g. std::bad_alloc from a std::string
      // allocation when heap is critically low, observed in practice right
      // around this exact auth-complete moment) used to propagate up
      // through the BT stack and abort() the whole device. Same
      // "optional/peripheral work must degrade, never crash" rule already
      // applied to SD/RTC access, extended to this callback boundary.
      Serial.println("AuthCallbacks::onWrite: exception (likely low memory) — write ignored");
    }
  }
};

// ---------------- DIGITAL WRITE CALLBACK ----------------
// Expected data format: AES-GCM encrypted payload encoded as hex text or raw bytes.
// Format (bytes): IV(12) | CIPHER | TAG(16)
// The decrypted payload must be a comma-separated motion command list:
//   [estop,up,down,left,right]
// e.g. "[0,1,0,0,0]" or "0,1,0,0,0"
// PLC14 only has 5 outputs (estop,up,down,left,right) — IntelliHMI sends
// this 5-field frame for PLC14, unlike PLC38's 10-field frame.
// estop=1 → E-STOP output OFF and ALL outputs OFF (emergency stop)
// estop=0 → E-STOP output ON and up/down/left/right follow command values
class DigitalCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    try {
    // Reject commands from unauthenticated clients
    if (!authenticated) {
      Serial.println("Command rejected — not authenticated");
      return;
    }

    std::string value = pCharacteristic->getValue();
    logBLEReceivedData("DIGITAL write received", value);
    if (value.length() < 1) return;

    uint8_t encrypted[256];
    size_t encryptedLen = 0;
    if (!decodePayload(value, encrypted, sizeof(encrypted), &encryptedLen)) {
      Serial.println("Command rejected — unable to decode encrypted payload");
      return;
    }

    if (encryptedLen < 12 + 16) {
      Serial.println("Command rejected — encrypted payload too short");
      return;
    }

    uint64_t sessionId = read48be(encrypted);
    uint64_t counter   = read48be(encrypted + 6);
    if (!isCounterFresh(sessionId, counter)) {
      Serial.printf("Command rejected — counter not incremented (session=%012llX counter=%llu)\n", (unsigned long long)sessionId, (unsigned long long)counter);
      return;
    }

    // Decrypt using AES-GCM (accepts hex text or raw bytes: IV(12) | CIPHER | TAG(16))
    uint8_t decrypted[128];
    size_t decryptedLen = 0;
    if (!decryptAESGCM_from_bytes(encrypted, encryptedLen, decrypted, &decryptedLen)) {
      Serial.println("DECRYPT FAILED");
      return;
    }

    updateLastCounter(sessionId, counter);

    // Trim trailing nulls if any
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;

    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    Serial.printf("Encrypted data length: %u\n", (unsigned)value.length());
    Serial.print("Decrypted bytes (hex): ");
    for (size_t i = 0; i < decryptedLen; ++i) {
      Serial.printf("%02X", decrypted[i]);
    }
    Serial.println();
    Serial.print("Decrypted ASCII: ");
    Serial.println(reinterpret_cast<char*>(decrypted));

    // Parse CSV payload like: "1,0,1,0,0" (estop,up,down,left,right)
    std::string s = reinterpret_cast<char*>(decrypted);
    // Trim leading/trailing whitespace
    auto trim = [](std::string &str) {
      while (!str.empty() && isspace((unsigned char)str.front())) str.erase(str.begin());
      while (!str.empty() && isspace((unsigned char)str.back())) str.pop_back();
    };
    trim(s);
    // Remove surrounding brackets if present
    if (!s.empty() && s.front() == '[' && s.back() == ']') {
      s = s.substr(1, s.size() - 2);
      trim(s);
    }

    int vals[5] = {0,0,0,0,0};
    size_t idx = 0;
    size_t start = 0;
    while (start < s.size() && idx < 5) {
      size_t pos = s.find(',', start);
      std::string token = (pos == std::string::npos) ? s.substr(start) : s.substr(start, pos - start);
      trim(token);
      if (!token.empty()) {
        vals[idx] = atoi(token.c_str());
      } else {
        vals[idx] = 0;
      }
      idx++;
      if (pos == std::string::npos) break;
      start = pos + 1;
    }

    int estop = vals[0];
    int up    = vals[1];
    int down  = vals[2];
    int left  = vals[3];
    int right = vals[4];

    Serial.printf("Received CSV: [%d,%d,%d,%d,%d]\n", estop, up, down, left, right);

    // Safety: UP/DOWN and LEFT/RIGHT pairs must never both be active at the same time
    if (up && down) {
      up = 0; down = 0;
      Serial.println("CONFLICT: UP+DOWN both active — both forced OFF");
    }
    if (left && right) {
      left = 0; right = 0;
      Serial.println("CONFLICT: LEFT+RIGHT both active — both forced OFF");
    }

    // Store the app's E-STOP request; motionEstop is derived from this plus
    // the live I0.1 interlock by updateEstopState() (relay only allowed ON
    // when BOTH the app has cleared E-STOP AND I0.1 reads HIGH).
    mobileEstopSignal = (estop == 1);
    estopChangeReason = String(estop == 1 ? "App E-STOP command by " : "App cleared E-STOP by ") + connectedUserEmail;

    if (estop == 1) {
      // Emergency stop requested — all directional outputs OFF
      motionUp    = false;
      motionDown  = false;
      motionLeft  = false;
      motionRight = false;
      Serial.println("E-STOP requested by app: Others OFF");
    } else {
      // App has cleared E-STOP — directional outputs follow the command
      motionUp    = (up != 0);
      motionDown  = (down != 0);
      motionLeft  = (left != 0);
      motionRight = (right != 0);
      Serial.printf("E-STOP:cleared UP:%d DOWN:%d LEFT:%d RIGHT:%d\n", motionUp, motionDown, motionLeft, motionRight);
    }

    updateEstopState();
    Serial.printf("I0.1=%s mobileEstopSignal=%d -> motionEstop=%d\n",
                  estopInputHigh ? "HIGH" : "LOW", mobileEstopSignal, motionEstop);

    updateOutputPinsFromState();
    //notifyMotionStatus();
    } catch (...) {
      // See AuthCallbacks::onWrite — same BLE-callback exception firewall.
      Serial.println("DigitalCallbacks::onWrite: exception (likely low memory) — write ignored");
    }
  }
};

class HeartbeatCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    try {
    if (!authenticated) {
      Serial.println("Heartbeat ignored — not authenticated");
      return;
    }

    std::string data = pCharacteristic->getValue();
    //logBLEReceivedData("HEARTBEAT write received", data);
    //Serial.printf("✓ Heartbeat received length=%u\n", (unsigned)data.length());
    
    if (data.length() == 0) {
      Serial.println("Heartbeat characteristic received EMPTY data");
      return;
    }

    uint8_t decrypted[32];
    size_t decryptedLen = 0;
    uint64_t sessionId = 0;
    uint64_t counter = 0;

    if (!decryptAndValidateEncryptedPayload(data, decrypted, &decryptedLen, sessionId, counter)) {
      Serial.println("Heartbeat decryption or validation failed");
      return;
    }

    // Trim trailing nulls if any
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;
    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    //Serial.printf("Heartbeat decrypted: %s (sessionId=%012llX counter=%llu)\n",
     // reinterpret_cast<char*>(decrypted),
     // (unsigned long long)sessionId,
     // (unsigned long long)counter);

    if (strcmp(reinterpret_cast<char*>(decrypted), "HB") != 0) {
      Serial.printf("Heartbeat invalid content: %s\n", reinterpret_cast<char*>(decrypted));
      return;
    }

    lastHeartbeatTime = millis();
    heartbeatMissCount = 0;
    if (!heartbeatAlive) {
      heartbeatAlive = true;
      Serial.println("✓ Heartbeat restored — outputs re-enabled");
    }
    updateOutputPinsFromState();
    } catch (...) {
      // See AuthCallbacks::onWrite — same BLE-callback exception firewall.
      Serial.println("HeartbeatCallbacks::onWrite: exception (likely low memory) — write ignored");
    }
  }
};

// Manual I2C bus-recovery sequence (per NXP AN10216-01 / DS3231 app notes),
// run once before Wire.begin(). If a previous run of this firmware
// crashed or reset mid I2C-transaction (which happened repeatedly while
// this board's original BLE/I2C task race was being debugged), a slave
// device — the RTC 10 Click's DS3231M in particular, per MikroE's own
// notes for this chip — can be left holding SDA low, waiting for clock
// pulses that will never come from a normal Wire.begin(). The RTC chip
// itself doesn't reset just because the ESP32 does (it stays powered from
// VCC or its backup coin cell), so a bus wedged this way stays wedged
// across every subsequent reboot until it's manually clocked free. This
// pulses SCL until SDA is observed released, then issues a clean STOP, so
// the bus always starts each boot in a known-idle state.
static void recoverI2CBus(int sdaPin, int sclPin) {
  pinMode(sdaPin, INPUT_PULLUP);
  pinMode(sclPin, OUTPUT_OPEN_DRAIN);
  digitalWrite(sclPin, HIGH);
  delayMicroseconds(5);

  if (digitalRead(sdaPin) == HIGH) return; // already idle, nothing stuck

  Serial.println("I2C bus recovery: SDA stuck low at boot — clocking it free");
  for (int i = 0; i < 9 && digitalRead(sdaPin) == LOW; i++) {
    digitalWrite(sclPin, LOW);
    delayMicroseconds(5);
    digitalWrite(sclPin, HIGH);
    delayMicroseconds(5);
  }

  // Manual STOP condition: SDA low-to-high while SCL is high.
  pinMode(sdaPin, OUTPUT_OPEN_DRAIN);
  digitalWrite(sdaPin, LOW);
  delayMicroseconds(5);
  digitalWrite(sclPin, HIGH);
  delayMicroseconds(5);
  digitalWrite(sdaPin, HIGH);
  delayMicroseconds(5);

  Serial.println(digitalRead(sdaPin) == HIGH
                      ? "I2C bus recovery: SDA released successfully"
                      : "I2C bus recovery: SDA still stuck low — check wiring/power to the RTC");
}

void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println("Firmware: " FIRMWARE_VERSION);

  // The closed-source WiFi driver's internal "wifi" log tag (wifi_log(),
  // separate from this app's own Serial output) is emitted from the
  // esp_timer task while handling AP beacon events. Formatting that log
  // line lazily initializes a newlib stdio lock on first use, which needs
  // a small heap allocation — and under this board's combined BLE + WiFi
  // AP + SD + web-server load, that allocation can fail at the wrong
  // moment. lock_init_generic() treats that failure as fatal and calls
  // abort() outright (observed as a reboot shortly after BLE auth, with
  // the crash backtrace rooted entirely in ieee80211_hostapd_beacon_txcb
  // -> wifi_log -> vprintf -> lock_init_generic, nothing in this app's own
  // code). Silencing the "wifi" tag stops wifi_log() from ever reaching
  // that vprintf/lock-init path, regardless of heap state at the time.
  esp_log_level_set("wifi", ESP_LOG_NONE);

  // Must exist before any I2C-touching call (RTC or MCP23017-backed
  // digitalRead/digitalWrite) can run from any task, BLE included.
  i2cMutex = xSemaphoreCreateMutex();

  // RTC + SD event logging — optional peripherals; init failures are
  // logged but never halt the PLC (this is safety-critical control
  // firmware, unlike a typical datalogger sketch).
  recoverI2CBus(SDA, SCL);
  Wire.begin();
  // Slower than the 100kHz default: gives weak/missing SDA-SCL pull-ups
  // (common on add-on RTC breakout boards, especially with a second I2C
  // device like this board's MCP23017 already sharing the bus) more time
  // to charge the lines before each bit is sampled, trading a little speed
  // for tolerance of a marginal bus. Cheap mitigation; does not replace
  // fixing the wiring/pull-ups if that's the actual root cause.
  Wire.setClock(50000);
  // Every I2C access in this app — including the I0.1 interlock read and
  // every output pin write, both safety-critical and done every loop()
  // cycle via the same MCP23017 — shares this one Wire instance and its
  // default 50ms per-transaction timeout. On a stressed/noisy bus (e.g.
  // relay-switching noise coupling into SDA/SCL), that default let a single
  // stuck transaction block loop() long enough to miss a real BLE heartbeat
  // and trip a spurious E-STOP — a hardware I2C hiccup should never be able
  // to fake a safety trip. Tightening the timeout bounds the worst case for
  // every I2C caller, not just the RTC.
  Wire.setTimeOut(20);
  if (!rtc10_init()) {
    Serial.println("RTC not found — event log timestamps will show N/A");
    rtcOk = false;
  } else {
    rtcOk = true;
    if (rtc10_lost_power()) {
      Serial.println("RTC lost power — setting to firmware compile time");
      // __DATE__/__TIME__ expand to this file's compile date/time, e.g.
      // "Jan 15 2026" / "10:32:01".
      static const char monthAbbrev[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
      char monStr[4] = {0};
      int cday = 1, cyear = 2026, chour = 0, cmin = 0, csec = 0;
      sscanf(__DATE__, "%3s %d %d", monStr, &cday, &cyear);
      sscanf(__TIME__, "%d:%d:%d", &chour, &cmin, &csec);
      const char *pos = strstr(monthAbbrev, monStr);
      int cmonth = pos ? (int)((pos - monthAbbrev) / 3) + 1 : 1;
      rtc10_setDate(computeDayOfWeek(cyear, cmonth, cday), (uint8_t)cday, (uint8_t)cmonth, (uint16_t)cyear);
      rtc10_setTime((uint8_t)chour, (uint8_t)cmin, (uint8_t)csec);
      rtc10_clear_lost_power();
    }
    // Prime the software clock cache immediately so the very first web
    // page load / log entry has a real timestamp instead of "N/A" until
    // the first periodic sync in loop() gets around to it.
    syncTimeCache();
  }

  if (!SD.begin(SD_CS_PIN)) {
    Serial.println("SD card not found — event logging disabled");
    sdOk = false;
  } else {
    sdOk = true;
    Serial.println("SD card ready for event logging");
  }

  loadUsers();
  loadOutputConfig();  // reads NVS, applies pinMode + LOW for all 5 outputs
  loadHoistConfig();   // reads NVS, which hoist(s) are enabled
  loadInputConfig();   // reads NVS, applies pinMode INPUT for all 9 inputs
  // Explicitly configure digital outputs and 24V supply pins
  pinMode(Q0_0, OUTPUT);
  pinMode(Q0_1, OUTPUT);
  pinMode(Q0_2, OUTPUT);
  pinMode(Q0_3, OUTPUT);

 pinMode(S0_24v, OUTPUT);
 pinMode(S1_24v, OUTPUT);
 pinMode(S2_24v, OUTPUT);
 pinMode(S3_24v, OUTPUT);

 digitalWrite(S0_24v, HIGH);
 digitalWrite(S1_24v, HIGH);
 digitalWrite(S2_24v, HIGH);
 digitalWrite(S3_24v, HIGH);

  // Ensure all configured output pins are set to OUTPUT on startup
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    digitalWrite(OUTPUT_PINS[i].pin, LOW);
  }
  loadNetworkConfig();
  forceAllOutputsOff();
  lastNotifiedMobileEstopSignal = mobileEstopSignal;

  startWiFi();

  setupWebRoutes();

  // This app only ever uses BLE (BLECharacteristic/BLEServer/etc. —
  // nothing here touches classic Bluetooth/SPP), but the ESP32's BT
  // controller reserves memory for BOTH classic BT and BLE by default,
  // whether or not classic BT is ever used. Releasing the unused classic
  // BT portion here — the one point in boot where it's still possible,
  // strictly before the controller initializes inside BLEDevice::init()
  // below — hands back roughly 70KB to the heap for the rest of this
  // app's lifetime. Given every OOM this firmware has hit this session
  // (WiFi's internal logger, SD.open(), a BLE notify's std::string,
  // WebServer's own read buffer) traces back to chronically low free
  // heap (as little as ~43KB reported right at boot, before any client
  // even connects), this single call is likely a bigger win than any of
  // those individual fixes.
  esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);

  BLEDevice::init(bleName);

  pBLEServer = BLEDevice::createServer();
  pBLEServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pBLEServer->createService(BLEUUID(SERVICE_UUID), BLE_SERVICE_HANDLE_COUNT);


  digitalChar = pService->createCharacteristic(
    DIGITAL_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE_NR
  );
  digitalChar->setCallbacks(new DigitalCallbacks());

  authChar = pService->createCharacteristic(
    AUTH_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_NOTIFY
  );
  authChar->addDescriptor(new BLE2902());
  authChar->setCallbacks(new AuthCallbacks());

  statusChar = pService->createCharacteristic(
    STATUS_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );
  statusChar->addDescriptor(new BLE2902());

  heartbeatChar = pService->createCharacteristic(
    HEARTBEAT_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE_NR
  );
  heartbeatChar->setCallbacks(new HeartbeatCallbacks());

  analogChar = pService->createCharacteristic(
    ANALOG_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );
  analogChar->addDescriptor(new BLE2902());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  BLEAdvertisementData advertData;
  advertData.setManufacturerData("PLC14");
  pAdvertising->setAdvertisementData(advertData);
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->start();

  Serial.printf("BLE Ready... (free heap: %u bytes)\n", (unsigned)ESP.getFreeHeap());
}

void loop() {

  // Sample I0.1 and refresh motionEstop every cycle, regardless of BLE
  // connection state, so the physical interlock is always live.
  updateEstopState();

  if (deviceConnected) {

    if (!authenticated && (millis() - connectTime > AUTH_TIMEOUT_MS)) {
      Serial.println("Auth timeout — disconnecting client");
      authChar->setValue("AUTH_TIMEOUT");
      authChar->notify();
      delay(200);
      pBLEServer->disconnect(connId);
      return;
    }

    // A timed user's access window can close while they're connected: check
    // once a second and drop the connection (which also trips E-STOP, same
    // as any other disconnect) as soon as it does.
    static unsigned long lastAccessCheckMs = 0;
    if (authenticated && millis() - lastAccessCheckMs >= 1000) {
      lastAccessCheckMs = millis();
      int ui = findUserIndexByEmail(connectedUserEmail);
      if (ui >= 0 && !isUserAccessAllowed(users[ui])) {
        Serial.printf("Access window ended — disconnecting user: %s\n", connectedUserEmail);
        std::string outHex;
        if (encryptAESGCM_packet("AUTH_FAIL:OUT_OF_TIME", outHex)) {
          authChar->setValue(outHex);
          authChar->notify();
        }
        delay(200);
        pBLEServer->disconnect(connId);
        return;
      }
    }

    unsigned long elapsed = lastHeartbeatTime == 0 ? ULONG_MAX : (millis() - lastHeartbeatTime);
    int newMissCount = 0;
    
    const unsigned long step = HEARTBEAT_TIMEOUT_MS / 5;
    if (elapsed > step)     newMissCount = 1;
    if (elapsed > step * 2) newMissCount = 2;
    if (elapsed > step * 3) newMissCount = 3;
    if (elapsed > step * 4) newMissCount = 4;
    if (elapsed > step * 5) newMissCount = 5;

    if (newMissCount != heartbeatMissCount) {
      heartbeatMissCount = newMissCount;
      if (heartbeatMissCount >= 1 && heartbeatMissCount <= 4) {
        Serial.printf("✗ Heartbeat NOT received — missing for > %lums\n", step * heartbeatMissCount);
      } else if (heartbeatMissCount >= 5) {
        if (heartbeatAlive) {
          heartbeatAlive = false;
          // Heartbeat loss now trips E-STOP the same way a physical I0.1
          // trip or a BLE disconnect does: latch mobileEstopSignal so the
          // relay de-energizes and requires a fresh estop=0 from the app
          // once the heartbeat recovers, instead of silently resuming.
          mobileEstopSignal = true;
          estopChangeReason = "Heartbeat lost";
          updateEstopState();
          Serial.println("✗ Heartbeat NOT received — missing counter reached 5 (10s) — outputs turned OFF, E-STOP tripped");
        } else if (lastHeartbeatTime == 0) {
          Serial.println("✗ Heartbeat NOT received — no data ever arrived on heartbeat characteristic");
        }
      }
    }

    updateOutputPinsFromState();
  } else {
    heartbeatAlive = false;
    motionUp    = false;
    motionDown  = false;
    motionLeft  = false;
    motionRight = false;
    applyOutputsDisconnected();
  }

  // Detect changes to mobileEstopSignal — including ones driven purely by an
  // I0.1 falling-edge trip, with no app command involved — and notify the
  // app as soon as they happen.
  if (mobileEstopSignal != lastNotifiedMobileEstopSignal) {
    lastNotifiedMobileEstopSignal = mobileEstopSignal;
    notifyMotionStatus();
  }

  // Log every real transition of the final gated E-STOP output to the SD
  // card, regardless of which of the four trigger sites (I0.1, app
  // command, BLE disconnect, heartbeat loss) caused it. The E-STOP output
  // is HIGH (relay energized) when motionEstop is false — the crane is
  // allowed to run — and LOW when motionEstop is true, so:
  //   output HIGH -> "CRANE_START",  output LOW -> "CRANE_STOP".
  if (motionEstop != lastLoggedMotionEstop) {
    lastLoggedMotionEstop = motionEstop;
    logEvent(motionEstop ? "CRANE_STOP" : "CRANE_START", estopChangeReason);
  }

  // Drain login/logout events recorded by BLE callbacks (a different task)
  // — the actual SD write always happens here, from loop(), never from the
  // BLE task itself.
  if (pendingLoginEvent) {
    pendingLoginEvent = false;
    logEvent("LOGIN", pendingLoginDetail);
  }
  if (pendingLogoutEvent) {
    pendingLogoutEvent = false;
    logEvent("LOGOUT", pendingLogoutDetail);
  }

  printHoistValues();

  // Periodic software-clock resync (see the cache comment near
  // syncTimeCache()'s definition) — off any event's critical path, so a
  // transient I2C fault here just leaves the cache as-is until next time.
  // A genuinely dead/disconnected RTC (not just a transient fault) still
  // costs real time on every attempt, since the ESP32's I2C peripheral has
  // to wait out its own hardware timeout talking to a chip that never
  // answers — even bounded, that's still overhead paid every 2 seconds
  // forever for no benefit once it's clear nothing is there. So after 3
  // consecutive periodic misses, stop retrying for the rest of this boot
  // (timestamps just stay at their last known value / "N/A") — a device
  // that's fully disconnected isn't going to start answering on attempt 4.
  static unsigned long lastTimeSyncMs        = 0;
  static uint8_t       consecutiveSyncMisses = 0;
  static bool          rtcSyncGivenUp        = false;
  const unsigned long  TIME_SYNC_INTERVAL_MS = 2000;
  if (!rtcSyncGivenUp && millis() - lastTimeSyncMs >= TIME_SYNC_INTERVAL_MS) {
    lastTimeSyncMs = millis();
    if (syncTimeCache()) {
      consecutiveSyncMisses = 0;
    } else if (++consecutiveSyncMisses >= 3) {
      rtcSyncGivenUp = true;
      Serial.println("syncTimeCache: RTC not responding after 3 consecutive attempts — giving up on periodic resync for this session");
    }
  }

  handleWiFi(); // does nothing in AP mode
  webServer.handleClient();

  delay(20);
}
