#include "rtc10.h"
#include <Wire.h>

static uint8_t bcd2bin(uint8_t val) { return (val & 0x0F) + ((val >> 4) * 10); }
static uint8_t bin2bcd(uint8_t val) { return (val % 10) | ((val / 10) << 4); }

bool rtc10_init() {
  Wire.beginTransmission(RTC10_I2C_SLAVE_ADDRESS);
  return Wire.endTransmission() == 0;
}

// Set whenever a read silently falls back to 0 below, so a caller can tell
// a genuine 0 apart from a dropped/NACK'd transaction. This intentionally
// does NOT retry the I2C transaction itself: on an already-stressed bus,
// retrying here too — on top of currentTimestamp()'s own paced retry —
// hammers the bus with back-to-back attempts and no settling delay, which
// in practice wedged the ESP32 Wire driver badly enough to abort()/reboot.
// currentTimestamp() checks this flag and does its retrying, with a delay
// between attempts, instead.
static bool s_readFailed = false;

void rtc10_clear_read_error() { s_readFailed = false; }
bool rtc10_had_read_error() { return s_readFailed; }

uint8_t rtc10_read_byte(uint8_t reg_address) {
  Wire.beginTransmission(RTC10_I2C_SLAVE_ADDRESS);
  Wire.write(reg_address);
  Wire.endTransmission(false); // repeated start — keep the bus for the read
  Wire.requestFrom((int)RTC10_I2C_SLAVE_ADDRESS, 1);
  if (Wire.available() < 1) {
    s_readFailed = true;
    return 0;
  }
  return Wire.read();
}

void rtc10_write_byte(uint8_t reg_address, uint8_t write_data) {
  Wire.beginTransmission(RTC10_I2C_SLAVE_ADDRESS);
  Wire.write(reg_address);
  Wire.write(write_data);
  Wire.endTransmission();
}

bool rtc10_lost_power() {
  return (rtc10_read_byte(RTC10_STATUS) & 0x80) != 0;
}

void rtc10_clear_lost_power() {
  uint8_t status = rtc10_read_byte(RTC10_STATUS);
  rtc10_write_byte(RTC10_STATUS, status & ~0x80);
}

// -- Per-field get/set, same BCD layout as the official rtc10.c --

uint8_t rtc10_get_time_seconds() { return bcd2bin(rtc10_read_byte(RTC10_RTCSEC) & 0x7F); }
void rtc10_set_time_seconds(uint8_t seconds) { rtc10_write_byte(RTC10_RTCSEC, bin2bcd(seconds % 60)); }

uint8_t rtc10_get_time_minutes() { return bcd2bin(rtc10_read_byte(RTC10_RTCMIN) & 0x7F); }
void rtc10_set_time_minutes(uint8_t minutes) { rtc10_write_byte(RTC10_RTCMIN, bin2bcd(minutes % 60)); }

uint8_t rtc10_get_time_hours() {
  // Bit 6 (12/24-hour select) is always written 0 by rtc10_set_time_hours
  // below, so bits 5:4 here are always the 24-hour "tens" field.
  return bcd2bin(rtc10_read_byte(RTC10_RTCHOUR) & 0x3F);
}
void rtc10_set_time_hours(uint8_t hours) { rtc10_write_byte(RTC10_RTCHOUR, bin2bcd(hours % 24)); }

uint8_t rtc10_get_day_of_the_week() { return rtc10_read_byte(RTC10_RTCWKDAY) & 0x07; }
void rtc10_set_day_of_the_week(uint8_t w_day) {
  w_day %= 8;
  if (w_day == 0) w_day = 1;
  rtc10_write_byte(RTC10_RTCWKDAY, w_day);
}

uint8_t rtc10_get_date_day() { return bcd2bin(rtc10_read_byte(RTC10_RTCDATE) & 0x3F); }
void rtc10_set_date_day(uint8_t date_day) {
  date_day %= 32;
  if (date_day == 0) date_day = 1;
  rtc10_write_byte(RTC10_RTCDATE, bin2bcd(date_day));
}

uint8_t rtc10_get_date_month() { return bcd2bin(rtc10_read_byte(RTC10_RTCMTH) & 0x1F); }
void rtc10_set_date_month(uint8_t date_month) {
  date_month %= 13;
  if (date_month == 0) date_month = 1;
  rtc10_write_byte(RTC10_RTCMTH, bin2bcd(date_month));
}

uint8_t rtc10_get_date_year() { return bcd2bin(rtc10_read_byte(RTC10_RTCYEAR)); }
void rtc10_set_date_year(uint16_t date_year) {
  date_year %= 100;
  rtc10_write_byte(RTC10_RTCYEAR, bin2bcd((uint8_t)date_year));
}

// -- Combined functions, matching the product page's documented API --

void rtc10_setTime(uint8_t timeHours, uint8_t timeMinutes, uint8_t timeSeconds) {
  rtc10_set_time_hours(timeHours);
  rtc10_set_time_minutes(timeMinutes);
  rtc10_set_time_seconds(timeSeconds);
}

void rtc10_getTime(uint8_t *timeHours, uint8_t *timeMinutes, uint8_t *timeSeconds) {
  *timeHours   = rtc10_get_time_hours();
  *timeMinutes = rtc10_get_time_minutes();
  *timeSeconds = rtc10_get_time_seconds();
}

void rtc10_setDate(uint8_t dayOfTheWeek, uint8_t dateDay, uint8_t dateMonth, uint16_t dateYear) {
  rtc10_set_day_of_the_week(dayOfTheWeek);
  rtc10_set_date_day(dateDay);
  rtc10_set_date_month(dateMonth);
  rtc10_set_date_year(dateYear);
}

void rtc10_getDate(uint8_t *dayOfTheWeek, uint8_t *dateDay, uint8_t *dateMonth, uint8_t *dateYear) {
  *dayOfTheWeek = rtc10_get_day_of_the_week();
  *dateDay      = rtc10_get_date_day();
  *dateMonth    = rtc10_get_date_month();
  *dateYear     = rtc10_get_date_year();
}

float rtc10_get_temperature() {
  uint8_t msb = rtc10_read_byte(RTC10_TEMPERATURE_MSB);
  uint8_t lsb = rtc10_read_byte(RTC10_TEMPERATURE_LSB);
  int8_t whole = (int8_t)msb;
  float frac = (lsb >> 6) * 0.25f;
  return whole + frac;
}
