#pragma once
#include <Arduino.h>

// Arduino/Wire port of the MikroElektronika "RTC 10 Click" board driver
// (DS3231M RTC, I2C address 0x68).
//
// The official rtc10.c/rtc10.h shipped in lib/"RTC 10 Click" are written
// against MikroElektronika's own mikroSDK hardware-abstraction layer
// (drv_i2c_master.h, drv_digital_out.h, drv_digital_in.h), which doesn't
// exist in this ESP32/Arduino/PlatformIO build — those files cannot
// compile here. This file reimplements the same register map (address
// 0x68, registers 0x00-0x12, verified against both the official rtc10.h
// and the DS3231 datasheet) and the same documented function names, on
// top of Arduino's Wire library instead, so the RTC 10 Click can actually
// be driven from this project.
//
// All time/date values are plain binary here (e.g. hours 0-23), not BCD —
// BCD<->binary conversion happens internally, exactly as the original
// library does.

#define RTC10_I2C_SLAVE_ADDRESS 0x68

#define RTC10_RTCSEC          0x00
#define RTC10_RTCMIN          0x01
#define RTC10_RTCHOUR         0x02
#define RTC10_RTCWKDAY        0x03
#define RTC10_RTCDATE         0x04
#define RTC10_RTCMTH          0x05
#define RTC10_RTCYEAR         0x06
#define RTC10_CONTROL         0x0E
#define RTC10_STATUS          0x0F
#define RTC10_TEMPERATURE_MSB 0x11
#define RTC10_TEMPERATURE_LSB 0x12

// Probes the RTC 10 Click on the I2C bus (call Wire.begin() first).
// Returns true if the device acknowledges its address.
bool rtc10_init();

// Low-level single-register access, same as the official driver.
uint8_t rtc10_read_byte(uint8_t reg_address);
void    rtc10_write_byte(uint8_t reg_address, uint8_t write_data);

// Tracks whether any rtc10_read_byte() call since the last clear silently
// fell back to 0 because the I2C transaction failed (e.g. NACK/timeout on
// a contended or unhealthy bus). A caller doing a multi-register read
// (time+date) should clear this first, then check it afterward alongside
// its own range checks, rather than trusting a "valid-looking" 0.
void rtc10_clear_read_error();
bool rtc10_had_read_error();

// STATUS register bit 7 (OSF - Oscillator Stop Flag): true once power was
// lost/insufficient since the time was last set — same signal RTClib
// exposes as lostPower(). Clear it once a known-good time has been set.
bool rtc10_lost_power();
void rtc10_clear_lost_power();

uint8_t rtc10_get_time_seconds();
void    rtc10_set_time_seconds(uint8_t seconds);
uint8_t rtc10_get_time_minutes();
void    rtc10_set_time_minutes(uint8_t minutes);
uint8_t rtc10_get_time_hours();
void    rtc10_set_time_hours(uint8_t hours);
uint8_t rtc10_get_day_of_the_week();
void    rtc10_set_day_of_the_week(uint8_t w_day); // 1=Monday .. 7=Sunday
uint8_t rtc10_get_date_day();
void    rtc10_set_date_day(uint8_t date_day);
uint8_t rtc10_get_date_month();
void    rtc10_set_date_month(uint8_t date_month);
uint8_t rtc10_get_date_year();           // 2-digit (0-99), same as the original driver
void    rtc10_set_date_year(uint16_t date_year); // pass 2- or 4-digit; reduced mod 100

// Combined set/get functions — same names/signatures as the RTC 10 Click
// product page's "Key functions" list.
void rtc10_setTime(uint8_t timeHours, uint8_t timeMinutes, uint8_t timeSeconds);
void rtc10_getTime(uint8_t *timeHours, uint8_t *timeMinutes, uint8_t *timeSeconds);
void rtc10_setDate(uint8_t dayOfTheWeek, uint8_t dateDay, uint8_t dateMonth, uint16_t dateYear);
void rtc10_getDate(uint8_t *dayOfTheWeek, uint8_t *dateDay, uint8_t *dateMonth, uint8_t *dateYear);

// Reads the DS3231M's on-die temperature sensor (deg C, 0.25 deg resolution).
float rtc10_get_temperature();
