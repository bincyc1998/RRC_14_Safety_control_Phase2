#include "web_handler.h"
#include <Update.h>
#include <SD.h>

// Drop-in replacement for webServer.send(...), used everywhere in this file
// instead of calling it directly.
//
// A client that silently vanishes mid-session — WiFi range lost, app
// killed, a bad moment of WiFi/BLE radio coexistence contention — leaves
// no FIN/RST for the ESP32's TCP stack to notice, so the socket still
// looks "connected" with nothing locally wrong to detect in advance.
// Writing to it then runs into WiFiClient::write()'s own internal retry
// loop: up to 10 attempts, each waiting up to 1 second for the socket to
// become writable, so a single send() can block this task for up to ~10
// seconds — and that loop never actually closes the socket on a plain
// timeout, only for a handful of specific hard errors. Left alone, the
// same zombie connection gets retried again on the next request that
// reaches it, and keeps one of the ESP32's very few sockets pinned
// indefinitely, which is what "site can't be reached" for a new visitor
// actually is: no free socket left to accept them.
//
// There's no way to detect this case beforehand, so this times the actual
// write instead: a write on a healthy local AP link should take single-
// digit milliseconds, so anything far beyond that is treated as proof the
// peer is gone, and the connection is force-closed right then rather than
// left to be retried again later.
static void sendSafe(int code, const char* contentType = NULL, const String& content = String("")) {
  unsigned long writeStartMs = millis();
  webServer.send(code, contentType, content);
  unsigned long writeMs = millis() - writeStartMs;
  if (writeMs > 300) {
    Serial.printf("Web: client write took %lums — treating connection as dead, closing it\n", writeMs);
    webServer.client().stop();
  }
}

#define MAX_SESSIONS 5
struct WebSession
{
  String token;
  String role;      // "Admin" / "Operator"
  String userEmail; // empty = web admin, else BLE user email
  bool timeExempt = false; // true for admin "Login As": skips the timed-access window check
};
static WebSession sessions[MAX_SESSIONS];
static int sessionNext = 0; // round-robin eviction counter

// Device registry
Device devices[MAX_DEVICES];
int deviceCount = 0;

void loadDevices()
{
  prefs.begin("devices", true);
  deviceCount = prefs.getInt("count", 0);
  if (deviceCount < 0)
    deviceCount = 0;
  if (deviceCount > MAX_DEVICES)
    deviceCount = MAX_DEVICES;
  for (int i = 0; i < deviceCount; i++)
  {
    char idkey[16], okey[16];
    sprintf(idkey, "dev_%d", i);
    sprintf(okey, "owner_%d", i);
    prefs.getString(idkey, devices[i].id, sizeof(devices[i].id));
    prefs.getString(okey, devices[i].owner, sizeof(devices[i].owner));
  }
  prefs.end();
}

void saveDevices()
{
  prefs.begin("devices", false);
  prefs.putInt("count", deviceCount);
  for (int i = 0; i < deviceCount; i++)
  {
    char idkey[16], okey[16];
    sprintf(idkey, "dev_%d", i);
    sprintf(okey, "owner_%d", i);
    prefs.putString(idkey, devices[i].id);
    prefs.putString(okey, devices[i].owner);
  }
  prefs.end();
}

bool isDeviceRegistered(const char *id)
{
  if (!id || id[0] == '\0')
    return false;
  for (int i = 0; i < deviceCount; i++)
  {
    if (strcmp(devices[i].id, id) == 0)
      return true;
  }
  return false;
}

bool registerDevice(const char *id, const char *owner)
{
  if (!id || id[0] == '\0')
    return false;
  if (strlen(id) > 40)
    return false;
  if (isDeviceRegistered(id))
    return false;
  if (deviceCount >= MAX_DEVICES)
    return false;
  strncpy(devices[deviceCount].id, id, sizeof(devices[deviceCount].id));
  devices[deviceCount].id[sizeof(devices[deviceCount].id) - 1] = '\0';
  if (owner)
    strncpy(devices[deviceCount].owner, owner, sizeof(devices[deviceCount].owner));
  else
    devices[deviceCount].owner[0] = '\0';
  devices[deviceCount].owner[sizeof(devices[deviceCount].owner) - 1] = '\0';
  deviceCount++;
  saveDevices();
  return true;
}

bool unregisterDevice(const char *id)
{
  if (!id)
    return false;
  for (int i = 0; i < deviceCount; i++)
  {
    if (strcmp(devices[i].id, id) == 0)
    {
      for (int j = i; j < deviceCount - 1; j++)
      {
        devices[j] = devices[j + 1];
      }
      deviceCount--;
      saveDevices();
      return true;
    }
  }
  return false;
}

// Web admin credentials (mutable, persisted in NVS namespace "webadmin")
static char webAdminUser[64] = "superadmin@plc.com";
static char webAdminPass[64] = "superadmin123";

static void loadWebAdmin()
{
  prefs.begin("webadmin", true);
  String u = prefs.getString("user", "superadmin@plc.com");
  String p = prefs.getString("pass", "superadmin123");
  prefs.end();
  // Migrate stale NVS that stored a plain username (no @) — reset to email default
  if (u.indexOf('@') < 0)
  {
    u = "superadmin@plc.com";
    p = "superadmin123";
    prefs.begin("webadmin", false);
    prefs.putString("user", u);
    prefs.putString("pass", p);
    prefs.end();
    Serial.println("Web admin migrated to email login (superadmin@plc.com / superadmin123)");
  }
  u.toCharArray(webAdminUser, sizeof(webAdminUser));
  p.toCharArray(webAdminPass, sizeof(webAdminPass));
}

static void saveWebAdmin()
{
  prefs.begin("webadmin", false);
  prefs.putString("user", webAdminUser);
  prefs.putString("pass", webAdminPass);
  prefs.end();
}

static String generateToken()
{
  char buf[33];
  for (int i = 0; i < 32; i++)
  {
    buf[i] = "0123456789abcdef"[random(16)];
  }
  buf[32] = '\0';
  return String(buf);
}

static String getSessionCookie()
{
  String cookieHeader = webServer.header("Cookie");
  int idx = cookieHeader.indexOf("session=");
  if (idx < 0)
    return "";
  int start = idx + 8;
  int end = cookieHeader.indexOf(';', start);
  if (end < 0)
    return cookieHeader.substring(start);
  return cookieHeader.substring(start, end);
}

// Find session slot for the current request cookie; returns -1 if not found
static int findSessionIdx()
{
  String cookie = getSessionCookie();
  if (cookie.length() == 0)
    return -1;
  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token.length() > 0 && sessions[i].token == cookie)
      return i;
  }
  return -1;
}
// Helpers: role and email for the current request
static String currentRole()
{
  int i = findSessionIdx();
  return i >= 0 ? sessions[i].role : "";
}
static String currentUserEmail()
{
  int i = findSessionIdx();
  return i >= 0 ? sessions[i].userEmail : "";
}
// ---- Timed-access helpers ----
// Formats a timestamp as "YYYY-MM-DD HH:MM", or as "YYYY-MM-DDTHH:MM" (the
// value format of <input type='datetime-local'>) when `forInput` is true.
static String formatDateTime(uint32_t ts, bool forInput = false)
{
  time_t t = (time_t)ts;
  struct tm tmv;
  gmtime_r(&t, &tmv);
  char buf[20];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d%c%02d:%02d", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
           forInput ? 'T' : ' ', tmv.tm_hour, tmv.tm_min);
  return String(buf);
}

// "Perpetual" or "Timed 2026-03-01 09:00 to 2026-03-05 17:00"
static String accessLabel(const User &u)
{
  if (u.accessType != ACCESS_TIMED)
    return "Perpetual";
  return "Timed " + formatDateTime(u.startTs) + " to " + formatDateTime(u.endTs);
}

// Parses "YYYY-MM-DDTHH:MM" (from <input type='datetime-local'>) into seconds
// since 1970, treating the fields as literal RTC date/time (no time zone).
static bool parseDateTimeLocal(const String &s, uint32_t &ts)
{
  if (s.length() < 16 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':')
    return false;
  int y = s.substring(0, 4).toInt();
  int mo = s.substring(5, 7).toInt();
  int d = s.substring(8, 10).toInt();
  int h = s.substring(11, 13).toInt();
  int mi = s.substring(14, 16).toInt();
  if (y < 2000 || y > 2099 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59)
    return false;
  // Days since 1970-01-01 for the given civil date (proleptic Gregorian).
  int yy = mo <= 2 ? y - 1 : y;
  int era = yy / 400;
  int yoe = yy - era * 400;
  int doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  long days = (long)era * 146097 + doe - 719468;
  ts = (uint32_t)(days * 86400L + h * 3600L + mi * 60L);
  return true;
}

// Reads accessType/from/to from the Add/Edit form into `u`. Returns an error
// message, or an empty string on success.
static String readAccessFromForm(User &u)
{
  if (webServer.arg("accessType") != "timed")
  {
    u.accessType = ACCESS_PERPETUAL;
    u.startTs = 0;
    u.endTs = 0;
    return "";
  }
  uint32_t from, to;
  if (!parseDateTimeLocal(webServer.arg("fromTime"), from) || !parseDateTimeLocal(webServer.arg("toTime"), to))
    return "Timed access requires both a From and a To date and time.";
  if (to <= from)
    return "Timed access: the To date and time must be after the From date and time.";
  u.accessType = ACCESS_TIMED;
  u.startTs = from;
  u.endTs = to;
  return "";
}

// Access Type dropdown + From/To date-time inputs (shown only for Timed).
// `u` is null on the Add form (defaults to Perpetual).
static String accessFormFields(const User *u)
{
  bool timed = u && u->accessType == ACCESS_TIMED;
  String selStyle = "width:100%;padding:9px 12px;border:1px solid #E2E8F0;"
                    "border-radius:7px;font-size:14.5px;color:#1E293B;outline:none;background:#fff;";
  String h = "<div class='form-group'><label>Access</label>";
  h += "<select name='accessType' id='accessType' style='" + selStyle + "' "
       "onchange=\"document.getElementById('timedBox').style.display=this.value==='timed'?'flex':'none';"
       "document.getElementById('fromTime').required=document.getElementById('toTime').required=this.value==='timed';\">";
  h += "<option value='perpetual'" + String(timed ? "" : " selected") + ">Perpetual (any time)</option>";
  h += "<option value='timed'" + String(timed ? " selected" : "") + ">Timed (only between a start and end date/time)</option>";
  h += "</select></div>";
  h += "<div class='form-group' id='timedBox' style='display:" + String(timed ? "flex" : "none") + ";gap:14px;flex-wrap:wrap;'>";
  h += "<div style='flex:1;min-width:200px;'><label>From (date &amp; time)</label><input type='datetime-local' name='fromTime' id='fromTime' value='" +
       (timed ? formatDateTime(u->startTs, true) : String("")) + "'" + (timed ? " required" : "") + "></div>";
  h += "<div style='flex:1;min-width:200px;'><label>To (date &amp; time)</label><input type='datetime-local' name='toTime' id='toTime' value='" +
       (timed ? formatDateTime(u->endTs, true) : String("")) + "'" + (timed ? " required" : "") + "></div>";
  h += "</div>";
  return h;
}

// Allocate a slot — prefers empty, else evicts round-robin
static int allocSessionSlot()
{
  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token.length() == 0)
      return i;
  }
  int slot = sessionNext;
  sessionNext = (sessionNext + 1) % MAX_SESSIONS;
  return slot;
}

static const char HTML_STYLE[] =
    ":root{--brand:#1565C0;--brand-dark:#0B3D91;--brand-ink:#0F2E5C;--border:#E2E8F0;"
    "--text:#1E293B;--text-soft:#64748B;--text-faint:#94A3B8;--bg:#F7F9FC;"
    "--surface:#fff;--danger:#DC2626;--danger-dark:#B91C1C;"
    "--shadow-sm:0 1px 2px rgba(15,23,42,.05);--shadow-md:0 4px 16px rgba(15,23,42,.08);}"
    "*{box-sizing:border-box;margin:0;padding:0;}"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;"
    "background:var(--bg);color:var(--text);min-height:100vh;font-size:15px;line-height:1.5;"
    "-webkit-font-smoothing:antialiased;}"
    ".topbar{background:var(--brand-dark);display:flex;align-items:center;"
    "justify-content:space-between;padding:0 28px;height:60px;box-shadow:0 1px 3px rgba(0,0,0,.18);}"
    ".brand{color:#fff;font-size:19px;font-weight:700;letter-spacing:.5px;}"
    ".topbar nav a{color:rgba(255,255,255,.82);text-decoration:none;margin-left:18px;font-size:14px;"
    "padding:6px 12px;border-radius:6px;transition:background .2s;}"
    ".topbar nav a:hover{background:rgba(255,255,255,.14);color:#fff;}"
    ".container{max-width:760px;margin:28px auto;padding:0 16px;}"
    ".layout{display:flex;min-height:calc(100vh - 60px);}"
    ".sidebar{width:232px;background:var(--surface);border-right:1px solid var(--border);"
    "flex-shrink:0;padding:16px 0;}"
    ".sidebar-section{padding:16px 20px 8px;font-size:11px;font-weight:700;color:var(--text-faint);"
    "text-transform:uppercase;letter-spacing:.6px;}"
    ".sidebar-item{display:flex;align-items:center;gap:11px;padding:10px 20px;cursor:pointer;"
    "color:var(--text-soft);font-size:14.5px;font-weight:500;border-left:3px solid transparent;"
    "transition:background .15s,color .15s,border-color .15s;user-select:none;}"
    ".sidebar-item:hover{background:#F1F5F9;color:var(--text);}"
    ".sidebar-item.active{background:#EFF6FF;color:var(--brand-dark);"
    "border-left-color:var(--brand);font-weight:600;}"
    ".sidebar-icon{font-size:17px;width:20px;text-align:center;opacity:.85;}"
    ".main-content{flex:1;padding:28px 32px;background:var(--bg);overflow-y:auto;}"
    ".tab-panel{display:none;}"
    ".tab-panel.active{display:block;}"
    ".section-title{font-size:19px;font-weight:700;color:var(--text);margin-bottom:4px;"
    "letter-spacing:-.2px;}"
    ".section-sub{font-size:13.5px;color:var(--text-soft);margin-bottom:20px;}"
    ".divider{border:none;border-top:1px solid var(--border);margin:24px 0;}"
    ".page-title{margin-bottom:20px;}"
    ".page-title h1{color:var(--text);font-size:21px;font-weight:700;letter-spacing:-.2px;}"
    ".subtitle{color:var(--text-soft);font-size:13.5px;margin-top:3px;}"
    ".card{background:var(--surface);border:1px solid var(--border);border-radius:10px;"
    "box-shadow:var(--shadow-sm);padding:24px 26px;margin-bottom:20px;}"
    "table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);"
    "border-radius:10px;overflow:hidden;box-shadow:var(--shadow-sm);margin-bottom:16px;}"
    "thead tr{background:var(--brand-ink);}"
    "thead th{color:rgba(255,255,255,.94);padding:11px 16px;font-size:12px;font-weight:600;"
    "text-align:left;text-transform:uppercase;letter-spacing:.5px;}"
    "tbody tr{border-bottom:1px solid var(--border);transition:background .15s;}"
    "tbody tr:last-child td{border-bottom:none;}"
    "tbody tr:hover{background:#F8FAFC;}"
    "td{padding:11px 16px;color:var(--text);font-size:14px;}"
    ".btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border:none;border-radius:7px;"
    "cursor:pointer;font-size:14px;font-weight:600;text-decoration:none;transition:all .15s;line-height:1.4;}"
    ".btn-primary{background:var(--brand);color:#fff;}"
    ".btn-primary:hover{background:var(--brand-dark);box-shadow:0 2px 8px rgba(11,61,145,.28);}"
    ".btn-outline{background:var(--surface);color:var(--brand);border:1px solid #C7D7EE;}"
    ".btn-outline:hover{background:#EFF6FF;border-color:var(--brand);}"
    ".btn-edit{background:var(--surface);color:var(--brand);border:1px solid #C7D7EE;}"
    ".btn-edit:hover{background:#EFF6FF;border-color:var(--brand);}"
    ".btn-danger{background:var(--danger);color:#fff;}"
    ".btn-danger:hover{background:var(--danger-dark);box-shadow:0 2px 8px rgba(185,28,28,.28);}"
    ".btn-cancel{background:var(--surface);color:var(--text-soft);border:1px solid var(--border);}"
    ".btn-cancel:hover{background:#F1F5F9;}"
    ".action-bar{display:flex;gap:10px;margin-bottom:20px;}"
    ".form-group{margin-bottom:16px;}"
    ".form-group label{display:block;font-size:12.5px;font-weight:700;color:var(--text-soft);"
    "text-transform:uppercase;letter-spacing:.4px;margin-bottom:7px;}"
    ".form-group input{width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:7px;"
    "font-size:14.5px;color:var(--text);background:var(--surface);outline:none;"
    "transition:border .2s,box-shadow .2s;}"
    ".form-group input:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(21,101,192,.12);}"
    ".form-actions{margin-top:22px;display:flex;gap:10px;}"
    ".badge{display:inline-block;background:#EFF6FF;color:var(--brand-dark);"
    "font-size:12.5px;font-weight:600;padding:4px 11px;border-radius:20px;}"
    ".alert{padding:12px 16px;border-radius:8px;font-size:14px;margin-bottom:16px;line-height:1.5;}"
    ".alert-info{background:#EFF6FF;color:var(--brand-ink);border-left:3px solid var(--brand);}"
    ".alert-danger{background:#FEF2F2;color:#991B1B;border-left:3px solid var(--danger);}"
    ".del-box{text-align:center;padding:10px 0 20px;}"
    ".del-icon{font-size:38px;margin-bottom:12px;}"
    ".del-msg{color:var(--text-soft);font-size:15px;margin-bottom:4px;}"
    ".del-email{font-weight:700;color:var(--text);font-size:15px;margin-bottom:22px;}"
    ".del-btns{display:flex;justify-content:center;gap:12px;}"
    ".table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:10px;margin-bottom:16px;}"
    /* ---- Responsive ---- */
    "@media(max-width:900px){"
    ".sidebar{width:196px;}"
    ".main-content{padding:20px 18px;}"
    "}"
    ".main-content{min-width:0;}"
    "img,input,select,textarea{max-width:100%;}"
    "@media(max-width:768px){"
    ".topbar{padding:0 14px;height:54px;}"
    ".brand{font-size:16px;}"
    ".layout{flex-direction:column;min-height:unset;}"
    ".sidebar{width:100%;border-right:none;border-bottom:1px solid var(--border);"
    "padding:0;display:flex;flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;}"
    ".sidebar-section{display:none;}"
    ".sidebar-item{flex:0 0 auto;white-space:nowrap;padding:12px 14px;border-left:none;"
    "border-bottom:3px solid transparent;justify-content:center;font-size:13.5px;}"
    ".sidebar-item.active{border-left:none;border-bottom-color:var(--brand);}"
    ".sidebar-icon{display:none;}"
    ".main-content{padding:14px 10px;overflow-x:hidden;}"
    ".card{padding:16px 14px;}"
    ".section-title{font-size:17px;}"
    "table{font-size:13px;display:block;overflow-x:auto;-webkit-overflow-scrolling:touch;}"
    "td,thead th{padding:8px 8px;}"
    ".btn{padding:7px 12px;font-size:13px;}"
    ".action-bar{flex-wrap:wrap;}"
    ".form-actions{flex-wrap:wrap;}"
    ".del-btns{flex-wrap:wrap;}"
    ".home-grid{grid-template-columns:1fr;}"
    "}"
    /* ---- User dropdown menu ---- */
    ".user-menu{position:relative;}"
    ".user-btn{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.1);"
    "color:#fff;border:1px solid rgba(255,255,255,.3);border-radius:8px;"
    "padding:6px 12px;cursor:pointer;font-size:13.5px;font-weight:600;"
    "font-family:inherit;outline:none;transition:background .2s;}"
    ".user-btn:hover{background:rgba(255,255,255,.18);}"
    ".user-avatar{width:24px;height:24px;border-radius:50%;background:rgba(255,255,255,.22);"
    "display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;}"
    ".user-dropdown{display:none;position:absolute;right:0;top:calc(100% + 8px);"
    "background:#fff;border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow-md);"
    "min-width:190px;z-index:999;overflow:hidden;}"
    ".user-dropdown.open{display:block;}"
    ".user-dropdown a{display:flex;align-items:center;gap:10px;padding:11px 16px;"
    "color:var(--text);text-decoration:none;font-size:14px;font-weight:500;"
    "border-bottom:1px solid var(--bg);transition:background .15s;}"
    ".user-dropdown a:last-child{border-bottom:none;}"
    ".user-dropdown a:hover{background:var(--bg);color:var(--brand-dark);}"
    ".dd-danger{color:var(--danger) !important;}"
    ".user-dropdown .dd-danger:hover{background:#FEF2F2;color:var(--danger-dark) !important;}"
    "@media(max-width:660px){"
    ".user-btn .uname{display:none;}"
    ".user-btn .arr{display:none;}"
    "}"
    /* ---- Home Overview Cards ---- */
    ".home-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:24px;}"
    ".home-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;"
    "box-shadow:var(--shadow-sm);padding:22px 24px;border-top:3px solid #E2E8F0;}"
    ".home-card-title{font-size:11px;font-weight:700;color:var(--text-faint);text-transform:uppercase;"
    "letter-spacing:.8px;margin-bottom:12px;}"
    ".home-val{font-size:25px;font-weight:700;color:var(--text);margin-bottom:4px;letter-spacing:-.3px;}"
    ".home-sub{font-size:13px;color:var(--text-soft);}"
    ".ble-pill{display:inline-flex;align-items:center;gap:7px;padding:5px 13px;"
    "border-radius:20px;font-size:14px;font-weight:600;}"
    ".ble-pill-on{background:#ECFDF3;color:#166534;}"
    ".ble-pill-off{background:#F1F5F9;color:var(--text-soft);}"
    ".ble-pill-wait{background:#FFF7ED;color:#C2410C;}"
    ".ble-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}"
    ".ble-dot-on{background:#16A34A;box-shadow:0 0 5px rgba(22,163,74,.5);}"
    ".ble-dot-off{background:#CBD5E1;}"
    ".ble-dot-wait{background:#EA580C;box-shadow:0 0 5px rgba(234,88,12,.5);}"
    ".motion-tag{display:inline-block;padding:5px 12px;border-radius:16px;"
    "font-size:13px;font-weight:600;margin:2px 3px;}"
    ".tag-up{background:#EFF6FF;color:var(--brand-dark);}"
    ".tag-down{background:#ECFEFF;color:#0E7490;}"
    ".tag-estop{background:#FEF2F2;color:#991B1B;}"
    ".tag-idle{background:#F1F5F9;color:var(--text-soft);}"
    "@media(max-width:660px){.home-grid{grid-template-columns:1fr;}}"
    /* ---- Output Config select ---- */
    ".oc-select{width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:7px;"
    "font-size:14px;color:var(--text);outline:none;background:var(--surface);"
    "transition:border .2s,box-shadow .2s;}"
    ".oc-select:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(21,101,192,.12);}"
    ".oc-row td{vertical-align:middle;padding:12px 16px;}"
    ".oc-motion{font-size:14px;font-weight:600;color:var(--text);}";

// ============================================================
//  Login page
// ============================================================
static String loginPage(const String &errMsg)
{
  String html;
  html = "<!DOCTYPE html><html lang='en'><head>";
  html += "<meta charset='UTF-8'>";
  html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>Sign In | INTELLI RRC</title>";
  html += "<link rel='stylesheet' href='/style.css?v=3'>";
  html += "<style>"
          "body{display:flex;justify-content:center;align-items:center;min-height:100vh;"
          "background:radial-gradient(circle at 30% 20%,#123B7A,#0B2447 70%);}"
          ".login-box{background:#fff;border:1px solid var(--border);border-radius:14px;"
          "box-shadow:0 20px 50px rgba(0,0,0,.3);padding:40px 36px;width:100%;max-width:380px;}"
          ".login-brand{text-align:center;color:var(--text);font-size:20px;font-weight:700;"
          "letter-spacing:.3px;margin-bottom:4px;}"
          ".login-sub{text-align:center;color:var(--text-soft);font-size:13px;margin-bottom:28px;}"
          "@media(max-width:440px){"
          ".login-box{padding:30px 20px;border-radius:10px;}"
          ".login-brand{font-size:17px;}"
          "}"
          "</style>";
  html += "</head><body>";
  html += "<div class='login-box'>";
  html += "<div class='login-brand'>&#9889; INTELLI RRC</div>";
  html += "<div class='login-sub'>PLC Control Panel</div>";
  if (errMsg.length() > 0)
  {
    html += "<div class='alert alert-danger'>" + errMsg + "</div>";
  }
  html += "<form method='POST' action='/login'>";
  html += "<div class='form-group'><label>Email Address</label>";
  html += "<input type='email' name='username' placeholder='Enter your email address' required autofocus></div>";
  html += "<div class='form-group' style='margin-bottom:24px;'><label>Password</label>";
  html += "<input type='password' name='password' placeholder='Enter password' required></div>";
  html += "<button type='submit' class='btn btn-primary' "
          "style='width:100%;justify-content:center;padding:11px;font-size:15px;'>"
          "&#128274; Sign In</button>";
  html += "</form></div></body></html>";
  return html;
}

// ============================================================
//  Page helpers
// ============================================================
static String pageHead(const char *title, const char *subtitle = nullptr)
{
  String h;
  h = "<!DOCTYPE html><html lang='en'><head>";
  h += "<meta charset='UTF-8'>";
  h += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  h += "<title>";
  h += title;
  h += " | Intelli RRC</title>";
  h += "<link rel='stylesheet' href='/style.css?v=3'>";
  h += "</head><body>";
  h += "<div class='topbar'>";
  h += "<span class='brand'>INTELLI RRC</span>";
  h += "<div class='user-menu'>";
  h += "<button class='user-btn' onclick='toggleMenu(event)'>";
  {
    String _dn;
    String _sue = currentUserEmail();
    if (_sue.length() > 0)
    {
      // Show name for BLE users
      _dn = _sue; // fallback to email
      for (int _i = 0; _i < userCount; _i++)
      {
        if (String(users[_i].email).equalsIgnoreCase(_sue))
        {
          _dn = String(users[_i].name);
          break;
        }
      }
    }
    else
    {
      _dn = String(webAdminUser);
    }
    h += "<div class='user-avatar'>" + String((char)toupper(_dn[0])) + "</div>";
    h += "<span class='uname'>" + _dn + "</span>";
  }
  h += "<span class='arr' style='font-size:10px;opacity:.75;'>&#9660;</span>";
  h += "</button>";
  h += "<div class='user-dropdown' id='userDrop'>";
  h += "<a href='/account'>&#9881; Account Settings</a>";
  h += "<a href='/logout' class='dd-danger'>&#x23FB; Logout</a>";
  h += "</div></div>";
  h += "</div><div class='container'>";
  h += "<div class='page-title'><h1>";
  h += title;
  h += "</h1>";
  if (subtitle)
  {
    h += "<p class='subtitle'>";
    h += subtitle;
    h += "</p>";
  }
  h += "</div>";
  return h;
}

static String pageFoot()
{
  return "<script>"
         "function toggleMenu(e){e.stopPropagation();"
         "document.getElementById('userDrop').classList.toggle('open');}"
         "document.addEventListener('click',function(){"
         "var d=document.getElementById('userDrop');if(d)d.classList.remove('open');});"
         "</script>"
         "</div></body></html>";
}

static String errorPage(String msg, const char *backUrl)
{
  String h = pageHead("Error");
  h += "<div class='card'><div class='alert alert-danger'>";
  h += msg;
  h += "</div>";
  h += "<a href='";
  h += backUrl;
  h += "' class='btn btn-cancel'>&#8592; Back</a>";
  h += "</div>";
  h += pageFoot();
  return h;
}

// ============================================================
//  Auth — cookie session
// ============================================================
static bool webAuth()
{
  int si = findSessionIdx();
  if (si >= 0)
  {
    // A timed user's session ends the moment their access window closes.
    // Web admin (no userEmail) and admin "Login As" sessions are exempt.
    if (sessions[si].userEmail.length() > 0 && !sessions[si].timeExempt)
    {
      int ui = findUserIndexByEmail(sessions[si].userEmail.c_str());
      if (ui >= 0 && !isUserAccessAllowed(users[ui]))
      {
        sessions[si].token = "";
        sessions[si].role = "";
        sessions[si].userEmail = "";
        Serial.printf("Web: access window ended — session closed for %s\n", users[ui].email);
        webServer.sendHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
        webServer.sendHeader("Location", "/login?timeout=1");
        sendSafe(302);
        return false;
      }
    }
    return true;
  }
  webServer.sendHeader("Location", "/login");
  sendSafe(302);
  return false;
}

// Accepts Admin or Operator for Output Config
static bool webAuthOutputConfig()
{
  if (!webAuth())
    return false;
  String role = currentRole();
  if (role != "SuperAdmin" && role != "Admin" && role != "Operator")
  {
    sendSafe(403, "text/html", errorPage("Access denied. Operator or Admin privileges required.", "/"));
    return false;
  }
  return true;
}

// Full web access: Super Admin and Admin.
static bool isManagerRole(const String &role)
{
  return role == "SuperAdmin" || role == "Admin";
}

static bool webAuthAdmin()
{
  if (!webAuth())
    return false;
  if (!isManagerRole(currentRole()))
  {
    sendSafe(403, "text/html", errorPage("Access denied. Admin privileges required.", "/"));
    return false;
  }
  return true;
}

// Only the Super Admin may create, edit, delete or impersonate Admin accounts;
// an Admin may only manage Operators. Sends a 403 and returns false otherwise.
static bool webCanManageUser(int idx)
{
  if (currentRole() == "SuperAdmin" || String(users[idx].role) != "Admin")
    return true;
  sendSafe(403, "text/html", errorPage("Access denied. Only the Super Admin can manage Admin accounts.", "/?tab=users"));
  return false;
}

// ============================================================
//  Login / Logout
// ============================================================
static void handleLoginGet()
{
  if (findSessionIdx() >= 0)
  {
    webServer.sendHeader("Location", "/");
    sendSafe(302);
    return;
  }
  sendSafe(200, "text/html", loginPage(webServer.hasArg("timeout") ? "Your access time has ended. You have been logged out." : ""));
}

static void handleLoginPost()
{
  String username = webServer.arg("username");
  String password = webServer.arg("password");
  // Web admin credentials
  if (String(webAdminUser).equalsIgnoreCase(username) && password == webAdminPass)
  {
    int _slot = allocSessionSlot();
    sessions[_slot].token = generateToken();
    sessions[_slot].role = "SuperAdmin";
    sessions[_slot].userEmail = "";
    sessions[_slot].timeExempt = false;
    webServer.sendHeader("Set-Cookie", "session=" + sessions[_slot].token + "; HttpOnly; Path=/");
    webServer.sendHeader("Location", "/");
    sendSafe(303);
    return;
  }
  // BLE user credentials — match by email only
  for (int i = 0; i < userCount; i++)
  {
    bool emailMatch = String(users[i].email).equalsIgnoreCase(username);
    if (emailMatch && String(users[i].password) == password)
    {
      if (!isUserAccessAllowed(users[i]))
      {
        String msg = (currentTimestamp() == "N/A")
                         ? String("Access not allowed: the device clock is unavailable, so your access time cannot be verified.")
                         : "Access not allowed at this time. Your access period is " + formatDateTime(users[i].startTs) +
                               " to " + formatDateTime(users[i].endTs) + ".";
        sendSafe(403, "text/html", loginPage(msg));
        return;
      }
      int _slot = allocSessionSlot();
      sessions[_slot].token = generateToken();
      sessions[_slot].role = String(users[i].role);
      sessions[_slot].userEmail = String(users[i].email);
      sessions[_slot].timeExempt = false;
      webServer.sendHeader("Set-Cookie", "session=" + sessions[_slot].token + "; HttpOnly; Path=/");
      webServer.sendHeader("Location", "/");
      sendSafe(303);
      return;
    }
  }
  sendSafe(401, "text/html", loginPage("Invalid email address or password."));
}

static void handleLogout()
{
  int _si = findSessionIdx();
  if (_si >= 0)
  {
    sessions[_si].token = "";
    sessions[_si].role = "";
    sessions[_si].userEmail = "";
  }
  webServer.sendHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
  webServer.sendHeader("Location", "/login");
  sendSafe(303);
}

// ============================================================
//  SD card file helpers (Files tab)
// ============================================================
// Files up to this size can be edited in the browser. The limit is small on
// purpose: saving posts the whole text as a urlencoded form body, which this
// WebServer library copies several times over in RAM (raw body, a parsed
// copy and the decoded value), and the ESP32 has little free heap.
#define FILE_EDIT_MAX_BYTES 4096
// A larger file is shown read-only: only its last FILE_VIEW_MAX_BYTES bytes.
#define FILE_VIEW_MAX_BYTES 16384
// Lines are only counted for files up to this size, so listing the card
// can't stall the main loop (which also runs the safety I/O) on huge files.
#define FILE_COUNT_MAX_BYTES 262144UL

static String htmlEsc(const String &s)
{
  String o;
  o.reserve(s.length() + 8);
  for (unsigned i = 0; i < s.length(); i++)
  {
    char c = s[i];
    if (c == '&')
      o += "&amp;";
    else if (c == '<')
      o += "&lt;";
    else if (c == '>')
      o += "&gt;";
    else if (c == '"')
      o += "&quot;";
    else if (c == '\'')
      o += "&#39;";
    else
      o += c;
  }
  return o;
}

static String urlEnc(const String &s)
{
  String o;
  char buf[4];
  for (unsigned i = 0; i < s.length(); i++)
  {
    char c = s[i];
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~')
      o += c;
    else
    {
      snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
      o += buf;
    }
  }
  return o;
}

// A plain file name in the SD root: no path separators or characters FAT
// forbids, and not hidden/relative (leading dot). Blocks "../" tricks.
static bool validSdName(const String &n)
{
  if (n.length() == 0 || n.length() > 60 || n[0] == '.')
    return false;
  for (unsigned i = 0; i < n.length(); i++)
  {
    char c = n[i];
    if ((unsigned char)c < 0x20 || strchr("/\\:*?\"<>|", c))
      return false;
  }
  return true;
}

// SD.open() throws std::bad_alloc when heap is low (see logEvent()); a failed
// open must degrade to "can't open", never abort the controller.
static bool sdOpen(const String &path, const char *mode, File &f)
{
  try
  {
    f = SD.open(path, mode);
  }
  catch (...)
  {
    return false;
  }
  return (bool)f;
}

static String formatSize(uint32_t bytes)
{
  char buf[16];
  if (bytes < 1024)
    snprintf(buf, sizeof(buf), "%u B", (unsigned)bytes);
  else if (bytes < 1024UL * 1024UL)
    snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1024.0);
  else
    snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024.0));
  return String(buf);
}

// Number of lines (log entries) in an open file, or -1 if the file is too
// large or counting ran past `deadlineMs`.
static long countEntries(File &f, unsigned long deadlineMs)
{
  if (f.size() > FILE_COUNT_MAX_BYTES)
    return -1;
  uint8_t buf[256];
  long lines = 0;
  uint8_t last = '\n';
  int n;
  while ((n = f.read(buf, sizeof(buf))) > 0)
  {
    for (int i = 0; i < n; i++)
      if (buf[i] == '\n')
        lines++;
    last = buf[n - 1];
    if (millis() > deadlineMs)
      return -1;
  }
  if (last != '\n')
    lines++; // final line without a trailing newline
  return lines;
}

// ============================================================
//  Dashboard  —  two-column layout
// ============================================================
static void handleRoot()
{
  if (!webAuth())
    return;

  String role = currentRole();
  bool isAdmin = isManagerRole(role); // Super Admin or Admin: full web access
  bool isSuper = (role == "SuperAdmin");
  bool isOperator = (role == "Operator");
  String defaultTab = "home";
  String activeTab = webServer.hasArg("tab") ? webServer.arg("tab") : defaultTab;
  if (!isAdmin && activeTab == "users")
    activeTab = "home";
  if (!isAdmin && activeTab == "devices")
    activeTab = "home";
  if (!isAdmin && activeTab == "ota")
    activeTab = "home";
  if (!isAdmin && activeTab == "files")
    activeTab = "home";
  if (activeTab != "home" && activeTab != "users" && activeTab != "outconfig" && activeTab != "network" && activeTab != "devices" && activeTab != "inconfig" && activeTab != "time" && activeTab != "ota" && activeTab != "files")
    activeTab = defaultTab;
  bool isHome = (activeTab == "home");
  bool isUsers = (activeTab == "users");
  bool isDevices = (activeTab == "devices");
  bool isOutConfig = (activeTab == "outconfig");
  bool isNetwork = (activeTab == "network");
  bool isInConfig = (activeTab == "inconfig");
  bool isTime = (activeTab == "time");
  bool isOta = (activeTab == "ota");
  bool isFiles = (activeTab == "files");

  // fragMode: an AJAX tab-switch request (see showTab() in the page shell
  // script below) asking only for the active tab's own markup, not the
  // whole page shell. Every full page navigation opens a brand-new TCP
  // connection on this WebServer library (it never reuses connections —
  // "Connection: close" is sent unconditionally), and the ESP32's socket
  // table is small enough that browsing through several tabs in a normal
  // session can exhaust it, wedging the whole web server until a manual
  // reset. Serving tab switches as a small fragment swapped into the
  // existing page — instead of a full page reload — avoids opening a new
  // connection for every sidebar click.
  bool fragMode = webServer.hasArg("frag");

  // Start chunked response immediately so the browser doesn't time out while
  // we build the large HTML string.
  webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
  sendSafe(200, "text/html", "");

  // Helper lambda: flush html to client whenever it exceeds 4 KB,
  // then clear the buffer.
  //
  // A client that's actually gone — not just "closed the tab" (a clean
  // FIN, which connected()'s cheap probe below catches), but silently
  // vanished (WiFi range lost, app killed, a bad moment of BLE/WiFi
  // coexistence contention on this same radio) — leaves the ESP32's TCP
  // stack still believing the socket is open, because no FIN/RST ever
  // arrived to tell it otherwise. Writing to a socket like that runs into
  // WiFiClient::write()'s own internal retry loop: up to 10 attempts,
  // each waiting up to 1s for the socket to become writable, so a single
  // sendContent() call can block this task for up to ~10 seconds — and
  // since that loop never actually closes the socket on a plain timeout
  // (only stop()s it for a handful of specific hard errors), the SAME
  // stale connection gets retried again on the next flush() of this same
  // response, and the one after that, stacking up into a multi-second
  // (here, ~23s) stall that blocks every page for every client, since
  // this WebServer handles one connection at a time. Left long enough,
  // this also clogs the ESP32's small socket table with zombie
  // connections that are never freed — which is what "site can't be
  // reached" for a NEW visitor actually is: no free socket left to
  // accept them.
  //
  // connected()'s probe can't see this "silently vanished" case (nothing
  // it can check locally says the peer is gone), so instead this times
  // the actual write and treats an abnormally slow one — far beyond what
  // any write on a healthy local AP link should take — as proof enough:
  // force-close the connection right then instead of leaving it to be
  // retried again later, and stop doing any further work for the rest of
  // this response.
  String html;
  html.reserve(4096);
  bool clientDead = false;
  auto flush = [&]()
  {
    if (clientDead) { html = ""; return; }
    if (html.length() > 0)
    {
      if (!webServer.client().connected()) {
        clientDead = true;
        html = "";
        return;
      }
      unsigned long writeStartMs = millis();
      webServer.sendContent(html);
      unsigned long writeMs = millis() - writeStartMs;
      if (writeMs > 300) {
        Serial.printf("Web: client write took %lums — treating connection as dead, closing it\n", writeMs);
        webServer.client().stop();
        clientDead = true;
      }
      html = "";
    }
  };
  auto mayFlush = [&]()
  {
    if (html.length() >= 4096)
      flush();
  };
  if (!fragMode)
  {
  html = "<!DOCTYPE html><html lang='en'><head>";
  html += "<meta charset='UTF-8'>";
  html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>Intelli RRC</title>";
  html += "<link rel='stylesheet' href='/style.css?v=3'>";
  html += "</head><body>";

  // Page-shell script: tab switching, menu toggle, and the helpers a
  // tab's own inline <script> (moved into that tab's panel markup below)
  // relies on. Emitted once, before any panel content, so those helpers
  // exist by the time a panel's script runs — whether that's this same
  // full-page load, or a later fragment swapped in by showTab().
  html += "<script>";
  html += "var __currentTab='" + activeTab + "';";
  html += "var __pollTimer=null;";
  html += "function __stopTimers(){if(__pollTimer){clearInterval(__pollTimer);__pollTimer=null;}}";
  html += "function __runScripts(container){";
  html += "var list=container.querySelectorAll('script');";
  html += "for(var i=0;i<list.length;i++){";
  html += "var old=list[i];var s=document.createElement('script');";
  html += "if(old.src){s.src=old.src;}else{s.textContent=old.textContent;}";
  html += "old.parentNode.replaceChild(s,old);}}";
  html += "function showTab(t){";
  html += "var mc=document.querySelector('.main-content');";
  html += "if(!mc){window.location='/?tab='+encodeURIComponent(t);return;}";
  html += "fetch('/?tab='+encodeURIComponent(t)+'&frag=1',{cache:'no-store',headers:{'X-Requested-With':'fetch'}})";
  html += ".then(function(r){if(!r.ok||(r.url&&r.url.indexOf('/login')!==-1))throw new Error('nav-failed');return r.text();})";
  html += ".then(function(frag){";
  html += "__stopTimers();mc.innerHTML=frag;__runScripts(mc);";
  html += "var items=document.querySelectorAll('.sidebar-item');";
  html += "for(var i=0;i<items.length;i++)items[i].classList.remove('active');";
  html += "var navEl=document.getElementById('nav-'+t);if(navEl)navEl.classList.add('active');";
  html += "history.pushState({tab:t},'','/?tab='+encodeURIComponent(t));";
  html += "__currentTab=t;";
  html += "})";
  html += ".catch(function(){window.location='/?tab='+encodeURIComponent(t);});";
  html += "}";
  html += "window.addEventListener('popstate',function(){";
  html += "var params=new URLSearchParams(window.location.search);";
  html += "var t=params.get('tab')||'home';";
  html += "if(t!==__currentTab)showTab(t);});";
  html += "function toggleMenu(e){e.stopPropagation();"
          "document.getElementById('userDrop').classList.toggle('open');}"
          "document.addEventListener('click',function(){"
          "var d=document.getElementById('userDrop');if(d)d.classList.remove('open');});";
  html += "</script>";
  mayFlush(); // flush <head>+styles+shell script immediately

  // Topbar
  html += "<div class='topbar'>";
  html += "<span class='brand'>INTELLI RRC</span>";
  html += "<div class='user-menu'>";
  html += "<button class='user-btn' onclick='toggleMenu(event)'>";
  {
    String _dn;
    String _sue2 = currentUserEmail();
    if (_sue2.length() > 0)
    {
      _dn = _sue2; // fallback
      for (int _i = 0; _i < userCount; _i++)
      {
        if (String(users[_i].email).equalsIgnoreCase(_sue2))
        {
          _dn = String(users[_i].name);
          break;
        }
      }
    }
    else
    {
      _dn = String(webAdminUser);
    }
    html += "<div class='user-avatar'>" + String((char)toupper(_dn[0])) + "</div>";
    html += "<span class='uname'>" + _dn + "</span>";
  }
  html += "<span class='arr' style='font-size:10px;opacity:.75;'>&#9660;</span>";
  html += "</button>";
  html += "<div class='user-dropdown' id='userDrop'>";
  html += "<a href='/account'>&#9881; Account Settings</a>";
  html += "<a href='/logout' class='dd-danger'>&#x23FB; Logout</a>";
  html += "</div></div>";
  html += "</div>";

  // Two-column layout
  html += "<div class='layout'>";

  // --- Sidebar ---
  html += "<div class='sidebar'>";
  html += "<div class='sidebar-section'>Navigation</div>";
  html += "<div class='sidebar-item" + String(isHome ? " active" : "") + "' id='nav-home' onclick=\"showTab('home')\"\u003e<span class='sidebar-icon'>&#127968;</span>Home</div>";
  if (isAdmin)
  {
    html += "<div class='sidebar-item" + String(isUsers ? " active" : "") + "' id='nav-users' onclick=\"showTab('users')\"\u003e<span class='sidebar-icon'>&#128100;</span>User Management</div>";
    html += "<div class='sidebar-item" + String(isDevices ? " active" : "") + "' id='nav-devices' onclick=\"showTab('devices')\"\u003e<span class='sidebar-icon'>&#128241;</span>Device Registry</div>";
    html += "<div class='sidebar-item" + String(isOta ? " active" : "") + "' id='nav-ota' onclick=\"showTab('ota')\"\u003e<span class='sidebar-icon'>&#128260;</span>Firmware Update</div>";
    html += "<div class='sidebar-item" + String(isFiles ? " active" : "") + "' id='nav-files' onclick=\"showTab('files')\"><span class='sidebar-icon'>&#128193;</span>Files</div>";
  }
  if (isAdmin || isOperator)
  {
    html += "<div class='sidebar-item" + String(isOutConfig ? " active" : "") + "' id='nav-outconfig' onclick=\"showTab('outconfig')\"\u003e<span class='sidebar-icon'>&#9881;</span>Output Config</div>";
    html += "<div class='sidebar-item" + String(isInConfig ? " active" : "") + "' id='nav-inconfig' onclick=\"showTab('inconfig')\"\u003e<span class='sidebar-icon'>&#128225;</span>Input Config</div>";
    html += "<div class='sidebar-item" + String(isNetwork ? " active" : "") + "' id='nav-network' onclick=\"showTab('network')\"\u003e<span class='sidebar-icon'>&#128246;</span>Network Settings</div>";
    html += "<div class='sidebar-item" + String(isTime ? " active" : "") + "' id='nav-time' onclick=\"showTab('time')\">" + "<span class='sidebar-icon'>&#128337;</span>Time &amp; Date</div>";
  }
  html += "</div>";
  mayFlush(); // flush sidebar

  // --- Main content ---
  html += "<div class='main-content'>";
  } // end if (!fragMode) — shell (head/topbar/sidebar/main-content-open)

  // ====== HOME PANEL ======
  if (isHome)
  {
    html += "<div id='tab-home' class='tab-panel active'>";
    html += "<div class='section-title'>&#127968; Home</div>";
    html += "<div class='home-grid'>";

    // --- BLE Connection Card ---
    {
      const char *pillCls, *dotCls, *bleLabel;
      String userLabel = "";
      if (deviceConnected && authenticated)
      {
        pillCls = "ble-pill ble-pill-on";
        dotCls = "ble-dot ble-dot-on";
        bleLabel = "Connected";
        if (connectedUserEmail[0] != '\0')
        {
          userLabel = String(connectedUserEmail);
          for (int _bi = 0; _bi < userCount; _bi++)
          {
            if (String(users[_bi].email).equalsIgnoreCase(connectedUserEmail))
            {
              userLabel = String(users[_bi].name);
              break;
            }
          }
        }
      }
      else if (deviceConnected)
      {
        pillCls = "ble-pill ble-pill-wait";
        dotCls = "ble-dot ble-dot-wait";
        bleLabel = "Authenticating...";
      }
      else
      {
        pillCls = "ble-pill ble-pill-off";
        dotCls = "ble-dot ble-dot-off";
        bleLabel = "Not Connected";
      }
      html += "<div class='home-card' style='border-top:3px solid #16A34A;'>";
      html += "<div class='home-card-title'>&#128241; BLE Connection</div>";
      html += "<div id='hble-conn' class='" + String(pillCls) + "'>";
      html += "<span class='" + String(dotCls) + "'></span>" + String(bleLabel) + "</div>";
      if (userLabel.length() > 0)
      {
        html += "<div id='hble-user' style='margin-top:10px;font-size:15px;"
                "color:#1E293B;font-weight:600;'>User: " +
                userLabel + "</div>";
      }
      else
      {
        html += "<div id='hble-user' style='display:none;margin-top:10px;font-size:15px;"
                "color:#1E293B;font-weight:600;'></div>";
      }
      html += "</div>";
    }

    // --- Motion Status Card ---
    {
      String tags = "";
      // Web status reflects E-STOP output state: HIGH means shown as active.
      if (!motionEstop)
        tags += "<span class='motion-tag tag-estop'>&#9888; E-STOP</span>";
      if (motionUp)
        tags += "<span class='motion-tag tag-up'>&#9650; UP</span>";
      if (motionDown)
        tags += "<span class='motion-tag tag-down'>&#9660; DOWN</span>";
      if (motionLeft)
        tags += "<span class='motion-tag tag-up'>&#9664; LEFT</span>";
      if (motionRight)
        tags += "<span class='motion-tag tag-down'>&#9654; RIGHT</span>";
      if (!motionUp && !motionDown && !motionLeft && !motionRight)
        tags += "<span class='motion-tag tag-idle'>No Active Motion</span>";
      html += "<div class='home-card' style='border-top:3px solid #EA580C;'>";
      html += "<div class='home-card-title'>&#127959; Motion Status</div>";
      html += "<div id='hmot-status'>" + tags + "</div>";
      html += "</div>";
    }
    html += "</div>"; // end home-grid

    // Home tab live updater — travels with this panel's own markup (moved
    // here from the old shared bottom script) so it works both on a full
    // page load and when this panel is swapped in as an AJAX fragment.
    html += "<script>";
    html += "function updateHomeUI(s){";
    html += "var bc=document.getElementById('hble-conn');";
    html += "var bu=document.getElementById('hble-user');";
    html += "if(bc){";
    html += "if(s.ble_conn===1&&s.ble_auth===1){";
    html += "bc.className='ble-pill ble-pill-on';";
    html += "bc.innerHTML=\"<span class='ble-dot ble-dot-on'></span>Connected\";";
    html += "if(bu){bu.style.display='block';bu.textContent='User: '+(s.ble_user||'Unknown');}";
    html += "}else if(s.ble_conn===1){";
    html += "bc.className='ble-pill ble-pill-wait';";
    html += "bc.innerHTML=\"<span class='ble-dot ble-dot-wait'></span>Authenticating...\";";
    html += "if(bu)bu.style.display='none';";
    html += "}else{";
    html += "bc.className='ble-pill ble-pill-off';";
    html += "bc.innerHTML=\"<span class='ble-dot ble-dot-off'></span>Not Connected\";";
    html += "if(bu)bu.style.display='none';}}";
    html += "var ms=document.getElementById('hmot-status');";
    html += "if(ms){";
    html += "var mt='';";
    html += "if(s.estop===1){mt+=\"<span class='motion-tag tag-estop'>&#9888; E-STOP</span>\";}";
    html += "if(s.up===1)mt+=\"<span class='motion-tag tag-up'>&#9650; UP</span>\";";
    html += "if(s.down===1)mt+=\"<span class='motion-tag tag-down'>&#9660; DOWN</span>\";";
    html += "if(s.left===1)mt+=\"<span class='motion-tag tag-up'>&#9664; LEFT</span>\";";
    html += "if(s.right===1)mt+=\"<span class='motion-tag tag-down'>&#9654; RIGHT</span>\";";
    html += "if(!s.up&&!s.down&&!s.left&&!s.right)mt+=\"<span class='motion-tag tag-idle'>No Active Motion</span>\";";
    html += "ms.innerHTML=mt;}}";
    html += "if(typeof __stopTimers==='function')__stopTimers();";
    html += "__pollTimer=setInterval(function(){";
    // A poll whose connection quietly dies mid-flight (WiFi hiccup, weak
    // signal) but is never aborted by the browser leaves the ESP32 no
    // clean TCP close to notice either — it just sits there as a zombie
    // socket, one of the ESP32's very few, until the server-side detection
    // eventually times it out (up to ~10s). Aborting client-side well
    // before the next poll fires means the browser sends a real reset
    // instead, so the ESP32 can free that socket immediately rather than
    // accumulating stale connections in the background every 3 seconds —
    // exactly the kind of buildup that leaves a *later*, unrelated page
    // navigation stuck waiting behind them.
    html += "var __pc=new AbortController();";
    html += "var __pt=setTimeout(function(){__pc.abort();},2500);";
    html += "fetch('/motion/status',{cache:'no-store',signal:__pc.signal}).then(function(r){clearTimeout(__pt);return r.json();})";
    html += ".then(function(s){updateHomeUI(s);}).catch(function(){clearTimeout(__pt);});";
    html += "},3000);";
    html += "</script>";

    html += "</div>"; // end tab-home
    mayFlush();       // flush home panel
  }

  // ====== USERS PANEL ======
  if (isAdmin && isUsers)
  {
    html += "<div id='tab-users' class='tab-panel active'>";
    html += "<div class='section-title'>&#128100; User Management</div>";
    html += "<div class='section-sub'>List of registered users</div>";

    html += "<div class='table-wrap' style='position:relative;'>";
    // + button pinned to top-right of the table header row
    if (userCount < MAX_USERS)
    {
      html += "<a href='/add' title='Add New User' "
              "style='position:absolute;top:6px;right:8px;z-index:10;"
              "width:30px;height:30px;border-radius:50%;background:rgba(255,255,255,.22);"
              "color:#fff;display:flex;align-items:center;justify-content:center;"
              "font-size:20px;font-weight:700;text-decoration:none;line-height:1;"
              "border:1.5px solid rgba(255,255,255,.45);transition:background .2s;'"
              " onmouseover=\"this.style.background='rgba(255,255,255,.38)'\""
              " onmouseout=\"this.style.background='rgba(255,255,255,.22)'\""
              ">&#43;</a>";
    }
    html += "<table><thead><tr>"
            "<th width='36'>#</th><th>Name</th><th>Email</th><th>Role</th><th>Access</th><th>Actions</th>"
            "</tr></thead><tbody>";
    for (int i = 0; i < userCount; i++)
    {
      html += "<tr><td>" + String(i + 1) + "</td>";
      html += "<td>" + String(users[i].name) + "</td>";
      html += "<td>" + String(users[i].email) + "</td>";
      html += "<td><span class='badge'>" + String(users[i].role) + "</span></td>";
      html += "<td>" + accessLabel(users[i]) + "</td>";
      html += "<td>";
      if (isSuper || String(users[i].role) != "Admin")
      {
        html += "<a href='/edit?idx=" + String(i) + "' class='btn btn-edit'>&#9998; Edit</a>&nbsp;";
        html += "<a href='/confirm-delete?idx=" + String(i) + "' class='btn btn-danger'>Delete</a>&nbsp;";
        html += "<a href='/login-as?idx=" + String(i) + "' class='btn btn-outline' title='Login as this user'>&#128100; Login As</a>";
      }
      else
      {
        html += "<span style='color:#94A3B8;font-size:13px;'>Super Admin only</span>";
      }
      html += "</td></tr>";
    }
    if (userCount == 0)
    {
      html += "<tr><td colspan='6' style='text-align:center;color:#94A3B8;padding:20px;'>"
              "No users yet. Press &#43; to add one.</td></tr>";
    }
    html += "</tbody></table>";
    html += "</div>"; // end table-wrap
    html += "<div style='margin-bottom:20px;'><span class='badge'>&#128100; " + String(userCount) + " / " + String(MAX_USERS) + " users</span></div>";

    html += "</div>"; // end tab-users
  } // end if(isAdmin) users panel
  mayFlush(); // flush users panel

  // ====== DEVICES PANEL ======
  if (isAdmin && isDevices)
  {
    html += "<div id='tab-devices' class='tab-panel active'>";
    html += "<div class='section-title'>&#128241; Device Registry</div>";
    html += "<div class='section-sub'>Registered mobile devices (max " + String(MAX_DEVICES) + ")</div>";

    html += "<div class='table-wrap' style='position:relative;'>";
    if (deviceCount < MAX_DEVICES)
    {
      html += "<form method='POST' action='/devices' style='position:absolute;top:6px;right:8px;z-index:10;'>";
      html += "<input type='text' name='id' placeholder='Device ID' required maxlength='40' style='padding:6px;border-radius:7px;border:1px solid #E2E8F0;margin-right:6px;'>";
      html += "<input type='text' name='owner' placeholder='Owner email (optional)' maxlength='64' style='padding:6px;border-radius:7px;border:1px solid #E2E8F0;margin-right:6px;'>";
      html += "<button type='submit' class='btn btn-primary' style='padding:6px 10px;font-size:13px;'>Add</button>";
      html += "</form>";
    }
    html += "<table><thead><tr><th width='36'>#</th><th>Device ID</th><th>Owner</th><th>Actions</th></tr></thead><tbody>";
    for (int i = 0; i < deviceCount; i++)
    {
      html += "<tr><td>" + String(i + 1) + "</td>";
      html += "<td>" + String(devices[i].id) + "</td>";
      html += "<td>" + String(devices[i].owner) + "</td>";
      html += "<td>";
      html += "<form method='POST' action='/devices/delete' style='display:inline-block;margin:0;padding:0;'>";
      html += "<input type='hidden' name='idx' value='" + String(i) + "'>";
      html += "<button type='submit' class='btn btn-danger'>Delete</button>";
      html += "</form>";
      html += "</td></tr>";
    }
    if (deviceCount == 0)
    {
      html += "<tr><td colspan='4' style='text-align:center;color:#94A3B8;padding:20px;'>No devices registered.</td></tr>";
    }
    html += "</tbody></table>";
    html += "</div>"; // end table-wrap
    html += "</div>"; // end tab-devices
  }
  mayFlush();

  // ====== OTA FIRMWARE UPDATE PANEL ======
  if (isAdmin && isOta)
  {
    html += "<div id='tab-ota' class='tab-panel active'>";
    html += "<div class='section-title'>&#128260; Firmware Update</div>";
    html += "<div class='section-sub'>Upload a new firmware (.bin) image to update this device over the network.</div>";
    html += "<div class='card'>";
    html += "<div class='form-group'><label>Current firmware version</label><div><strong>" FIRMWARE_VERSION "</strong></div></div>";
    html += "<div class='alert alert-danger' style='margin-bottom:16px;'>&#9888; All outputs (including any active hoist/motion output) will be forced OFF and E-STOP latched the instant the upload starts. The device will restart automatically once the update finishes. Do not close this page, remove power, or leave the machine unattended until it reconnects.</div>";
    html += "<form id='ota-form' method='POST' action='/ota' enctype='multipart/form-data'>";
    html += "<div class='form-group'><label>Firmware file (.bin)</label>";
    html += "<input type='file' name='firmware' accept='.bin' required></div>";
    html += "<div class='form-group' style='margin-top:12px;'><label style='display:flex;align-items:center;gap:8px;font-weight:400;'>";
    html += "<input type='checkbox' id='ota-confirm' required style='width:auto;'> I understand outputs will be forced OFF and the device will restart.";
    html += "</label></div>";
    html += "<div class='form-actions' style='margin-top:18px;'>";
    html += "<button type='submit' id='ota-submit' class='btn btn-primary'>&#11014; Upload &amp; Update</button>";
    html += "</div>";
    html += "<div id='ota-status' style='margin-top:14px;'></div>";
    html += "</form>";
    html += "</div>"; // end card
    html += "<script>";
    html += "(function(){";
    html += "var f=document.getElementById('ota-form');";
    html += "if(!f)return;";
    html += "f.addEventListener('submit',function(){";
    html += "document.getElementById('ota-submit').disabled=true;";
    html += "document.getElementById('ota-status').innerHTML=\"<div class='alert alert-info'>Uploading firmware — this can take a minute, please wait...</div>\";";
    html += "});";
    html += "})();";
    html += "</script>";
    html += "</div>"; // end tab-ota
  }
  mayFlush();

  // ====== FILES PANEL (SD card) ======
  if (isAdmin && isFiles)
  {
    html += "<div id='tab-files' class='tab-panel active'>";
    html += "<div class='section-title'>&#128193; Files</div>";
    html += "<div class='section-sub'>Files on the SD card. Event logs are saved one file per month (events_YYYY-MM.log).</div>";

    // Create-new-file form
    html += "<div class='card' style='margin-bottom:16px;'>";
    html += "<form method='POST' action='/files/new' style='display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0;'>";
    html += "<input type='text' name='name' placeholder='New file name, e.g. notes.txt' required maxlength='60' "
            "style='flex:1;min-width:220px;padding:9px 12px;border:1px solid #E2E8F0;border-radius:7px;'>";
    html += "<button type='submit' class='btn btn-primary'>&#43; Create File</button>";
    html += "</form></div>";
    mayFlush();

    File root;
    if (!sdOpen("/", FILE_READ, root) || !root.isDirectory())
    {
      html += "<div class='alert alert-danger'>&#9888; SD card not available. Check that the card is inserted.</div>";
    }
    else
    {
      html += "<div class='table-wrap'><table><thead><tr>"
              "<th width='36'>#</th><th>File name</th><th>Size</th><th>Entries</th><th>Actions</th>"
              "</tr></thead><tbody>";
      unsigned long countDeadline = millis() + 2500; // total time allowed for line counting
      int rows = 0;
      File e = root.openNextFile();
      while (e && rows < 100 && !clientDead)
      {
        if (!e.isDirectory())
        {
          String nm = e.name();
          int sl = nm.lastIndexOf('/');
          if (sl >= 0)
            nm = nm.substring(sl + 1);
          long entries = countEntries(e, countDeadline);
          rows++;
          html += "<tr><td>" + String(rows) + "</td>";
          html += "<td>" + htmlEsc(nm) + "</td>";
          html += "<td>" + formatSize(e.size()) + "</td>";
          html += "<td>" + (entries >= 0 ? String(entries) : String("&mdash;")) + "</td>";
          html += "<td>";
          if (validSdName(nm))
          {
            String q = urlEnc(nm);
            html += "<a href='/files/download?name=" + q + "' class='btn btn-outline'>&#11015; Download</a>&nbsp;";
            html += "<a href='/files/edit?name=" + q + "' class='btn btn-edit'>&#9998; View / Edit</a>&nbsp;";
            html += "<a href='/files/confirm-delete?name=" + q + "' class='btn btn-danger'>Delete</a>";
          }
          else
          {
            html += "<span style='color:#94A3B8;'>unsupported name</span>";
          }
          html += "</td></tr>";
          mayFlush();
        }
        e.close();
        e = root.openNextFile();
      }
      if (e)
        e.close();
      root.close();
      if (rows == 0)
      {
        html += "<tr><td colspan='5' style='text-align:center;color:#94A3B8;padding:20px;'>No files on the SD card yet.</td></tr>";
      }
      html += "</tbody></table></div>";
    }
    html += "</div>"; // end tab-files
  }
  mayFlush();

  // ====== OUTPUT CONFIG PANEL ======
  if ((isAdmin || isOperator) && isOutConfig)
  {
    bool savedOk = webServer.hasArg("saved");
    bool dupErr = webServer.hasArg("err") && webServer.arg("err") == "dup";
    html += "<div id='tab-outconfig' class='tab-panel active'>";
    html += "<div class='section-title'>&#9881; Output Configuration</div>";
    html += "<div class='section-sub'>Assign each physical output pin to a DF function and choose the motion for that pin.</div>";
    if (savedOk)
    {
      html += "<div class='alert alert-info'>&#10003; Configuration saved successfully.</div>";
    }
    if (dupErr)
    {
      html += "<div class='alert alert-danger'>&#9888; Save failed: each output must have a unique function and motion.</div>";
    }
    html += "<form id='oc-form' method='POST' action='/outconfig'>";
    html += "<div class='card' style='padding:0;overflow:hidden;'>";
    html += "<table>";
    html += "<thead><tr><th>Physical Pin</th><th>Digital Function</th><th>Motion</th></tr></thead>";
    html += "<tbody>";

    // Build one select dropdown row for each physical output pin
    for (int p = 0; p < NUM_OUTPUT_PINS; p++)
    {
      uint8_t currentFunction = pinMotionConfig[p].function;
      uint8_t currentMotion = pinMotionConfig[p].motion;
      html += "<tr class='oc-row'>";
      html += "<td class='oc-pin'>" + String(OUTPUT_PINS[p].label) + "</td>";
      html += "<td><select name='pin_" + String(p) + "_function' class='oc-select'>";
      for (int f = 0; f < NUM_OUTPUT_PINS; f++)
      {
        html += "<option value='" + String(f) + "'" + String(currentFunction == f ? " selected" : "") + ">" + String(OUTPUT_FUNCTIONS[f]) + "</option>";
      }
      html += "</select></td>";
      html += "<td><select name='pin_" + String(p) + "_motion' class='oc-select'>";
      html += "<option value='0'" + String(currentMotion == MOTION_NONE ? " selected" : "") + ">";
      html += "&#8212; None &#8212;</option>";
      uint8_t motions[] = {MOTION_ESTOP, MOTION_UP, MOTION_DOWN, MOTION_LEFT, MOTION_RIGHT};
      for (int m = 0; m < 5; m++)
      {
        uint8_t motionId = motions[m];
        html += "<option value='" + String(motionId) + "'" + String(currentMotion == motionId ? " selected" : "") + ">" + String(getMotionLabel(motionId)) + "</option>";
      }
      html += "</select></td></tr>";
    }

    html += "</tbody></table>";
    html += "</div>"; // end card
    html += "<div id='oc-save-msg' class='alert alert-info' style='display:none;margin-top:14px;'></div>";
    html += "<div class='form-actions' style='margin-top:18px;'>";
    html += "<button id='oc-save-btn' type='submit' class='btn btn-primary'>&#10003; Save Configuration</button>";
    html += "</div>";
    html += "</form>";

    // Output config save without full page reload — travels with this
    // panel's own markup (moved here from the old shared bottom script) so
    // it works both on a full page load and as an AJAX fragment swap.
    html += "<script>";
    html += "(function(){";
    html += "var f=document.getElementById('oc-form');if(!f)return;";
    html += "var b=document.getElementById('oc-save-btn');";
    html += "var m=document.getElementById('oc-save-msg');";
    html += "function setMsg(ok,msg){if(!m)return;m.style.display='block';m.className='alert '+(ok?'alert-info':'alert-danger');m.textContent=msg;}";
    html += "f.addEventListener('submit',function(e){e.preventDefault();";
    html += "var functions=[];";
    html += "var motions=[];";
    html += "for(var p=0;p<" + String(NUM_OUTPUT_PINS) + ";p++){";
    html += "var fsel=f.elements['pin_'+p+'_function']; if(fsel){functions.push(fsel.value);}";
    html += "var msel=f.elements['pin_'+p+'_motion']; if(msel){motions.push(msel.value);}";
    html += "}";
    html += "var noneVal='0';";
    html += "var funcSeen={};";
    html += "for(var i=0;i<functions.length;i++){";
    html += "if(funcSeen[functions[i]]){setMsg(false,'Save failed: each output must have a unique digital function.');return;}";
    html += "funcSeen[functions[i]]=true;}";
    html += "var motSeen={};";
    html += "for(var i=0;i<motions.length;i++){";
    html += "if(motions[i]!==noneVal){";
    html += "if(motSeen[motions[i]]){setMsg(false,'Save failed: two outputs cannot be assigned the same motion.');return;}";
    html += "motSeen[motions[i]]=true;}";
    html += "}";
    html += "if(b)b.disabled=true;";
    html += "var body=new URLSearchParams(new FormData(f)).toString();";
    html += "fetch('/outconfig',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'fetch'},body:body})";
    html += ".then(function(r){return r.json().then(function(j){return {ok:r.ok,body:j};});})";
    html += ".then(function(x){";
    html += "if(!x.ok||!x.body||!x.body.ok)throw new Error((x.body&&x.body.msg)?x.body.msg:'Save failed. Please try again.');";
    html += "setMsg(true,'Configuration saved successfully.');";
    html += "})";
    html += ".catch(function(err){setMsg(false,(err&&err.message)?err.message:'Save failed. Please try again.');})";
    html += ".finally(function(){if(b)b.disabled=false;});";
    html += "});";
    html += "})();";
    html += "</script>";

    html += "</div>"; // end tab-outconfig
    mayFlush();       // flush outconfig panel
  }

  // ====== NETWORK SETTINGS PANEL ======
  if ((isAdmin || isOperator) && isNetwork)
  {
    bool savedOk = webServer.hasArg("saved");
    html += "<div id='tab-network' class='tab-panel active'>";
    html += "<div class='section-title'>&#128246; Network Settings</div>";
    html += "<div class='section-sub'>Configure BLE name, WiFi SSID and password.</div>";
    if (savedOk)
    {
      html += "<div class='alert alert-info'>&#10003; Network settings saved. Restarting device...</div>";
    }
    html += "<form id='net-form' method='POST' action='/netconfig'>";
    html += "<div class='card' style='padding:0;overflow:hidden;'>";
    html += "<div style='padding:18px;'>";
    html += "<div class='form-group'><label>BLE Device Name</label>";
    html += "<input type='text' name='ble_name' value='" + String(bleName) + "' placeholder='RRC_' minlength='5' maxlength='10' required pattern='RRC_.{1,6}'>";
    html += "</div>";
    html += "<div class='form-group'><label>WiFi SSID</label>";
    html += "<input type='text' name='wifi_ssid' value='" + String(wifiSsid) + "' minlength='5' maxlength='10' required>";
    html += "</div>";
    html += "<div class='form-group'><label>WiFi Password</label>";
    html += "<input id='wifi-password' type='password' name='wifi_password' value='" + String(wifiPassword) + "' minlength='8' maxlength='10' required>";
    html += "<div style=\"margin-top:8px;display:flex;align-items:center;gap:8px;font-size:14px;color:#1E293B;\">";
    html += "<input id='toggle-wifi-password' type='checkbox' onchange='toggleWifiPassword()'>";
    html += "<label for='toggle-wifi-password' style='margin:0;cursor:pointer;'>Show password</label>";
    html += "</div>";
    html += "</div>";
    html += "<div style='font-size:13px;color:#64748B;margin-bottom:12px;'>The device will restart automatically after saving new BLE or WiFi credentials.</div>";
    html += "</div>";
    html += "</div>"; // end card
    html += "<div class='form-actions' style='margin-top:18px;'>";
    html += "<button id='net-save-btn' type='submit' class='btn btn-primary'>&#10003; Save Network Settings</button>";
    html += "</div>";
    html += "</form>";

    // Moved here from the old shared bottom script so it travels with this
    // panel's own markup, working both on a full page load and as an AJAX
    // fragment swap.
    html += "<script>";
    html += "function toggleWifiPassword(){";
    html += "var pw=document.getElementById('wifi-password');";
    html += "if(!pw)return;";
    html += "pw.type = (pw.type === 'password' ? 'text' : 'password');";
    html += "}";
    html += "</script>";

    html += "</div>"; // end tab-network
    mayFlush();
  }

  // ====== TIME & DATE PANEL ======
  if ((isAdmin || isOperator) && isTime)
  {
    bool savedOk = webServer.hasArg("saved");
    html += "<div id='tab-time' class='tab-panel active'>";
    html += "<div class='section-title'>&#128337; Time &amp; Date</div>";
    html += "<div class='section-sub'>View and correct the device's real-time clock, used to timestamp SD card event logs.</div>";
    if (savedOk)
    {
      html += "<div class='alert alert-info'>&#10003; Device time updated.</div>";
    }
    if (!rtcOk)
    {
      html += "<div class='alert alert-danger'>&#9888; RTC hardware not detected — event log entries will show N/A for timestamp until this is resolved.</div>";
    }
    html += "<div class='card' style='padding:18px;margin-bottom:18px;'>";
    html += "<div class='form-group'><label>Current Device Time</label>";
    html += "<div style='font-size:20px;font-weight:600;'>" + currentTimestamp() + "</div>";
    html += "</div>";
    html += "</div>";
    if (rtcOk)
    {
      String isoNow = currentTimestamp();
      isoNow.replace(" ", "T");
      html += "<form id='time-form' method='POST' action='/timeconfig'>";
      html += "<div class='card' style='padding:18px;'>";
      html += "<div class='form-group'><label>Set New Date &amp; Time</label>";
      html += "<input type='datetime-local' name='device_time' step='1' value='" + isoNow + "' required>";
      html += "</div>";
      html += "</div>";
      html += "<div class='form-actions' style='margin-top:18px;'>";
      html += "<button type='submit' class='btn btn-primary'>&#10003; Set Device Time</button>";
      html += "</div>";
      html += "</form>";
    }
    html += "</div>"; // end tab-time
    mayFlush();
  }

  // ====== INPUT CONFIGURATION PANEL ======
  if ((isAdmin || isOperator) && isInConfig)
  {
    bool savedOk = webServer.hasArg("saved");
    html += "<div id='tab-inconfig' class='tab-panel active'>";
    html += "<div class='section-title'>&#128225; Input Configuration</div>";
    html += "<div class='section-sub'>I0.7 and I0.8 share their pin with A0.7/A0.8 — choose digital or analog mode for each, then assign inputs to the configured hoist(s) or the mobile remote control.</div>";
    if (savedOk)
    {
      html += "<div class='alert alert-info'>&#10003; Input configuration saved.</div>";
    }
    html += "<script>function icOnRemoteChange(sel){if(sel.value=='1'){var all=document.querySelectorAll(\"select[name$='_remote']\");for(var i=0;i<all.length;i++){if(all[i]!==sel)all[i].value='0';}}}</script>";
    html += "<form method='POST' action='/inconfig'>";
    html += "<div class='card' style='padding:0;overflow:hidden;'>";
    html += "<table>";
    html += "<thead><tr><th>Input</th><th>Mode</th><th>Assign</th></tr></thead><tbody>";
    for (int i = 0; i < NUM_INPUT_PINS; i++)
    {
      html += "<tr class='oc-row'>";
      html += "<td class='oc-pin'>" + String(INPUT_PINS[i].label) + "</td>";
      html += "<td>";
      if (INPUT_PINS[i].switchable)
      {
        html += "<select name='in_" + String(i) + "_mode' class='oc-select'>";
        html += "<option value='0'" + String(inputMode[i] == INPUT_MODE_DIGITAL ? " selected" : "") + ">Digital (" + String(INPUT_PINS[i].label) + ")</option>";
        html += "<option value='1'" + String(inputMode[i] == INPUT_MODE_ANALOG ? " selected" : "") + ">Analog (" + String(INPUT_PINS[i].analogLabel) + ")</option>";
        html += "</select>";
      }
      else
      {
        html += "<span class='badge'>Digital</span>";
      }
      html += "</td>";
      html += "<td>";
      html += "<select name='in_" + String(i) + "_remote' class='oc-select' onchange='icOnRemoteChange(this)'>";
      html += "<option value='0'" + String(remoteInputIdx == i ? "" : " selected") + ">None</option>";
      html += "<option value='1'" + String(remoteInputIdx == i ? " selected" : "") + ">Remote Control</option>";
      html += "</select>";
      html += "</td></tr>";
    }
    html += "</tbody></table>";
    html += "</div>"; // end card

    bool wantHoist1 = (hoistConfig == HOIST_ONE || hoistConfig == HOIST_BOTH);
    bool wantHoist2 = (hoistConfig == HOIST_TWO || hoistConfig == HOIST_BOTH);
    if (wantHoist1 || wantHoist2)
    {
      html += "<div class='card' style='margin-top:20px;'>";
      html += "<div class='section-title' style='font-size:17px;'>Hoist Input Mapping</div>";
      if (wantHoist1)
      {
        html += "<div class='form-group'><label>Hoist 1 Input</label>";
        html += "<select name='hoist1_input' class='oc-select'>";
        html += "<option value='-1'" + String(hoistOneInputIdx == -1 ? " selected" : "") + ">&#8212; None &#8212;</option>";
        for (int i = 0; i < NUM_INPUT_PINS; i++)
        {
          if (!INPUT_PINS[i].switchable) continue;
          html += "<option value='" + String(i) + "'" + String(hoistOneInputIdx == i ? " selected" : "") + ">" + String(getInputLabel(i)) + "</option>";
        }
        html += "</select></div>";
      }
      if (wantHoist2)
      {
        html += "<div class='form-group'><label>Hoist 2 Input</label>";
        html += "<select name='hoist2_input' class='oc-select'>";
        html += "<option value='-1'" + String(hoistTwoInputIdx == -1 ? " selected" : "") + ">&#8212; None &#8212;</option>";
        for (int i = 0; i < NUM_INPUT_PINS; i++)
        {
          if (!INPUT_PINS[i].switchable) continue;
          html += "<option value='" + String(i) + "'" + String(hoistTwoInputIdx == i ? " selected" : "") + ">" + String(getInputLabel(i)) + "</option>";
        }
        html += "</select></div>";
      }
      html += "</div>";
    }
    else
    {
      html += "<div class='alert alert-info' style='margin-top:20px;'>No hoist configured.</div>";
    }

    html += "<div class='form-actions' style='margin-top:18px;'>";
    html += "<button type='submit' class='btn btn-primary'>&#10003; Save Input Configuration</button>";
    html += "</div>";
    html += "</form>";
    html += "</div>"; // end tab-inconfig
    mayFlush();
  }

  if (!fragMode)
  {
  html += "</div>"; // end main-content
  html += "</div>"; // end layout
  html += "</body></html>";
  }
  flush();                   // send final chunk and close chunked response
  // Same dead-client guard as flush() above — a zero-length chunk write
  // to an already-gone (or just-detected-and-closed) client would
  // otherwise pay the same retry cost.
  if (!clientDead && webServer.client().connected())
    webServer.sendContent(""); // zero-length chunk = end of chunked transfer
}

// ============================================================
//  Add User
// ============================================================
static void handleAddGet()
{
  if (!webAuthAdmin())
    return;
  if (userCount >= MAX_USERS)
  {
    sendSafe(200, "text/html",
                   pageHead("Add User", "Max users reached") +
                       "<div class='card'><div class='alert alert-info'>Maximum users reached (" +
                       String(MAX_USERS) + ").</div>"
                                           "<a href='/?tab=users' class='btn btn-cancel'>&#8592; Back</a></div>" +
                       pageFoot());
    return;
  }
  String html = pageHead("Add User", "Create a new BLE login credential");
  html += "<div class='card'>";
  html += "<form method='POST' action='/add'>";
  html += "<div class='form-group'><label>Full Name</label>";
  html += "<input type='text' name='name' placeholder='e.g. John Smith' required autofocus></div>";
  html += "<div class='form-group'><label>Email Address</label>";
  html += "<input type='email' name='email' placeholder='user@example.com' required></div>";
  html += "<div class='form-group'><label>Password</label>";
  html += "<input type='password' name='password' placeholder='Minimum 6 characters' "
          "required minlength='6'></div>";
  html += "<div class='form-group'><label>Role</label>";
  html += "<select name='role' style='width:100%;padding:9px 12px;border:1px solid #E2E8F0;"
          "border-radius:7px;font-size:14.5px;color:#1E293B;outline:none;background:#fff;'>";
  html += "<option value='Operator'>Operator</option>";
  if (currentRole() == "SuperAdmin") // only the Super Admin may create Admins
    html += "<option value='Admin'>Admin</option>";
  html += "</select></div>";
  html += accessFormFields(nullptr);
  html += "<div class='form-actions'>";
  html += "<button type='submit' class='btn btn-primary'>&#10003; Add User</button>";
  html += "<a href='/?tab=users' class='btn btn-cancel'>&#8592; Cancel</a>";
  html += "</div></form></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleAddPost()
{
  Serial.printf("Web: POST /add — accessType='%s' from='%s' to='%s'\n",
                webServer.arg("accessType").c_str(), webServer.arg("fromTime").c_str(), webServer.arg("toTime").c_str());
  if (!webAuthAdmin())
  {
    Serial.println("Web: POST /add rejected — not an authenticated admin session");
    return;
  }
  if (userCount >= MAX_USERS)
  {
    sendSafe(400, "text/html", errorPage("Max users reached.", "/"));
    return;
  }
  String name = webServer.arg("name");
  String email = webServer.arg("email");
  String password = webServer.arg("password");
  String role = webServer.arg("role");
  if (name.length() == 0 || email.length() == 0 || password.length() == 0)
  {
    sendSafe(400, "text/html", errorPage("Name, email and password are required.", "/add"));
    return;
  }
  if (role != "Admin" && role != "Operator")
    role = "Operator";
  if (role == "Admin" && currentRole() != "SuperAdmin")
  {
    sendSafe(403, "text/html", errorPage("Only the Super Admin can add Admin accounts.", "/add"));
    return;
  }
  for (int i = 0; i < userCount; i++)
  {
    if (email.equalsIgnoreCase(users[i].email))
    {
      sendSafe(400, "text/html", errorPage("Email already exists.", "/add"));
      return;
    }
  }
  User newUser = {};
  String accessErr = readAccessFromForm(newUser);
  if (accessErr.length() > 0)
  {
    Serial.printf("Web: POST /add rejected — %s\n", accessErr.c_str());
    sendSafe(400, "text/html", errorPage(accessErr, "/add"));
    return;
  }
  name.toCharArray(users[userCount].name, sizeof(users[userCount].name));
  email.toCharArray(users[userCount].email, sizeof(users[userCount].email));
  password.toCharArray(users[userCount].password, sizeof(users[userCount].password));
  role.toCharArray(users[userCount].role, sizeof(users[userCount].role));
  users[userCount].accessType = newUser.accessType;
  users[userCount].startTs = newUser.startTs;
  users[userCount].endTs = newUser.endTs;
  userCount++;
  Serial.println("Web: saving users to NVS...");
  if (!saveUsers())
  {
    userCount--; // roll back: the new user could not be stored persistently
    sendSafe(500, "text/html", errorPage("Could not save the user to device storage (storage full?). The user was not added.", "/?tab=users"));
    return;
  }
  Serial.printf("Web: user added — %s (%s)\n", users[userCount - 1].email,
                users[userCount - 1].accessType == ACCESS_TIMED ? "timed" : "perpetual");
  webServer.sendHeader("Location", "/?tab=users");
  sendSafe(303);
}

// ============================================================
//  Devices POST — add new device (Admin only)
// ============================================================
static void handleDevicesPost()
{
  if (!webAuthAdmin())
    return;
  String id = webServer.arg("id");
  String owner = webServer.arg("owner");
  id.trim();
  owner.trim();
  if (id.length() == 0 || id.length() > 40)
  {
    sendSafe(400, "text/html", errorPage("Device ID required and must be 1-40 characters.", "/?tab=devices"));
    return;
  }
  // prevent duplicate
  for (int i = 0; i < deviceCount; i++)
  {
    if (id == String(devices[i].id))
    {
      sendSafe(400, "text/html", errorPage("Device ID already registered.", "/?tab=devices"));
      return;
    }
  }
  // add
  if (deviceCount >= MAX_DEVICES)
  {
    sendSafe(400, "text/html", errorPage("Device registry full.", "/?tab=devices"));
    return;
  }
  id.toCharArray(devices[deviceCount].id, sizeof(devices[deviceCount].id));
  owner.toCharArray(devices[deviceCount].owner, sizeof(devices[deviceCount].owner));
  deviceCount++;
  saveDevices();
  webServer.sendHeader("Location", "/?tab=devices");
  sendSafe(303);
}

// ============================================================
//  Devices DELETE — remove device by index (Admin only)
// ============================================================
static void handleDeleteDevicePost()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= deviceCount)
  {
    sendSafe(404, "text/html", errorPage("Device not found.", "/?tab=devices"));
    return;
  }
  for (int i = idx; i < deviceCount - 1; i++)
  {
    devices[i] = devices[i + 1];
  }
  deviceCount--;
  saveDevices();
  webServer.sendHeader("Location", "/?tab=devices");
  sendSafe(303);
}

// ============================================================
//  OTA Firmware Update  (Admin only)
// ============================================================
// otaAuthorized/otaErrorMsg are set at UPLOAD_FILE_START and checked on
// every subsequent chunk: this is the actual security boundary for the
// upload (it gates every Update.write() call), not just the final
// handler below — webAuthAdmin()'s redirect can't be used mid-upload,
// so authorization here is a plain currentRole() check instead.
static bool   otaAuthorized = false;
static String otaErrorMsg   = "";

static void handleOtaUpload()
{
  HTTPUpload &upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START)
  {
    otaErrorMsg   = "";
    otaAuthorized = isManagerRole(currentRole());
    if (!otaAuthorized)
    {
      otaErrorMsg = "Admin privileges required.";
      return;
    }
    Serial.printf("Web: OTA update starting — file=%s\n", upload.filename.c_str());
    // Safe state before any flash write begins: outputs off, E-STOP
    // latched, same as this device's own boot-time safe state.
    forceAllOutputsOff();
    if (!Update.begin(UPDATE_SIZE_UNKNOWN))
    {
      otaErrorMsg = "Could not start update (image too large for the inactive partition, or update already in progress).";
      Update.printError(Serial);
    }
  }
  else if (upload.status == UPLOAD_FILE_WRITE)
  {
    if (otaAuthorized && otaErrorMsg.length() == 0)
    {
      if (Update.write(upload.buf, upload.currentSize) != upload.currentSize)
      {
        otaErrorMsg = "Write failed mid-upload.";
        Update.printError(Serial);
        Update.abort(); // release the update session now rather than leaving it half-open until END
      }
    }
  }
  else if (upload.status == UPLOAD_FILE_END)
  {
    if (otaAuthorized && otaErrorMsg.length() == 0)
    {
      if (Update.end(true))
      {
        Serial.printf("Web: OTA update received — %u bytes, verifying and rebooting\n", (unsigned)upload.totalSize);
      }
      else
      {
        otaErrorMsg = "Update did not verify (corrupt upload or wrong image type).";
        Update.printError(Serial);
      }
    }
  }
  else if (upload.status == UPLOAD_FILE_ABORTED)
  {
    Update.abort();
    otaErrorMsg = "Upload aborted.";
  }
}

static void handleOtaComplete()
{
  if (!webAuthAdmin())
    return;
  if (!otaAuthorized || otaErrorMsg.length() > 0)
  {
    String msg = otaErrorMsg.length() > 0 ? otaErrorMsg : "Update failed.";
    sendSafe(400, "text/html", errorPage("Update failed: " + msg, "/?tab=ota"));
    return;
  }
  String html = pageHead("Firmware Update", "Update complete");
  html += "<div class='card'>";
  html += "<div class='alert alert-info'>&#10003; Firmware updated successfully. Restarting device...</div>";
  html += "<p>Please wait while the device restarts, then reconnect once it comes back online.</p>";
  html += "</div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
  delay(500);
  ESP.restart();
}

// ============================================================
//  Edit User
// ============================================================
static void handleEditGet()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  String html = pageHead("Edit User", "Update login credentials");
  html += "<div class='card'><form method='POST' action='/edit'>";
  html += "<input type='hidden' name='idx' value='" + String(idx) + "'>";
  html += "<div class='form-group'><label>Full Name</label>"
          "<input type='text' name='name' value='" +
          String(users[idx].name) + "' required></div>";
  html += "<div class='form-group'><label>Email Address</label>"
          "<input type='email' name='email' value='" +
          String(users[idx].email) + "' required></div>";
  html += "<div class='form-group'><label>Password</label>"
          "<input type='text' name='password' value='" +
          String(users[idx].password) + "' minlength='6'></div>";
  html += "<div class='form-group'><label>Role</label>";
  html += "<select name='role' style='width:100%;padding:9px 12px;border:1px solid #E2E8F0;"
          "border-radius:7px;font-size:14.5px;color:#1E293B;outline:none;background:#fff;'>";
  const char *roles[] = {"Operator", "Admin"};
  int roleCount = (currentRole() == "SuperAdmin") ? 2 : 1; // Admins can only assign Operator
  for (int r = 0; r < roleCount; r++)
  {
    html += "<option value='" + String(roles[r]) + "'";
    if (String(users[idx].role) == roles[r])
      html += " selected";
    html += ">" + String(roles[r]) + "</option>";
  }
  html += "</select></div>";
  html += accessFormFields(&users[idx]);
  html += "<div class='form-actions'>";
  html += "<button type='submit' class='btn btn-primary'>&#10003; Save Changes</button>";
  html += "<a href='/?tab=users' class='btn btn-cancel'>Cancel</a>";
  html += "</div></form></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleEditPost()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  String name = webServer.arg("name");
  String email = webServer.arg("email");
  String password = webServer.arg("password");
  String role = webServer.arg("role");
  if (role == "Admin" && currentRole() != "SuperAdmin")
  {
    sendSafe(403, "text/html", errorPage("Only the Super Admin can assign the Admin role.", "/?tab=users"));
    return;
  }
  if (name.length() == 0 || email.length() == 0)
  {
    sendSafe(400, "text/html", errorPage("Name and email are required.", "/"));
    return;
  }
  if (role != "Admin" && role != "Operator")
    role = "Operator";
  for (int i = 0; i < userCount; i++)
  {
    if (i != idx && email.equalsIgnoreCase(users[i].email))
    {
      sendSafe(400, "text/html", errorPage("Email already in use by another user.", "/"));
      return;
    }
  }
  User newAccess = {};
  String accessErr = readAccessFromForm(newAccess);
  if (accessErr.length() > 0)
  {
    sendSafe(400, "text/html", errorPage(accessErr, ("/edit?idx=" + String(idx)).c_str()));
    return;
  }
  name.toCharArray(users[idx].name, sizeof(users[idx].name));
  email.toCharArray(users[idx].email, sizeof(users[idx].email));
  role.toCharArray(users[idx].role, sizeof(users[idx].role));
  users[idx].accessType = newAccess.accessType;
  users[idx].startTs = newAccess.startTs;
  users[idx].endTs = newAccess.endTs;
  if (password.length() > 0)
  {
    password.toCharArray(users[idx].password, sizeof(users[idx].password));
  }
  saveUsers();
  Serial.printf("Web: user edited — %s\n", users[idx].email);
  webServer.sendHeader("Location", "/?tab=users");
  sendSafe(303);
}

// ============================================================
//  Delete User
// ============================================================
static void handleConfirmDelete()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  String html = pageHead("Delete User", "This action cannot be undone");
  html += "<div class='card'><div class='del-box'>";
  html += "<div class='del-icon'>&#128465;</div>";
  html += "<p class='del-msg'>Are you sure you want to delete</p>";
  html += "<p class='del-email'>" + String(users[idx].email) + "</p>";
  html += "<form method='POST' action='/delete'>";
  html += "<input type='hidden' name='idx' value='" + String(idx) + "'>";
  html += "<div class='del-btns'>";
  html += "<button type='submit' class='btn btn-danger'>Yes, Delete</button>";
  html += "<a href='/?tab=users' class='btn btn-cancel'>Cancel</a>";
  html += "</div></form></div></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleDeletePost()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  Serial.printf("Web: user deleted — %s\n", users[idx].email);
  for (int i = idx; i < userCount - 1; i++)
  {
    users[i] = users[i + 1];
  }
  userCount--;
  saveUsers();
  webServer.sendHeader("Location", "/?tab=users");
  sendSafe(303);
}

// ============================================================
//  Account GET — dedicated settings page
// ============================================================
static void handleAccountGet()
{
  if (!webAuth())
    return;
  String _se = currentUserEmail();
  bool isBleUser = _se.length() > 0;
  // For BLE users, show their name/email; for web admin show username
  String currentName = isBleUser ? "" : "";
  String currentId = isBleUser ? _se : String(webAdminUser);
  if (isBleUser)
  {
    for (int i = 0; i < userCount; i++)
    {
      if (String(users[i].email).equalsIgnoreCase(_se))
      {
        currentName = String(users[i].name);
        break;
      }
    }
  }
  String subtitle = isBleUser ? "Change your name and password" : "Change your web panel login credentials";
  String html = pageHead("Account Settings", subtitle.c_str());
  html += "<div class='card'>";
  html += "<form method='POST' action='/account'>";
  if (isBleUser)
  {
    html += "<div class='form-group'><label>Full Name</label>";
    html += "<input type='text' name='new_user' value='" + currentName + "' required></div>";
    html += "<div class='form-group'><label>Email</label>";
    html += "<input type='text' value='" + currentId + "' disabled style='width:100%;padding:9px 12px;"
                                                       "border:1px solid #E2E8F0;border-radius:7px;font-size:14.5px;color:#94A3B8;background:#F1F5F9;'></div>";
  }
  else
  {
    html += "<div class='form-group'><label>Email Address</label>";
    html += "<input type='email' name='new_user' value='" + currentId + "' required></div>";
  }
  html += "<div class='form-group'><label>Current Password</label>";
  if (isBleUser)
  {
    for (int _i = 0; _i < userCount; _i++)
    {
      if (String(users[_i].email).equalsIgnoreCase(_se))
      {
        html += "<input type='text' name='cur_pass' value='" + String(users[_i].password) + "' required></div>";
        break;
      }
    }
  }
  else
  {
    html += "<input type='text' name='cur_pass' value='" + String(webAdminPass) + "' required></div>";
  }
  html += "<div class='form-group'><label>New Password</label>";
  html += "<input type='password' name='new_pass' placeholder='Leave blank to keep current'></div>";
  html += "<div class='form-group'><label>Confirm New Password</label>";
  html += "<input type='password' name='cfm_pass' placeholder='Repeat new password'></div>";
  html += "<div class='form-actions'>";
  html += "<button type='submit' class='btn btn-primary'>&#10003; Save Changes</button>";
  html += "<a href='/' class='btn btn-cancel'>&#8592; Back</a>";
  html += "</div></form></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

// ============================================================
//  Account POST — change credentials (web admin or BLE user)
// ============================================================
static void handleAccountPost()
{
  if (!webAuth())
    return;
  String newUser = webServer.arg("new_user");
  String curPass = webServer.arg("cur_pass");
  String newPass = webServer.arg("new_pass");
  String cfmPass = webServer.arg("cfm_pass");
  if (newUser.length() == 0)
  {
    sendSafe(400, "text/html", errorPage("Name/username cannot be empty.", "/account"));
    return;
  }
  String _se2 = currentUserEmail();
  bool isBleUser = _se2.length() > 0;
  if (isBleUser)
  {
    // Find the BLE user by session email
    int idx = -1;
    for (int i = 0; i < userCount; i++)
    {
      if (String(users[i].email).equalsIgnoreCase(_se2))
      {
        idx = i;
        break;
      }
    }
    if (idx < 0)
    {
      sendSafe(404, "text/html", errorPage("User session invalid.", "/account"));
      return;
    }
    if (String(users[idx].password) != curPass)
    {
      sendSafe(401, "text/html", errorPage("Current password is incorrect.", "/account"));
      return;
    }
    if (newPass.length() > 0)
    {
      if (newPass != cfmPass)
      {
        sendSafe(400, "text/html", errorPage("New passwords do not match.", "/account"));
        return;
      }
      if (newPass.length() < 6)
      {
        sendSafe(400, "text/html", errorPage("New password must be at least 6 characters.", "/account"));
        return;
      }
      newPass.toCharArray(users[idx].password, sizeof(users[idx].password));
    }
    newUser.toCharArray(users[idx].name, sizeof(users[idx].name));
    saveUsers();
    Serial.printf("Web: user updated own account — %s\n", users[idx].email);
    webServer.sendHeader("Location", "/");
    sendSafe(303);
  }
  else
  {
    // Web admin credentials
    if (String(webAdminPass) != curPass)
    {
      sendSafe(401, "text/html", errorPage("Current password is incorrect.", "/account"));
      return;
    }
    if (newPass.length() > 0)
    {
      if (newPass != cfmPass)
      {
        sendSafe(400, "text/html", errorPage("New passwords do not match.", "/account"));
        return;
      }
      if (newPass.length() < 6)
      {
        sendSafe(400, "text/html", errorPage("New password must be at least 6 characters.", "/account"));
        return;
      }
      newPass.toCharArray(webAdminPass, sizeof(webAdminPass));
    }
    newUser.toCharArray(webAdminUser, sizeof(webAdminUser));
    saveWebAdmin();
    // Invalidate current session so admin re-logs in with new credentials
    int _si2 = findSessionIdx();
    if (_si2 >= 0)
    {
      sessions[_si2].token = "";
      sessions[_si2].role = "";
      sessions[_si2].userEmail = "";
    }
    webServer.sendHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
    webServer.sendHeader("Location", "/login");
    sendSafe(303);
  }
}

// ============================================================
//  Login As (Admin only) — switch web session to a BLE user
// ============================================================
static void handleLoginAs()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  int _slot2 = findSessionIdx();
  if (_slot2 < 0)
    _slot2 = allocSessionSlot();
  sessions[_slot2].token = generateToken();
  sessions[_slot2].role = String(users[idx].role);
  sessions[_slot2].userEmail = String(users[idx].email);
  sessions[_slot2].timeExempt = true; // admin impersonation is exempt from the timed-access window
  webServer.sendHeader("Set-Cookie", "session=" + sessions[_slot2].token + "; HttpOnly; Path=/");
  Serial.printf("Web: Admin switched session to user — %s (%s)\n", users[idx].email, users[idx].role);
  webServer.sendHeader("Location", "/");
  sendSafe(303);
}

// ============================================================
//  Network Settings POST — change BLE/WiFi credentials
// ============================================================
static void handleNetConfigPost()
{
  if (!webAuthOutputConfig())
    return;
  String newBleName = webServer.arg("ble_name");
  String newSsid = webServer.arg("wifi_ssid");
  String newPass = webServer.arg("wifi_password");

  newBleName.trim();
  newSsid.trim();
  newPass.trim();

  if (newBleName.length() < 5 || newBleName.length() > 10 || !newBleName.startsWith("RRC_"))
  {
    sendSafe(400, "text/html", errorPage("BLE name must start with RRC_ and be 5-10 characters long.", "/?tab=network"));
    return;
  }
  if (newSsid.length() < 5 || newSsid.length() > 10)
  {
    sendSafe(400, "text/html", errorPage("WiFi SSID must be 5-10 characters long.", "/?tab=network"));
    return;
  }
  if (newPass.length() < 8 || newPass.length() > 10)
  {
    sendSafe(400, "text/html", errorPage("WiFi Password must be 8-10 characters long.", "/?tab=network"));
    return;
  }

  newBleName.toCharArray(bleName, sizeof(bleName));
  newSsid.toCharArray(wifiSsid, sizeof(wifiSsid));
  newPass.toCharArray(wifiPassword, sizeof(wifiPassword));
  saveNetworkConfig();

  String html = pageHead("Network Settings", "BLE and WiFi credentials updated.");
  html += "<div class='card'>";
  html += "<div class='alert alert-info'>&#10003; Saved successfully. Restarting device with new settings...</div>";
  html += "<p>Please wait while the device restarts. Reconnect to the new WiFi SSID and BLE name after reboot.</p>";
  html += "</div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
  delay(500);
  ESP.restart();
}

// ============================================================
//  Time & Date POST — corrects the RTC from the web UI
// ============================================================
static void handleTimeConfigPost()
{
  if (!webAuthOutputConfig())
    return;

  if (!rtcOk)
  {
    sendSafe(400, "text/html", errorPage("RTC hardware not detected — cannot set device time.", "/?tab=time"));
    return;
  }

  // Expect HTML datetime-local format: "YYYY-MM-DDTHH:MM" or "YYYY-MM-DDTHH:MM:SS"
  String dt = webServer.arg("device_time");
  int year, month, day, hour, minute, second = 0;
  int matched = sscanf(dt.c_str(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);
  if (matched < 5 || year < 2000 || year > 2099 || month < 1 || month > 12 || day < 1 || day > 31 ||
      hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59)
  {
    sendSafe(400, "text/html", errorPage("Invalid date/time value.", "/?tab=time"));
    return;
  }

  bool ok = setRtcDateTime(year, month, day, hour, minute, second);
  if (!ok)
  {
    Serial.printf("Web: FAILED to set device time to %04d-%02d-%02d %02d:%02d:%02d — write did not verify\n",
                  year, month, day, hour, minute, second);
    sendSafe(500, "text/html", errorPage(
        "Failed to set device time — the RTC did not accept the write. This usually means a wiring/connection "
        "problem (e.g. missing pull-up resistors on SDA/SCL, or a loose RTC module). Please check the hardware and try again.",
        "/?tab=time"));
    return;
  }
  Serial.printf("Web: device time set to %04d-%02d-%02d %02d:%02d:%02d\n", year, month, day, hour, minute, second);
  webServer.sendHeader("Location", "/?tab=time&saved=1");
  sendSafe(303);
}

// ============================================================
//  Input Configuration POST — I0.7/I0.8 mode + hoist input mapping
// ============================================================
static void handleInConfigPost()
{
  if (!webAuthOutputConfig())
    return;

  for (int i = 0; i < NUM_INPUT_PINS; i++)
  {
    if (!INPUT_PINS[i].switchable)
      continue;
    char paramName[16];
    sprintf(paramName, "in_%d_mode", i);
    int m = webServer.arg(paramName).toInt();
    inputMode[i] = (m == INPUT_MODE_ANALOG) ? INPUT_MODE_ANALOG : INPUT_MODE_DIGITAL;
  }

  bool wantHoist1 = (hoistConfig == HOIST_ONE || hoistConfig == HOIST_BOTH);
  bool wantHoist2 = (hoistConfig == HOIST_TWO || hoistConfig == HOIST_BOTH);

  int8_t newHoist1 = -1;
  int8_t newHoist2 = -1;
  if (wantHoist1)
  {
    int v = webServer.arg("hoist1_input").toInt();
    newHoist1 = (v >= 0 && v < NUM_INPUT_PINS) ? (int8_t)v : -1;
  }
  if (wantHoist2)
  {
    int v = webServer.arg("hoist2_input").toInt();
    newHoist2 = (v >= 0 && v < NUM_INPUT_PINS) ? (int8_t)v : -1;
  }
  hoistOneInputIdx = newHoist1;
  hoistTwoInputIdx = newHoist2;

  int8_t newRemote = -1;
  for (int i = 0; i < NUM_INPUT_PINS; i++)
  {
    char paramName[16];
    sprintf(paramName, "in_%d_remote", i);
    if (webServer.arg(paramName).toInt() == 1)
    {
      newRemote = (int8_t)i;
      break;
    }
  }
  remoteInputIdx = newRemote;

  saveInputConfig();
  Serial.println("Web: input configuration updated");
  webServer.sendHeader("Location", "/?tab=inconfig&saved=1");
  sendSafe(303);
}

// ============================================================
//  Motion Status  —  read-only JSON endpoint
// ============================================================
// ============================================================
//  Output Configuration  (POST /outconfig)
// ============================================================
static void handleOutConfigPost()
{
  if (!webAuthOutputConfig())
    return;
  String reqType = webServer.header("X-Requested-With");

  // Parse function and motion assignments for each physical pin
  uint8_t newPinFunctions[NUM_OUTPUT_PINS];
  uint8_t newPinMotions[NUM_OUTPUT_PINS];
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    char paramName[24];
    sprintf(paramName, "pin_%d_function", p);
    String functionStr = webServer.arg(paramName);
    int functionId = functionStr.toInt();

    sprintf(paramName, "pin_%d_motion", p);
    String motionStr = webServer.arg(paramName);
    int motionId = motionStr.toInt();

    newPinFunctions[p] = (functionId >= 0 && functionId < NUM_OUTPUT_PINS) ? (uint8_t)functionId : (uint8_t)p;
    newPinMotions[p] = (motionId >= MOTION_NONE && motionId <= MOTION_RIGHT) ? (uint8_t)motionId : MOTION_NONE;
  }

  // Validate: each physical pin must have a unique digital function
  for (int p1 = 0; p1 < NUM_OUTPUT_PINS; p1++)
  {
    for (int p2 = p1 + 1; p2 < NUM_OUTPUT_PINS; p2++)
    {
      if (newPinFunctions[p1] == newPinFunctions[p2])
      {
        Serial.println("Out config rejected: duplicate digital function assignment");
        if (reqType == "fetch")
        {
          webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
          sendSafe(400, "application/json", "{\"ok\":0,\"msg\":\"Save failed: each output must have a unique digital function.\"}");
          return;
        }
        webServer.sendHeader("Location", "/?tab=outconfig&err=dup");
        sendSafe(303);
        return;
      }
    }
  }

  // Validate: no two pins can be assigned the same motion (unless it's None)
  for (int p1 = 0; p1 < NUM_OUTPUT_PINS; p1++)
  {
    if (newPinMotions[p1] == MOTION_NONE)
      continue;
    for (int p2 = p1 + 1; p2 < NUM_OUTPUT_PINS; p2++)
    {
      if (newPinMotions[p2] == newPinMotions[p1])
      {
        Serial.println("Out config rejected: duplicate motion assignment");
        if (reqType == "fetch")
        {
          webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
          sendSafe(400, "application/json", "{\"ok\":0,\"msg\":\"Save failed: two outputs cannot be assigned the same motion.\"}");
          return;
        }
        webServer.sendHeader("Location", "/?tab=outconfig&err=dup");
        sendSafe(303);
        return;
      }
    }
  }

  // Apply new configuration
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    pinMotionConfig[p].function = newPinFunctions[p];
    pinMotionConfig[p].motion = newPinMotions[p];
  }
  saveOutputConfig();

  Serial.println("Output config updated:");
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    Serial.printf("  %s (%s) → %s\n", OUTPUT_FUNCTIONS[pinMotionConfig[p].function], OUTPUT_PINS[p].label,
                  getMotionLabel(pinMotionConfig[p].motion));
  }

  if (reqType == "fetch")
  {
    webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    sendSafe(200, "application/json", "{\"ok\":1}");
    return;
  }
  webServer.sendHeader("Location", "/?tab=outconfig&saved=1");
  sendSafe(303);
}

// ============================================================
//  Motion status  (GET /motion/status — JSON, used by home page)
// ============================================================
static void handleMotionStatus()
{
  if (!webAuth())
    return;
  String bleUserName = "";
  if (authenticated && connectedUserEmail[0] != '\0')
  {
    bleUserName = String(connectedUserEmail);
    for (int i = 0; i < userCount; i++)
    {
      if (String(users[i].email).equalsIgnoreCase(connectedUserEmail))
      {
        bleUserName = String(users[i].name);
        break;
      }
    }
    bleUserName.replace("\"", "\\\"");
  }

  // Determine which output pins are active based on pin-motion configuration and current motion states
  int estopOutputOn = 0;
  int upOutputOn = 0;
  int downOutputOn = 0;
  int leftOutputOn = 0;
  int rightOutputOn = 0;

  // Check each pin to see if its assigned motion is active
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    uint8_t motion = pinMotionConfig[p].motion;
    bool isActive = false;

    switch (motion)
    {
    case MOTION_ESTOP:
      isActive = motionEstop;
      // E-STOP output is inverted: LOW = active
      estopOutputOn = isActive ? 0 : 1;
      break;
    case MOTION_UP:
      isActive = motionUp;
      upOutputOn = isActive ? 1 : 0;
      break;
    case MOTION_DOWN:
      isActive = motionDown;
      downOutputOn = isActive ? 1 : 0;
      break;
    case MOTION_LEFT:
      isActive = motionLeft;
      leftOutputOn = isActive ? 1 : 0;
      break;
    case MOTION_RIGHT:
      isActive = motionRight;
      rightOutputOn = isActive ? 1 : 0;
      break;
    default:
      break;
    }
  }

  String json = "{\"estop\":" + String(estopOutputOn) +
                ",\"up\":" + String(upOutputOn) +
                ",\"down\":" + String(downOutputOn) +
                ",\"left\":" + String(leftOutputOn) +
                ",\"right\":" + String(rightOutputOn) +
                ",\"ble_conn\":" + String(deviceConnected ? 1 : 0) +
                ",\"ble_auth\":" + String(authenticated ? 1 : 0) +
                ",\"ble_user\":\"" + bleUserName + "\"}";
  webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  sendSafe(200, "application/json", json);
}

// ============================================================
//  Files (SD card) — download, view/edit, delete, create
// ============================================================
static void handleFileDownload()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  File f;
  if (!validSdName(name) || !sdOpen("/" + name, FILE_READ, f) || f.isDirectory())
  {
    sendSafe(404, "text/html", errorPage("File not found.", "/?tab=files"));
    return;
  }
  // Phone browsers (Android Chrome / iOS Safari) are stricter than desktop ones:
  // give them a real MIME type and ask for a one-shot connection so the
  // download manager doesn't try to reuse/resume it (this server has no Range support).
  String lower = name;
  lower.toLowerCase();
  const char *mime = "application/octet-stream";
  if (lower.endsWith(".csv"))
    mime = "text/csv";
  else if (lower.endsWith(".txt") || lower.endsWith(".log"))
    mime = "text/plain";
  else if (lower.endsWith(".json"))
    mime = "application/json";
  webServer.sendHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
  webServer.sendHeader("Cache-Control", "no-store");
  webServer.sendHeader("Connection", "close");
  webServer.streamFile(f, mime);
  f.close();
}

static void handleFileEditGet()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  File f;
  if (!validSdName(name) || !sdOpen("/" + name, FILE_READ, f) || f.isDirectory())
  {
    sendSafe(404, "text/html", errorPage("File not found.", "/?tab=files"));
    return;
  }
  size_t size = f.size();
  bool editable = size <= FILE_EDIT_MAX_BYTES;
  bool tailOnly = !editable && size > FILE_VIEW_MAX_BYTES;
  if (tailOnly)
  {
    // Show only the last FILE_VIEW_MAX_BYTES bytes, starting at a line boundary.
    f.seek(size - FILE_VIEW_MAX_BYTES);
    int c;
    while ((c = f.read()) >= 0 && c != '\n')
    {
    }
  }

  // Stream the page in chunks: the file's text is never held in RAM whole.
  webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
  sendSafe(200, "text/html", "");
  String head = pageHead("View / Edit File", htmlEsc(name).c_str());
  head += "<div class='card'>";
  head += "<div style='margin-bottom:12px;color:#64748B;'>Size: " + formatSize(size) + "</div>";
  if (editable)
  {
    head += "<form method='POST' action='/files/save'>";
    head += "<input type='hidden' name='name' value='" + htmlEsc(name) + "'>";
  }
  else
  {
    head += "<div class='alert alert-info' style='margin-bottom:12px;'>This file is too large to edit here (limit " +
            formatSize(FILE_EDIT_MAX_BYTES) + ")." +
            (tailOnly ? String(" Showing only the last ") + formatSize(FILE_VIEW_MAX_BYTES) + "." : String("")) +
            " Use Download to get the whole file.</div>";
  }
  head += "<textarea name='content' rows='22' maxlength='" + String(FILE_EDIT_MAX_BYTES) + "' spellcheck='false' " +
          (editable ? "" : "readonly ") +
          "style='width:100%;box-sizing:border-box;font-family:monospace;font-size:13px;padding:10px;"
          "border:1px solid #E2E8F0;border-radius:7px;white-space:pre;overflow:auto;'>\n"; // first newline is ignored by the browser
  webServer.sendContent(head);

  uint8_t buf[512];
  int n;
  while ((n = f.read(buf, sizeof(buf))) > 0)
  {
    String chunk;
    chunk.reserve(n + 32);
    for (int i = 0; i < n; i++)
    {
      char c = (char)buf[i];
      if (c == '&')
        chunk += "&amp;";
      else if (c == '<')
        chunk += "&lt;";
      else if (c == '>')
        chunk += "&gt;";
      else
        chunk += c;
    }
    webServer.sendContent(chunk);
  }
  f.close();

  String tail = "</textarea>";
  tail += "<div class='form-actions' style='margin-top:14px;'>";
  if (editable)
    tail += "<button type='submit' class='btn btn-primary'>&#10003; Save Changes</button>";
  tail += "<a href='/files/download?name=" + urlEnc(name) + "' class='btn btn-outline'>&#11015; Download</a>";
  tail += "<a href='/?tab=files' class='btn btn-cancel'>&#8592; Back</a>";
  tail += "</div>";
  tail += editable ? "</form></div>" : "</div>";
  tail += pageFoot();
  webServer.sendContent(tail);
  webServer.sendContent("");
}

static void handleFileSavePost()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  String content = webServer.arg("content");
  if (!validSdName(name))
  {
    sendSafe(400, "text/html", errorPage("Invalid file name.", "/?tab=files"));
    return;
  }
  if (content.length() > FILE_EDIT_MAX_BYTES)
  {
    sendSafe(400, "text/html", errorPage("Content too large to save (limit " + formatSize(FILE_EDIT_MAX_BYTES) + ").", "/?tab=files"));
    return;
  }
  content.replace("\r", ""); // browsers submit textarea line breaks as CRLF
  File f;
  if (!sdOpen("/" + name, FILE_WRITE, f)) // FILE_WRITE truncates, i.e. replaces the file
  {
    sendSafe(500, "text/html", errorPage("Could not write the file. Check the SD card.", "/?tab=files"));
    return;
  }
  f.print(content);
  f.close();
  Serial.printf("Web: file saved — %s (%u bytes)\n", name.c_str(), (unsigned)content.length());
  webServer.sendHeader("Location", "/?tab=files");
  sendSafe(303);
}

static void handleFileConfirmDelete()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  if (!validSdName(name) || !SD.exists("/" + name))
  {
    sendSafe(404, "text/html", errorPage("File not found.", "/?tab=files"));
    return;
  }
  String html = pageHead("Delete File", "This action cannot be undone");
  html += "<div class='card'><div class='del-box'>";
  html += "<div class='del-icon'>&#128465;</div>";
  html += "<p class='del-msg'>Are you sure you want to delete</p>";
  html += "<p class='del-email'>" + htmlEsc(name) + "</p>";
  html += "<form method='POST' action='/files/delete'>";
  html += "<input type='hidden' name='name' value='" + htmlEsc(name) + "'>";
  html += "<div class='del-btns'>";
  html += "<button type='submit' class='btn btn-danger'>Yes, Delete</button>";
  html += "<a href='/?tab=files' class='btn btn-cancel'>Cancel</a>";
  html += "</div></form></div></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleFileDeletePost()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  if (!validSdName(name) || !SD.remove("/" + name))
  {
    sendSafe(404, "text/html", errorPage("Could not delete the file.", "/?tab=files"));
    return;
  }
  Serial.printf("Web: file deleted — %s\n", name.c_str());
  webServer.sendHeader("Location", "/?tab=files");
  sendSafe(303);
}

static void handleFileNewPost()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  name.trim();
  if (name.indexOf('.') < 0)
    name += ".txt";
  if (!validSdName(name))
  {
    sendSafe(400, "text/html", errorPage("Invalid file name. Use up to 60 characters and avoid / \\ : * ? \" &lt; &gt; |.", "/?tab=files"));
    return;
  }
  if (SD.exists("/" + name))
  {
    sendSafe(400, "text/html", errorPage("A file with that name already exists.", "/?tab=files"));
    return;
  }
  File f;
  if (!sdOpen("/" + name, FILE_WRITE, f))
  {
    sendSafe(500, "text/html", errorPage("Could not create the file. Check the SD card.", "/?tab=files"));
    return;
  }
  f.close();
  Serial.printf("Web: file created — %s\n", name.c_str());
  webServer.sendHeader("Location", "/files/edit?name=" + urlEnc(name));
  sendSafe(303);
}

// ============================================================
//  Static CSS  (GET /style.css — cached by browser for 24 h)
// ============================================================
static void handleStyleCSS()
{
  // Bump the ETag whenever HTML_STYLE changes so browsers drop their cached copy.
  if (webServer.header("If-None-Match") == "\"v3\"")
  {
    webServer.sendHeader("Cache-Control", "public, max-age=86400");
    webServer.sendHeader("ETag", "\"v3\"");
    sendSafe(304);
    return;
  }
  webServer.sendHeader("Cache-Control", "public, max-age=86400");
  webServer.sendHeader("ETag", "\"v3\"");
  sendSafe(200, "text/css", HTML_STYLE);
}

void setupWebRoutes()
{
  loadWebAdmin();
  loadDevices();
  const char *hdrs[] = {"Cookie", "If-None-Match", "X-Requested-With"};
  webServer.collectHeaders(hdrs, 3);
  webServer.on("/style.css", HTTP_GET, handleStyleCSS);
  webServer.on("/login", HTTP_GET, handleLoginGet);
  webServer.on("/login", HTTP_POST, handleLoginPost);
  webServer.on("/logout", HTTP_GET, handleLogout);
  webServer.on("/", HTTP_GET, handleRoot);
  webServer.on("/add", HTTP_GET, handleAddGet);
  webServer.on("/add", HTTP_POST, handleAddPost);
  webServer.on("/edit", HTTP_GET, handleEditGet);
  webServer.on("/edit", HTTP_POST, handleEditPost);
  webServer.on("/confirm-delete", HTTP_GET, handleConfirmDelete);
  webServer.on("/delete", HTTP_POST, handleDeletePost);
  webServer.on("/account", HTTP_GET, handleAccountGet);
  webServer.on("/account", HTTP_POST, handleAccountPost);
  webServer.on("/login-as", HTTP_GET, handleLoginAs);
  webServer.on("/motion/status", HTTP_GET, handleMotionStatus);
  webServer.on("/outconfig", HTTP_POST, handleOutConfigPost);
  webServer.on("/inconfig", HTTP_POST, handleInConfigPost);
  webServer.on("/netconfig", HTTP_POST, handleNetConfigPost);
  webServer.on("/timeconfig", HTTP_POST, handleTimeConfigPost);
  webServer.on("/devices", HTTP_POST, handleDevicesPost);
  webServer.on("/devices/delete", HTTP_POST, handleDeleteDevicePost);
  webServer.on("/ota", HTTP_POST, handleOtaComplete, handleOtaUpload);
  webServer.on("/files/download", HTTP_GET, handleFileDownload);
  webServer.on("/files/edit", HTTP_GET, handleFileEditGet);
  webServer.on("/files/save", HTTP_POST, handleFileSavePost);
  webServer.on("/files/confirm-delete", HTTP_GET, handleFileConfirmDelete);
  webServer.on("/files/delete", HTTP_POST, handleFileDeletePost);
  webServer.on("/files/new", HTTP_POST, handleFileNewPost);
  webServer.onNotFound([]()
                       {
    Serial.printf("Web: 404 — no route for %s %s\n", webServer.method() == HTTP_POST ? "POST" : "GET", webServer.uri().c_str());
    sendSafe(404, "text/plain", "Not found"); });
  webServer.begin();
  Serial.println("Web server started");
}
