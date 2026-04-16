<div dir="rtl">

# 🔍 Network Scanner — סורק רשת ארגוני

כלי סריקה ומיפוי רשת ארגונית עם ממשק ווב בעברית.  
מזהה מכשירים, שירותים, מערכות הפעלה, ומשיג מידע OSINT — ומייצא דוחות Excel ו-PDF.

---

## תכונות עיקריות

| תכונה | פירוט |
|---|---|
| 🖥️ **סריקת פורטים** | TCP scan מהיר על טווח IP עם זיהוי שירות ורמת סיכון |
| 🗺️ **מיפוי נכסים** | ARP · NetBIOS/SMB · SNMP · DNS Sweep · Docker API |
| 🔎 **OSINT** | Shodan InternetDB (חינמי) + Shodan / Censys API |
| 🏢 **Active Directory** | שאילתת LDAP לאובייקטי מחשב ב-AD |
| 📊 **דוחות** | Excel רב-גיליוני + PDF עם תמיכת RTL עברית |
| 🪟 **חוויית Desktop** | EXE עצמאי (ללא Python), מגש מערכת, מסך ספלאש |
| 🔒 **הרשאות** | UAC elevation אוטומטי (נדרש לסריקת ARP/NetBIOS) |

---

## דרישות מערכת

- **Windows 10 / 11** (64-bit)
- **הרשאות Administrator** (לסריקת ARP, NetBIOS, ו-raw sockets)
- חיבור לרשת הפנימית שברצונך לסרוק

> **אין צורך בהתקנת Python** — קובץ ה-EXE כולל את כל הספריות.

---

## שימוש מהיר — הרצת EXE לאחר בנייה

לאחר שתריצו את `build.bat` (ראו פרק "בנייה מקוד מקור" למטה), ה-EXE המוכן ימצא כאן:

```
dist\NetworkScanner\NetworkScanner.exe
```

**שלבי הפעלה:**

1. ודאו שריצתם `build.bat` לפחות פעם אחת
2. פתחו את התיקייה `dist\NetworkScanner\`
3. לחצו לחיצה כפולה על `NetworkScanner.exe`
4. אשרו את חלון ה-UAC (בקשת הרשאות Administrator)
5. ימתין מסך ספלאש קצר עד שהשרת עולה
6. הדפדפן ייפתח אוטומטית ל-`http://localhost:5000`

> **להפצה:** העתיקו את כל תיקיית `dist\NetworkScanner\` — ה-EXE תלוי ב-DLL-ים שנמצאים לידו.

> מגש המערכת (System Tray) יציג אייקון עם אפשרויות:  
> **פתח ממשק** · **הפסק שרת** · **יציאה**

---

## בנייה מקוד מקור

### דרישות פיתוח

| כלי | גרסה מינימלית |
|---|---|
| Python | 3.11+ |
| pip | 23+ |

### שלב 1 — שכפול הריפו

```bat
git clone https://github.com/kobika2024/network-scanner.git
cd network-scanner
```

### שלב 2 — התקנת תלויות

```bat
pip install -r requirements.txt
```

זה מתקין:

| חבילה | מטרה |
|---|---|
| `flask` | שרת הווב |
| `pysnmp-lextudio` | סריקת SNMP |
| `docker` | גילוי Docker containers |
| `ldap3` | שאילתות Active Directory |
| `reportlab` | יצירת PDF |
| `openpyxl` | יצירת Excel |
| `arabic-reshaper` + `python-bidi` | תמיכת RTL עברית ב-PDF |
| `pystray` + `Pillow` | אייקון מגש מערכת |

### שלב 3 — הרצה ישירה (פיתוח)

```bat
python app.py
```

פתחו דפדפן ב-`http://localhost:5000`

### שלב 4 — בניית EXE לווינדוס

```bat
build.bat
```

הסקריפט:
1. מוודא שיש Python + PyInstaller
2. מתקין את כל התלויות
3. מייצר את אייקון האפליקציה (`static/icon.ico`)
4. מנקה build קודם
5. מריץ PyInstaller עם ה-spec המוגדר מראש

הפלט: `dist\NetworkScanner\NetworkScanner.exe`

> **להפצה:** העתיקו / דחסו את כל תיקיית `dist\NetworkScanner\` — ה-EXE תלוי ב-DLL-ים שנמצאים לידו.

---

## מבנה הפרויקט

```
network-scanner/
│
├── launcher.py            ← נקודת כניסה ל-EXE (מגש, ספלאש, Flask)
├── app.py                 ← Flask backend + REST API
├── scanner.py             ← מנוע סריקת TCP
│
├── discovery/
│   ├── orchestrator.py    ← צינור גילוי שלושה-שלבי
│   ├── arp_discovery.py   ← ARP + זיהוי MAC vendor
│   ├── netbios_discovery.py ← NetBIOS NBNS + SMB version
│   ├── snmp_discovery.py  ← SNMP v1/v2c
│   ├── dns_sweep.py       ← Reverse DNS
│   ├── docker_discovery.py ← Docker API + Kubernetes
│   ├── os_fingerprint.py  ← זיהוי OS רב-שכבתי
│   └── ldap_discovery.py  ← Active Directory
│
├── models/
│   └── asset.py           ← dataclass מאוחד לנכס
│
├── reports/
│   ├── excel_report.py    ← Excel רב-גיליוני + RTL
│   └── pdf_report.py      ← PDF עם תמיכת עברית
│
├── templates/
│   └── index.html         ← ממשק SPA עברית RTL
│
├── static/
│   └── icon.ico           ← אייקון האפליקציה (נוצר ע"י make_icon.py)
│
├── make_icon.py           ← יוצר את icon.ico (Pillow)
├── network_scanner.spec   ← הגדרת PyInstaller
├── build.bat              ← סקריפט בנייה מלא
├── app.manifest           ← UAC + DPI awareness (Windows)
└── requirements.txt
```

---

## מדריך שימוש — לשונית אחר לשונית

### 🔵 לשונית 1: סריקת פורטים

**מטרה:** מצא אילו פורטים פתוחים על כל מכשיר בטווח IP.

| שדה | דוגמה | הסבר |
|---|---|---|
| Target | `192.168.1.0/24` | CIDR, טווח (`192.168.1.1-50`), או IP בודד |
| Port Preset | `common` | ראה טבלת Presets למטה |
| Timeout | `2.0` | שניות המתנה לכל פורט |

**Presets מובנים:**

| Preset | פורטים נסרקים | שימוש |
|---|---|---|
| `quick` | 22, 80, 443, 3389, 445 | סריקה ראשונית מהירה |
| `common` | ~40 פורטים נפוצים | ברירת מחדל לרוב השימושים |
| `web` | 80, 443, 8080, 8443, 8888... | שרתי ווב |
| `database` | 1433, 3306, 5432, 6379... | בסיסי נתונים |
| `remote` | 22, 23, 3389, 5900, 5985 | גישה מרחוק |
| `infra` | 161, 162, 389, 636, 3268... | תשתית ארגונית |
| `custom` | לפי הכנסה ידנית | `80,443,8080` |

**פירוש רמות הסיכון:**

| צבע | רמה | דוגמה |
|---|---|---|
| 🔴 אדום | CRITICAL | Telnet, SMBv1, RDP ללא הגנה |
| 🟠 כתום | HIGH | FTP, SMTP, MySQL חשוף |
| 🟡 צהוב | MEDIUM | HTTP, שירותים פנימיים |
| 🟢 ירוק | LOW | HTTPS, SSH |

---

### 🟢 לשונית 2: מלאי נכסים (Asset Discovery)

**מטרה:** מיפוי עמוק של כל מכשיר ברשת — שם, OS, חומרה, שירותים.

**שיטות גילוי (ניתן לבחור):**

| שיטה | מה היא מגלה |
|---|---|
| **ARP** | כתובות MAC + ספק חומרה (תמיד פעיל) |
| **NetBIOS/SMB** | שם מחשב Windows + גרסת OS מ-SMB banner |
| **SNMP** | sysName, sysDescr, interfaces, location |
| **DNS Sweep** | hostname מ-Reverse DNS |
| **Docker** | containers פעילים, images, ports |

**תהליך הגילוי — שלושה שלבים:**

```
שלב 1: Network Sweep
  └─ ARP + DNS + ICMP ping במקביל על כל הרשת

שלב 2: Per-Host Deep Scan
  └─ TCP + NetBIOS + SNMP + Docker במקביל לכל מכשיר

שלב 3: OS Fingerprinting
  └─ SSH banner → HTTP header → SNMP sysDescr → TTL
```

**ייצוא תוצאות:**

- **Excel** — 5 גיליונות: מלאי נכסים, פורטים פתוחים, סטטיסטיקות, Docker, SNMP
- **PDF** — דוח ניהולי עם תמיכת עברית RTL
- **JSON** — פורמט גולמי לעיבוד נוסף

**Active Directory (LDAP):**

מלא את פרטי ה-Domain, שם משתמש וסיסמה לשאילתת אובייקטי מחשב ב-AD:

```
Domain:   corp.local
Username: administrator
Password: ••••••••
DC Server: (השאר ריק לגילוי אוטומטי)
```

---

### 🟡 לשונית 3: OSINT

**מטרה:** מידע ציבורי על IP חיצוני — ארגון, מדינה, פורטים, חולשות.

**Shodan InternetDB (ללא API Key — חינמי):**
- הכנס IP חיצוני
- השאר את שדה ה-API Key ריק
- קבל פורטים פתוחים, hostnames, CVEs ידועות

**Shodan Full API (דורש API Key):**
- אותה תוצאה + org, ISP, מיקום גיאוגרפי, banner לכל שירות

**Censys (דורש API ID + Secret):**
- הרשם ב-[censys.io](https://censys.io) וקבל API credentials
- תוצאות: שירותים, תעודות TLS, ASN, BGP prefix

---

## שאלות נפוצות

**ש: האפליקציה לא נפתחת / חלון ה-UAC לא מופיע**  
ת: ודאו שאתם מריצים את ה-EXE ישירות (לא מ-network drive). לחצו ימין → "הפעל כמנהל".

**ש: הסריקה לא מוצאת מכשירים**  
ת: בדקו שאתם מחוברים לאותה רשת. Windows Firewall יכול לחסום ARP — כבו אותו זמנית או הוסיפו חריג.

**ש: NetBIOS לא מזהה שמות מחשב**  
ת: ודאו שפורט UDP 137 אינו חסום ב-Firewall. בדקו שה-NetBIOS over TCP/IP מופעל בהגדרות ה-Adapter.

**ש: שגיאת SNMP "No response"**  
ת: בדקו שה-community string נכון (`public` הוא ברירת המחדל). ודאו שפורט UDP 161 אינו חסום.

**ש: ה-EXE הופעל פעמיים ויש קונפליקט פורטים**  
ת: האפליקציה מנסה אוטומטית פורטים 5000–5010. אם כולם תפוסים — סגרו instances קודמים דרך מגש המערכת.

**ש: הדוח PDF לא מציג עברית**  
ת: ודאו שהקובץ `NotoSansHebrew` זמין. האפליקציה נופלת ל-Helvetica אם הפונט חסר — העברית עדיין תופיע אך ללא עיצוב RTL מושלם.

**ש: Docker לא מזוהה**  
ת: Docker API מאזין בפורט TCP 2375 (HTTP) או 2376 (HTTPS). ב-Docker Desktop ל-Windows, הפעילו "Expose daemon on tcp://localhost:2375 without TLS" בהגדרות.

---

## אבטחה ואחריות

> ⚠️ **שימוש מורשה בלבד**  
> כלי זה מיועד לניטור ואבטחת רשתות שברשותך או שיש לך אישור מפורש לסרוק אותן.  
> שימוש לסריקת רשתות ללא אישור עלול להיות בלתי חוקי.

- כל הסריקות מתבצעות **ממחשבך בלבד** — אין שרת חיצוני
- התוצאות נשמרות **בזיכרון בלבד** (נמחקות עם סגירת האפליקציה)
- ה-OSINT שואב ממידע **ציבורי** בלבד (Shodan InternetDB / Censys API)

---

## רישיון

MIT License — שימוש חופשי לצרכי פנים ארגוניים ומחקר.

</div>
