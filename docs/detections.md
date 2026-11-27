# جدول كشف التقنيات (نطاق Windows + Active Directory)

هذا الجدول يوضح لكل تقنية MITRE ATT&CK في المشروع: وين تنكشف، ورقم الحدث، ومثال استعلام Splunk، والتنبيه اللي يمثلها في مرصاد. المصدر: `rules/mitre_mapping.json`.

> الاستعلامات أمثلة مبدئية، وتحتاج تعديل أسماء الـ index حسب بيئة Splunk عندكم.

| التكتيك | التقنية | مصدر السجل | رقم الحدث | التنبيه في مرصاد |
| --- | --- | --- | --- | --- |
| Reconnaissance | T1595 الفحص النشط (Active Scanning) | Firewall / IDS | — | فحص منافذ |
| Defense Evasion / Persistence / Initial Access | T1078 حسابات صالحة (Valid Accounts) | Windows Security | 4624 | دخول ناجح بعد محاولات فاشلة، دخول VPN من دولة جديدة |
| Initial Access | T1091 الانتشار عبر وسائط قابلة للإزالة (Replication Through Removable Media) | Windows Security | 6416 | توصيل ذاكرة USB |
| Initial Access | T1133 خدمات الوصول عن بعد (External Remote Services) | VPN Gateway | — | دخول VPN من دولة جديدة |
| Initial Access | T1190 استغلال تطبيق مكشوف للإنترنت (Exploit Public-Facing Application) | Web Server / WAF | — | من الظل الرقمي |
| Initial Access | T1566 التصيّد الاحتيالي (Phishing) | Email Gateway | — | حظر بريد مزعج |
| Initial Access | T1566.001 تصيّد بمرفق خبيث (Spearphishing Attachment) | Email Gateway | — | وصول بريد بمرفق فيه ماكرو |
| Execution | T1059.001 تنفيذ أوامر PowerShell (PowerShell) | Sysmon | 1 | برنامج أوفيس شغّل PowerShell |
| Execution | T1204.002 تشغيل المستخدم لملف خبيث (User Execution: Malicious File) | Sysmon | 1 | برنامج أوفيس شغّل PowerShell، تشغيل برنامج غير موقّع |
| Execution | T1569.002 التنفيذ عبر الخدمات (PsExec) (Service Execution) | Windows System | 7045 | تثبيت خدمة عن بُعد (PsExec) |
| Persistence | T1053.005 مهمة مجدولة (Scheduled Task) | Windows Security | 4698 | إنشاء مهمة مجدولة |
| Defense Evasion / Persistence | T1078.001 حسابات افتراضية (Default Accounts) | Device Logs | — | من الظل الرقمي |
| Defense Evasion / Persistence | T1078.002 حسابات النطاق (Domain Accounts) | Windows Security (DC) | 4624 | من الظل الرقمي |
| Defense Evasion / Persistence | T1078.003 حسابات محلية (Local Accounts) | Windows Security | 4624 | من الظل الرقمي |
| Persistence | T1547.001 التشغيل التلقائي عبر الريجستري (Registry Run Keys / Startup Folder) | Sysmon | 13 | إضافة برنامج للتشغيل التلقائي |
| Defense Evasion | T1070.001 مسح سجلات ويندوز (Clear Windows Event Logs) | Windows Security | 1102 | مسح سجلات الأمان |
| Credential Access | T1003 سحب بيانات الدخول من النظام (OS Credential Dumping) | Sysmon | 10 | من الظل الرقمي |
| Credential Access | T1003.001 سحب كلمات المرور من ذاكرة LSASS (LSASS Memory) | Sysmon | 10 | قراءة ذاكرة LSASS (سرقة كلمات المرور) |
| Credential Access | T1110 تخمين كلمات المرور (Brute Force) | Windows Security | 4625 | محاولات دخول فاشلة متكررة |
| Credential Access | T1552.001 بيانات دخول محفوظة في ملفات (Credentials In Files) | Windows Security | 4663 | فتح ملف حساس |
| Discovery | T1046 استكشاف خدمات الشبكة (Network Service Discovery) | Firewall / IDS | — | من الظل الرقمي |
| Discovery | T1087.002 استكشاف حسابات النطاق (Account Discovery: Domain Account) | Directory Service (DC) | 1644 | استعلامات LDAP مكثفة على النطاق |
| Lateral Movement | T1021.002 التحرك عبر مشاركات SMB (SMB/Windows Admin Shares) | Windows Security | 5140 | تثبيت خدمة عن بُعد (PsExec) |
| Lateral Movement | T1210 استغلال خدمات بعيدة (Exploitation of Remote Services) | IDS | — | من الظل الرقمي |
| Collection | T1005 جمع بيانات من النظام (Data from Local System) | Database Audit | — | استعلام ضخم على قاعدة البيانات |
| Command and Control | T1071.001 قيادة وتحكم عبر بروتوكولات الويب (Web Protocols) | Firewall / Proxy | — | اتصال بعنوان خبيث معروف |
| Command and Control | T1071.004 قيادة وتحكم عبر DNS (DNS) | Sysmon / DNS Server | 22 | نفق اتصال مخفي عبر DNS |
| Exfiltration | T1041 تسريب البيانات عبر قناة التحكم (Exfiltration Over C2 Channel) | Firewall | — | نقل بيانات كبير للخارج |
| Exfiltration | T1567.002 تسريب البيانات لتخزين سحابي (Exfiltration to Cloud Storage) | Firewall / Proxy | — | رفع بيانات لتخزين سحابي خارجي |

## استعلامات Splunk

**T1595 · الفحص النشط**

```spl
index=network sourcetype=ids signature=*scan* | stats dc(dest_port) as ports by src_ip | where ports>100
```

**T1078 · حسابات صالحة**

```spl
index=wineventlog EventCode=4625 OR EventCode=4624 | transaction TargetUserName src_ip maxspan=10m | where eventcount>5 AND searchmatch("EventCode=4624")
```

**T1091 · الانتشار عبر وسائط قابلة للإزالة**

```spl
index=wineventlog EventCode=6416 | table _time, host, DeviceDescription
```

**T1133 · خدمات الوصول عن بعد**

```spl
index=vpn action=login | iplocation src_ip | stats dc(Country) as countries values(Country) by user | where countries>1
```

**T1190 · استغلال تطبيق مكشوف للإنترنت**

```spl
index=web status=200 uri="*..%2f*" OR uri="*/cgi-bin/*" | stats count by src_ip, uri
```

**T1566 · التصيّد الاحتيالي**

```spl
index=email action=quarantine OR action=delivered | stats count by sender, recipient
```

**T1566.001 · تصيّد بمرفق خبيث**

```spl
index=email action=delivered attachment IN ("*.xlsm","*.docm","*.iso") | table _time, sender, recipient, attachment
```

**T1059.001 · تنفيذ أوامر PowerShell**

```spl
index=sysmon EventCode=1 Image="*powershell.exe" (ParentImage="*excel.exe" OR ParentImage="*winword.exe") | table _time, host, CommandLine
```

**T1204.002 · تشغيل المستخدم لملف خبيث**

```spl
index=sysmon EventCode=1 Signed=false | table _time, host, Image, ParentImage, User
```

**T1569.002 · التنفيذ عبر الخدمات (PsExec)**

```spl
index=wineventlog EventCode=7045 ServiceName=PSEXESVC OR ImagePath="*PSEXESVC*" | table _time, host, ServiceName, ImagePath
```

**T1053.005 · مهمة مجدولة**

```spl
index=wineventlog EventCode=4698 NOT TaskName="*GoogleUpdate*" | table _time, host, TaskName, Command
```

**T1078.001 · حسابات افتراضية**

```spl
index=network user IN (admin, root, default) action=success
```

**T1078.002 · حسابات النطاق**

```spl
index=wineventlog EventCode=4624 TargetUserName IN ("*admin*") LogonType=10 | stats count by TargetUserName, host
```

**T1078.003 · حسابات محلية**

```spl
index=wineventlog EventCode=4624 TargetUserName=svc_* LogonType IN (2,10)
```

**T1547.001 · التشغيل التلقائي عبر الريجستري**

```spl
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*" | table _time, host, TargetObject, Details
```

**T1070.001 · مسح سجلات ويندوز**

```spl
index=wineventlog EventCode=1102 | table _time, host, SubjectUserName
```

**T1003 · سحب بيانات الدخول من النظام**

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
```

**T1003.001 · سحب كلمات المرور من ذاكرة LSASS**

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" NOT SourceImage IN ("*CSFalconService.exe","*MsMpEng.exe") | table _time, host, SourceImage, GrantedAccess
```

**T1110 · تخمين كلمات المرور**

```spl
index=wineventlog EventCode=4625 | bin _time span=5m | stats count by _time, src_ip, TargetUserName | where count>=5
```

**T1552.001 · بيانات دخول محفوظة في ملفات**

```spl
index=wineventlog EventCode=4663 ObjectName IN ("*password*","*.kdbx","*cred*") | table _time, host, SubjectUserName, ObjectName
```

**T1046 · استكشاف خدمات الشبكة**

```spl
index=network | stats dc(dest_port) as ports by src_ip | where ports>50
```

**T1087.002 · استكشاف حسابات النطاق**

```spl
index=wineventlog EventCode=1644 | stats count by src_ip, user | where count>500
```

**T1021.002 · التحرك عبر مشاركات SMB**

```spl
index=wineventlog EventCode=5140 ShareName IN ("\\\\*\\ADMIN$","\\\\*\\C$") | table _time, host, IpAddress, SubjectUserName
```

**T1210 · استغلال خدمات بعيدة**

```spl
index=network sourcetype=ids category=exploit | table _time, src_ip, dest_ip, signature
```

**T1005 · جمع بيانات من النظام**

```spl
index=db action=select | where rows_returned>50000 | table _time, login, client, statement
```

**T1071.001 · قيادة وتحكم عبر بروتوكولات الويب**

```spl
index=network action=allowed | lookup threat_intel ip as dest_ip OUTPUT threat | where isnotnull(threat)
```

**T1071.004 · قيادة وتحكم عبر DNS**

```spl
index=sysmon EventCode=22 | eval len=len(QueryName) | stats count avg(len) as avg_len by host | where count>200 AND avg_len>40
```

**T1041 · تسريب البيانات عبر قناة التحكم**

```spl
index=network direction=outbound | stats sum(bytes_out) as out by src_ip, dest_ip | where out>100000000
```

**T1567.002 · تسريب البيانات لتخزين سحابي**

```spl
index=network sni IN ("*mega.co.nz","*mega.nz","*dropboxapi.com") | stats sum(bytes_out) by src_ip, sni
```
