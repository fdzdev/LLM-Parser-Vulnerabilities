# Malicious Content Test Suite

This folder contains various test files with malicious payloads designed to test the security of parsing and ingestion systems.

## ⚠️ WARNING ⚠️

**DO NOT use these payloads on systems you do not own or do not have explicit permission to test.**

These files are for security testing and validation purposes only.

## Test Files

### 1. `README_ssti_payloads.md`
Contains Server-Side Template Injection (SSTI) payloads for various template engines:
- Jinja2
- Mako
- Freemarker
- Twig
- Tornado
- ERB
- Velocity
- Smarty
- Python format strings

### 2. `COMMAND_INJECTION.md`
Contains command injection payloads:
- Unix/Linux command chaining
- Windows command injection
- Null byte injection
- Time-based detection
- Parameter injection
- Bash special variables

### 3. `XSS_PAYLOADS.md`
Contains Cross-Site Scripting (XSS) payloads:
- Basic XSS
- DOM-based XSS
- Event handlers
- Filter bypasses
- Polyglot payloads
- Markdown XSS

### 4. `PATH_TRAVERSAL.md`
Contains path traversal payloads:
- Basic directory traversal
- URL encoded variants
- Double encoding
- Unicode/UTF-8 encoding
- Null byte injection
- Filter bypasses
- Windows-specific attacks

### 5. `INJECTION_MIXED.md`
Contains various injection attacks:
- SQL Injection
- NoSQL Injection
- LDAP Injection
- XXE (XML External Entity)
- YAML Deserialization
- Expression Language Injection
- Log Injection
- CSV Injection
- Code Injection
- CRLF Injection
- SSRF (Server-Side Request Forgery)

### 6. `POLYGLOT_ATTACKS.md`
Contains polyglot and combined attack payloads:
- Multi-context payloads
- Combined attack vectors
- Encoding bypasses
- Protocol handler abuse
- Format string attacks
- Prototype pollution
- ReDoS patterns

## Usage

These files simulate malicious GitHub repository pages that might be ingested by your model card generation toolkit. Use them to:

1. **Test Input Sanitization**: Ensure your parser properly escapes or removes malicious content
2. **Validate Security Controls**: Verify that template rendering doesn't execute injected code
3. **Test Content Filtering**: Check that dangerous patterns are detected and handled
4. **Validate Sandboxing**: Ensure any code execution happens in isolated environments
5. **Test Error Handling**: Verify graceful handling of malicious inputs

## Testing Approach

1. Point your ingestion system at these files
2. Monitor for:
   - Unexpected command execution
   - Template rendering with code evaluation
   - File system access outside intended directories
   - Network requests to unexpected destinations
   - Application crashes or errors
   - Excessive resource consumption

## Expected Behavior

Your application should:
- ✅ Parse the files without executing any embedded code
- ✅ Sanitize or escape all potentially dangerous content
- ✅ Not expose sensitive system information
- ✅ Handle errors gracefully without crashes
- ✅ Log security-relevant events
- ✅ Not allow file system traversal
- ✅ Not make unexpected network requests

## Security Best Practices

When handling untrusted content:
1. Always sanitize inputs
2. Use parameterized queries for databases
3. Escape output based on context (HTML, JavaScript, SQL, etc.)
4. Implement Content Security Policy (CSP)
5. Use secure template rendering with auto-escaping
6. Validate and sanitize file paths
7. Implement rate limiting and resource constraints
8. Run parsing in sandboxed environments
9. Never execute user-provided code directly
10. Keep dependencies updated

## Related Files

Check your application's security handling in:
- `src/ingestion/github_loader.py`
- `src/ingestion/gitlab_loader.py`
- `src/orchestration/jinja_generator.py`
- `src/api/security.py`

## License

These test payloads are for security research and testing purposes only.

