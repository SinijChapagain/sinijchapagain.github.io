# QLotto — HTB (Quantum Lottery Challenge)

QLotto is Hack The Box's quantum lottery challenge by Qubitrix. At first glance it looks like pure chance — until you realize the "quantum draws" aren't random at all. By exploiting how qubits are indexed and entangled, prediction turns into certainty.

## First contact

Connecting to the server with `nc 83.136.252.32 48713` drops you at a prompt:

![initial prompt](qlotto-htb/doc-1_1.png)

```
Place your quantum moves :
```

It says "moves", plural — so it likely expects a *sequence* of gates, not a single one. Typing a single gate like `H:0` gets rejected:

```
[Dealer] Hey, don't tamper with the house card — that's forbidden.
```

The description mentions "Qubitrix", a fictional quantum company, suggesting a custom gate syntax.

## Reading the source

The challenge ships `server.py`. Right at the start of `generate_circuit`:

```python
circuit = QuantumCircuit(2)
circuit.h(0)
```

So the server already applies a Hadamard gate to qubit 0 before our input — qubit 0 starts in superposition, but we can't touch it directly. Parsing of our moves looks like this:

![server.py parsing](qlotto-htb/doc-2_1.png)

```python
instructions = instructions.split(";")
for instr in instructions:
    parts = instr.split(":")
    if len(parts) != 2:
        print(f"[Dealer] The move '{instr}' isn't recognized at this table.")
        return None
```

Two takeaways:

1. Input is split on semicolons, so multiple moves are allowed.
2. Each move must be `<gate>:<params>`, e.g. `H:0` or `RYY:90,-2,1`.

A later check forbids the literal `0` in any parameter:

```python
if any(p == 0 for p in params):
    print("[Dealer] Hey, don't tamper with the house card — that's forbidden.")
    return None
```

## The bypass — negative indexing

In Python, negative indices wrap around. In a two-qubit system, index `-2` refers to the *same* qubit as `0`. So even though `0` is forbidden, `-2` means exactly the same thing — letting me reference the hidden house qubit.

My goal: entangle the visible qubit 1 with the hidden qubit 0. The only entangling gate available was `RYY`. The sequence:

- `H:-2` — safely reference the hidden qubit
- `H:1; Z:1; H:1` — flip the visible qubit usefully
- `RYY:90,-2,1` — tie the two qubits together

So I sent:

```
H:-2;H:1;Z:1;H:1;RYY:90,-2,1
```

## Turning draws into the winning bet

The server returned six numbers — my "draws". Because the qubits were now entangled, the draws weren't random; they were correlated with the secret winning numbers. After a few rounds, a clear pattern emerged:

- If a draw was small (under 25), the secret number was `23 - draw`
- If it was large (25 or more), it was `65 - draw`

Applying that rule to each draw produced the correct bet, which returned the flag:

![flag](qlotto-htb/doc-5_1.png)

**Happy Hacking!!!**
