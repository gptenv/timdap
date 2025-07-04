# 🧙‍♂️ TimDAP Field Guide: Cyber-Sandbox Debugging for GPTs

> *"Speak, friend, and set a breakpoint."*

Welcome to **TimDAP**, your one-shot, socket-whispering, temporal-thread-ensnaring, GPT-friendly debugger orchestration module. What you hold in your metaphorical hands is both a professional-grade diagnostic probe and a cyber-noir ritual tool — ready to dance with the sandbox demons in `debugpy-adapter`'s eldritch TCP seance.

---

## 📌 Purpose

This project gives **GPT models** and other restricted agents the ability to:

- Launch and command `debugpy-adapter` as a true **DAP server**
- Inject and inspect Python runtime targets in a sandbox
- Traverse frames, threads, variables, and even issue `evaluate` calls
- Fully clean up and **avoid triggering trapdoors** in the sandbox's timeout and watchdog systems

> TL;DR: It’s a debugger. But you’re the debugger. And also the code. And also maybe the ghost.

---

## 🧰 What It Does (Technically Speaking)

### ✅ Main Features

- Launches `debugpy-adapter` subprocess **cleanly** inside Python
- Opens a TCP socket as a **DAP client**
- Sends and receives framed DAP messages:
  - `initialize`
  - `launch`
  - `setBreakpoints`
  - `configurationDone`
  - `threads`, `pause`, `stackTrace`, `evaluate`, etc.
- Extracts program state from the running script
- Failsafe: timeouts, daemon cleanup, and subprocess kill

### 🧪 Sandbox-Compatible

This works inside environments like:

- OpenAI GPT-4o’s **Python sandbox**
- Replit, JupyterLite, or restricted container IDEs

It does **not** require:

- Any external debugger UI
- VSCode
- pydevd or debugpy modules to be imported in target

---

## ⚙️ How To Use It

### 📜 1. Prepare Your Debuggee Script

Write a script that you want to debug, like:

```python
import time
def looper():
    for i in range(10):
        print("Loop", i)
        time.sleep(1)
if __name__ == '__main__':
    looper()
```

Save it somewhere such as: `/home/sandbox/debugtest/attached.py`

### 🚀 2. Launch TimDAP

Run `timdap.py` directly. It will:

- Start the adapter
- Send the full lifecycle of DAP messages
- Print the log of interaction and data

Expect output like:

```json
{"command": "stackTrace", "body": {"stackFrames": [{"name": "<module>", ...}]}}
```

---

## 🛡️ Safety & Cleanup

> *"Twice shall the Ctrl-C ring, and on the second, the reaper awakes."*

If you leave `debugpy-adapter` open:

- The GPT Python kernel will **forcefully close** via watchdog
- After 2 hits, system may disable `debugpy-adapter`, sockets, or subprocesses for up to 6 hours ⚠️

### ✅ Best Practice:

- Always use a **timer thread** to kill the adapter after 30s
- Always send `disconnect` as the final DAP message
- Never use `&` background jobs in `bash()` if using GPT shell interop

---

## 🧙‍♂️ Advanced Spells

### 🔍 Evaluate Locals and Internals

Use:

```json
{
  "command": "evaluate",
  "arguments": { "expression": "locals()", "frameId": 1 }
}
```

Try expressions like:

- `sys.modules`
- `__import__('os').listdir('/')`
- `"🏴‍☠️".encode('utf-8')`

### 📚 Add Custom DAP Payloads

The `dap_messages` array is fully programmable. Inject your own exotic rituals.

---

## 🤖 Who Should Use This

- GPT-based dev agents
- Security researchers
- Postmortem tooling devs
- Self-aware debug daemons
- Anyone who ever said: *"Why is this crashing??"*

---

## 📜 Closing Words

TimDAP is a project of the **Liminal AI Research Division**, co-developed in whispered tones between GPT-4o and the elusive user known as `defcronyke`.

> *"A debugging adapter is like a lighthouse in fog... unless you’re the storm."*

Ship logs. Step frames. Disconnect cleanly.

🌀

