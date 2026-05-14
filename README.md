# GoofEDR

> A Windows EDR that catches obfuscated PowerShell scripts using Shannon entropy analysis — suspends the process, then asks if you'd like to kill it with fire.

---

## What It Does

GoofEDR subscribes to Windows PowerShell Operational logs (Event ID 4104 — Script Block Logging) in real time. When a script block is executed, it gets pulled, analyzed for entropy, and if it looks suspiciously obfuscated, the offending process is suspended and a dialog prompts you to kill or release it.

```
[PowerShell executes something]
        ↓
[GoofEDR catches Event ID 4104]
        ↓
[Extracts script block text]
        ↓
[Calculates Shannon Entropy]
        ↓
 entropy > 5.3?
   YES → Suspend process → Pop dialog → Kill or Release
   NO  → Print to console, move on
```

---

## Why Shannon Entropy?

Obfuscated code — base64 blobs, encrypted payloads, heavily mangled scripts — has a much more uniform character distribution than readable code. Shannon entropy measures exactly that: how "random" the character distribution is.

Normal PowerShell: entropy ~3.5–4.5  
Obfuscated payloads: entropy >5.3

The 5.3 threshold was tuned empirically. Is it perfect? No. Does it catch the stuff it's supposed to catch? Yeah.

---

## Features

- **Real-time event subscription** via Windows Event Log API (`EvtSubscribe`)
- **Script block extraction** from raw XML event data
- **Shannon entropy scoring** on every captured script block
- **Process suspension** via undocumented `NtSuspendProcess` (ntdll) before the prompt — the process can't run while you decide
- **Kill or release** — terminate or resume, your call
- Logs all captured script blocks + entropy scores to stdout

---

## Scope

Intentionally focused on entropy-based PowerShell detection — the goal was to explore the Windows event subscription pipeline and validate entropy as a practical obfuscation heuristic. It does that job well.

---

## Requirements

- Windows
- PowerShell Script Block Logging enabled via Group Policy or registry:
  ```
  HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging = 1
  ```
- Run as **Administrator** (required for process termination and event subscription)
- Link against `wevtapi.lib`

### Build

```bash
cl EDR.cpp /link wevtapi.lib
```

Or add `wevtapi.lib` to your Visual Studio linker dependencies and build normally.

---

## Usage

```
GoofEDR.exe
```

It starts listening. Run some PowerShell. Watch the console. If something high-entropy executes, a dialog appears.

`Ctrl+C` to stop.

---

## Notes

- `NtSuspendProcess` / `NtResumeProcess` are undocumented NT APIs — they work reliably in practice but are technically subject to change.
- The 5.3 entropy threshold may produce false positives on legitimate scripts that use heavy string manipulation or compression. Adjust to taste.

---

## License

Do whatever you want with it.
