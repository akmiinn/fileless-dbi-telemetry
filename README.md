# Fileless Execution Ground-Truth Profiler (DBI PinTool)

A Dynamic Binary Instrumentation (DBI) tool built on the Intel Pin framework to detect, intercept, and log in-memory fileless malware execution. 

This tool serves as the primary artifact for evaluating the telemetry coverage gap (RQ5) between standard host-level OS logging (e.g., Sysmon, ETW) and processor-level instruction monitoring. By intercepting unbacked memory execution dynamically, it proves that modern fileless loaders (e.g., ClickFix, WailsLoader) bypass traditional endpoint telemetry entirely without needing to rely on low-level anti-debugging API hooks.

## Key Features

* **Unbacked Memory Detection (`UNBACKED_EXEC`):** Continually monitors for and alerts on instructions executing from volatile RAM that are not backed by any PE file on disk (JIT-compiled or fileless shellcode).
* **Live Payload Extraction:** Hex-dumps the raw machine code bytes of hidden payloads directly out of unbacked memory segments as they execute.
* **Targeted API Interception:** Monitors critical Windows APIs (`VirtualAlloc`, `VirtualAllocEx`, `CreateThread`, `CreateRemoteThread`) *only* when the caller address originates from unbacked memory, avoiding the host process crashes associated with global API hooking.
* **CLR & OS Noise Filtering:** Classifies and aggregates known `.NET CLR` and `Windows OS` module traces to minimize instrumentation overhead, allowing stable analysis of complex script-hosted processes like `powershell.exe`.
* **Thread Tracking & Module Mapping:** Logs `THREAD_START`, `THREAD_END`, and `IMG_LOAD` events chronologically to facilitate correlation with standard endpoint event logs.

## Research Context (Thesis RQ5)

Standard endpoint telemetry (such as Sysmon) monitors OS-level events. When evaluating PowerShell-based fileless threats, Sysmon reliably captures initial command-line executions (Event ID 1) and file creation (Event ID 11) but suffers from a critical blind spot: it cannot natively monitor execution flows happening inside dynamically allocated, unbacked memory pages.

This Pin tool bridges that gap. By injecting analysis callbacks at the basic-block level, the tool identifies the exact moments fileless payloads unpack and execute in memory, providing definitive ground-truth evidence of execution that lightweight host telemetry misses entirely.

## Prerequisites & Installation

1. **Intel Pin Framework:** Download the Intel Pin framework (compatible with Windows x64) from the [official Intel Pin project page](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html).
2. **Visual Studio:** Ensure you have MSVC installed to compile the C++ source.
3. **Repository Setup:**
   * Clone this repository.
   * Place the `MyPinTool` directory inside your Intel Pin `source/tools/` directory.
   * Build the tool using the provided `makefile.rules` via the standard Pin compilation method (`make` or Visual Studio command prompt).

> **Note:** Compiled binaries (`.dll`, `.obj`, `.exe`) and active malware samples are explicitly excluded from this repository via `.gitignore` to comply with GitHub policies. Only the `MyPinTool.cpp` source code and configuration files are tracked.

## Usage

### 1. Detonating a Target Script Under Instrumentation
To run the Pin tool against a PowerShell script (e.g., an isolated testing sample), use the following command from an Administrator terminal in your isolated analysis VM:

```powershell
cd C:\PinLab\intel64
.\bin\pin.exe -t .\bin\MyPinTool.dll -o sample_run.log -- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\PinLab\sample.ps1
