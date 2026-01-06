# non-malicious powershell script crash (with automated azure recovery)

## Incident Summary

**_windows-target-1_**, a **honeypot virtual machine** used in the Cyber Range SOC, was identified as being **offline for approximately six weeks** following a **SYSTEM-level unhandled exception** that resulted in a **critical crash** recorded by **_WerFault.exe_**.

As a result of the failure, the **attack simulation framework** ceased functioning, preventing the generation of **security telemetry** required for **student lab exercises**. The issue was initially surfaced through **community observation**, prompting further investigation into the underlying cause.

The virtual machine has since been **re-deployed** to restore lab functionality. The **root cause of the crash remains undetermined**, presenting an opportunity for further analysis as an **educational exercise in incident reconstruction, telemetry correlation, and log analysis**.

- **Intel Highlights**
   - Honeypot VM `windows-target-1` unexpectedly offline for ~ 6 weeks
   - Many WERFault processes spawned at time of offline
   - VM failed to run automated scripts due to being offline
   - even after being rebooted, vm reset the credentials via the portal (ARM API) and it would not work

## Investigation

### pwncrypt.ps1 stops unexpectedly
Looking into vm events, there are many powershell scripts on this device that run on a schedule. we notice the `pwncrypt.ps1` script in particular stops at `2025-11-24T04:12:59.7367393Z`

kql```
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where ProcessCommandLine contains "pwncrypt"
| where TimeGenerated > ago(50d)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc 

<img width="1115" height="262" alt="image" src="https://github.com/user-attachments/assets/eb27289c-4dbc-427c-8f65-6446548b8901" />

### Windows Error Reporting detects crash 

this is showing the werfault log that correlates to the pwncrypt.ps1 script, and also the last time pwncrypt ran was `2025-11-24T04:12:59.7367393Z`, just a few seconds after the werfault spawned. 
Note: Some PowerShellCommand events appear after the WerFault.exe entry. This is due to buffered PowerShell telemetry being flushed after the PowerShell process terminated. Process creation and termination events confirm that script execution occurred prior to the crash.

kql```
let crash = todatetime('2025-11-24T04:12:50');
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between ( crash - 10m .. crash + 10m)
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated desc

<img width="1136" height="296" alt="image" src="https://github.com/user-attachments/assets/be751198-5396-4e43-bbf5-1ad8cdd074a6" />

### Azure MMA Heartbeat service installed

- Azure detected something wrong with the guest agent
- Azure (re)installed or repaired the MMA Extension Heartbeat Service
- Azure then went through multiple internal processes trying to restore a “healthy” state
- This is the first sign of control-plane disruption

kql```
let crash = todatetime('2025-11-24T04:10:00');
DeviceEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between ( crash - 20m .. crash + 20m)
| project TimeGenerated, FileName, ActionType, AdditionalFields, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc

<img width="1045" height="340" alt="image" src="https://github.com/user-attachments/assets/494e69b1-f269-4f32-9b89-226a5f983d6f" />

### Guest Configuration compliance checks `_gc_worker.exe_`

- Azure repeatedly runs gc_worker.exe attempting to re‑establish trust and validate the VM after the guest agent became unstable
  - AzureWindowsBaseline → run a specific policy / baseline
   -c Compliant / NonCompliant → result of that check
   -s inguest → executed inside the VM
   -g https://...guestconfiguration.azure.com → report results back to Azure
- some compliance checks are _NonCompliant_ because the VM is in a partial / degraded state
- VM never fully re‑established trust, causing ARM API commands and attack simulation to fail until the VM was redeployed.

kql```
let crash = todatetime('2025-11-24T04:10:00');
DeviceEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between ( crash - 20m .. crash + 20m)
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc

<img width="1140" height="319" alt="image" src="https://github.com/user-attachments/assets/8011828a-7ad1-44a5-933a-b4bd6d93261c" />

### Restarting the VM did not restore functionality

- A VM reboot restarts the OS, but does not necessarily repair Azure VM Agent
- If the crash impacted the Azure VM Agent, ARM API commands will fail or time out indefinitely
- The attack simulator relies on SYSTEM-level commands via ARM. If Azure can’t authenticate to the guest or launch scripts as SYSTEM, no simulated attacks will run
## Conclusion
things that are automated and have been working for a long time are still suceptible to changes in the environment and may cease to function. issues popping up in the environment aren't always indicitive of malicious intent

What actually crashed

The script ran as SYSTEM: powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1.

SYSTEM scripts have full access to the VM, including the VM agent and DPAPI-protected secrets.

An unhandled exception at this level can leave the guest agent or service state in a partial / corrupted state.

2. Why Azure reacts so aggressively

Azure VMs rely on guest agent integrity for control-plane communication:

The VM agent manages:

Extension execution (Custom Script Extension)

Heartbeat (MMAHeartbeatService)

Telemetry reporting (MDE / Defender / HealthService)

When the agent detects something unusual, it assumes the VM is unhealthy.

To fix this, Azure triggers:

Heartbeat service reinstall / restart (MMAExtensionHeartbeatService.exe)

DPAPI access to validate credentials

Memory protection operations (NtProtectVirtualMemoryApiCall)

HealthService checks (reading LSASS, validating OS state)

Basically:

The guest agent interprets the crash as a “VM might be broken or compromised”.

3. Why it cascades into multiple processes

WerFault.exe / wermgr.exe: captures crash details

Heartbeat service: restarts to check VM health

HealthService.exe: validates OS security context

DPAPI access: tries to decrypt credentials for ARM API communication

Even though it was just a PowerShell script crash, the VM agent sees it as a threat to VM stability, so it triggers all these recovery / verification steps automatically.

4. Why restarts didn’t fix it

The crash can corrupt DPAPI-protected secrets or extension state.

Azure thinks the VM is unhealthy even after reboot.

The only reliable fix is redeploying the VM, which reinstalls the agent and regenerates secrets.

✅ Plain summary

A SYSTEM-level PowerShell script failing can cause Azure to perceive the VM as unstable. This triggers multiple recovery processes—heartbeat service, HealthService checks, DPAPI access, memory protections—trying to restore agent trust. If the crash partially corrupts agent state, the VM can remain “broken” until redeployment. 

This dataset perfectly demonstrates:

How benign recovery activity can look extremely suspicious

Why context + sequencing matters more than single events

How cloud control-plane failures surface as noisy endpoint telemetry
