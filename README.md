# Non-Malicious Powershell Script Crash

## Report Information

**Analyst:** Justin Soflin  
**Date Completed:** Jan. 06, 2026  
**Environment Investigated:** Cyber Range at LOG(N) Pacific  
**Host Investigated:** `windows-target-1`  <Br>
**User Context:** SYSTEM | Scheduled PowerShell crash & Automated Azure Recovery <br>
**Tools & Data Sources:** Microsoft Azure, Microsoft Defender for Endpoint, Log Analytics workspaces, KQL (Kusto Query Language)  <br>
**Scope:** SYSTEM-level script execution review, crash correlation analysis, Azure guest agent and extension behavior, recovery telemetry validation, and platform-driven recovery behavior

---

## Table of Contents

- [Report Information](#report-information)
- [Executive Summary](#executive-summary)
  - [**Notable Events**](#notable-events)
- [Investigation](#investigation)
  - [_pwncrypt.ps1_ Stops Unexpectedly](#_pwncryptps1_stops-unexpectedly)
  - [Windows Error Reporting Detects Crash](#windows-error-reporting-detects-crash)
  - [Azure MMA Heartbeat Service Installed](#azure-mma-heartbeat-service-installed)
  - [Guest Configuration Compliance Checks _`gc_worker.exe`_](#guest-configuration-compliance-checks-_gc_workerexe_)
  - [Restarting the VM Did Not Restore Functionality](#restarting-the-vm-did-not-restore-functionality)
- [Recommended Actions](#recommended-actions)
  - [Immediate Recovery Actions](#immediate-recovery-actions)
  - [Investigation Actions Already Taken](#investigation-actions-already-taken)
  - [Monitoring Actions](#monitoring-actions)
- [Conclusion](#conclusion)

---

## Executive Summary

_`windows-target-1`_, a **honeypot virtual machine** used in the Cyber Range SOC, was identified as being **offline for approximately six weeks** following a **SYSTEM-level unhandled exception** that resulted in a **critical crash** recorded by **_WerFault.exe_**. As a result of the failure, the **attack simulation framework** ceased functioning, preventing the generation of **security telemetry** required for **student lab exercises**.

Post-crash telemetry indicates that Azure attempted automated recovery, including 
   - Guest Configuration assessments
   - Custom Script Extension retries
   - Defender/HealthService activity
These events reflect Azure control-plane remediation efforts against a **degraded guest state**, rather than continued attack activity or malicious persistence.

- **Notable Events**
   - Honeypot VM _`windows-target-1`_ unexpectedly went offline for about _42 days_
   - Many **_WerFault.exe_** processes were observed at the time of failure
   - The outage prevented execution of **automated attack simulation scripts**
   - Post-reboot, **credential reset attempts via the Azure portal (ARM API)** consistently failed

---
  
## Investigation

### _pwncrypt.ps1_ Stops Unexpectedly
- Multiple **scheduled PowerShell scripts** were configured to run on _`windows-target-1`_
- The scheduled **_pwncrypt.ps1_** script stops unexpectedly at **`2025-11-24T04:12:59.7367393Z`**
- No subsequent scheduled scripts executed after this point

```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where ProcessCommandLine contains "pwncrypt"
| where TimeGenerated > ago(50d)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="1115" height="262" alt="image" src="https://github.com/user-attachments/assets/eb27289c-4dbc-427c-8f65-6446548b8901" />

<br>

### Windows Error Reporting Detects Crash
- **_WerFault.exe_** activity directly correlates with the unexpected termination of **_pwncrypt.ps1_**
- The final execution of **_pwncrypt.ps1_** occurred at **`2025-11-24T04:12:59.7367393Z`**, seconds before the crash was recorded
- Some PowerShellCommand events appear after the WerFault entry because PowerShell finished writing its logs after the process ended
- Process start and stop events confirm the script ran **before the crash**, instead of after

```kql
let crash = todatetime('2025-11-24T04:12:50');
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between ( crash - 10m .. crash + 10m)
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated desc
```

<img width="1136" height="296" alt="image" src="https://github.com/user-attachments/assets/be751198-5396-4e43-bbf5-1ad8cdd074a6" />

<br>

### Azure MMA Heartbeat service installed

- Azure detected something wrong with the guest agent
- Azure (re)installed or repaired the MMA Extension Heartbeat Service
- Azure then went through multiple internal processes trying to restore a “healthy” state
- This is the first sign of control-plane disruption

```kql
let crash = todatetime('2025-11-24T04:10:00');
DeviceEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between ( crash - 20m .. crash + 20m)
| project TimeGenerated, FileName, ActionType, AdditionalFields, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="1045" height="340" alt="image" src="https://github.com/user-attachments/assets/494e69b1-f269-4f32-9b89-226a5f983d6f" />

<Br>

### Guest Configuration compliance checks _`gc_worker.exe`_

- Azure repeatedly runs gc_worker.exe attempting to re‑establish trust and validate the VM after the guest agent became unstable
- Some compliance checks are _NonCompliant_ because the VM is in a partial / degraded state
- VM never fully re‑established trust, causing ARM API commands and attack simulation to cease

```kql
let crash = todatetime('2025-11-24T04:10:00');
DeviceEvents
| where DeviceName == "windows-target-1"
| where TimeGenerated between ( crash - 20m .. crash + 20m)
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="1140" height="319" alt="image" src="https://github.com/user-attachments/assets/8011828a-7ad1-44a5-933a-b4bd6d93261c" />

<br>

### Restarting the VM did not restore functionality

- A VM reboot restarts the OS, but does not necessarily repair Azure VM Agent
- If the crash impacted the Azure VM Agent, ARM API commands will fail or time out indefinitely
- The attack simulator relies on SYSTEM-level commands via ARM. If Azure can’t authenticate to the guest or launch scripts as SYSTEM, no simulated attacks will run

---

## Recommended Actions

While this event appears to be a non-malicious anomaly, the following actions are recommended to maintain reliable functionality and help detect similar issues in the future.

1. Immediate Recovery Actions
   - Redeploy the affected VM
   - Ensure the Azure VM Agent and extensions are fully restored
   - Verify attack simulator scripts execute successfully
   - Run gc_worker.exe checks manually to ensure the VM is fully trusted and reporting correctly

2. Investigation Actions Already Taken
   - Review crash telemetry
   - Confirm no malicious artifacts appeared during the SYSTEM-level script crash
   - Document sequence of events, including WerFault, gc_worker, heartbeat service, and HealthService logs 

3. Monitoring Actions
   - Add crash monitoring for SYSTEM scripts
   - Detect future unhandled exceptions automatically
   - Audit scheduled tasks and guest agent health
   - Periodic validation of VM agent, MMAHeartbeatService, and extension states
   - Log and visualize Azure recovery events

---

## Conclusion

This incident demonstrates that long-running, fully automated systems are still vulnerable to environmental changes, and failures within those systems are not inherently indicative of malicious activity. In this case, a SYSTEM-level PowerShell script (_pwncrypt.ps1_) encountered an unhandled exception, triggering a cascade of recovery behavior rather than an attack. Because the script executed with SYSTEM privileges, it had access to critical VM components, including the Azure VM agent, and an unhandled failure at this level can leave the guest in a partially corrupted state even when no compromise has occurred. 

Azure relies heavily on guest agent integrity for control-plane communication, so when abnormal behavior is detected, it assumes the VM may be unhealthy and automatically initiates recovery actions such as restarting heartbeat services. The resulting telemetry spanning WerFault.exe, heartbeat services, HealthService activity, and credential validation reflects Azure attempting to re-establish trust with a VM it no longer considers reliable. 

Reboots were insufficient because the agent remained degraded, making VM redeployment the process that reinstalls the agent the only reliable resolution. Overall, this dataset highlights how cloud recovery mechanisms can generate noisy and suspicious-looking endpoint telemetry and reinforces the importance of context and system role awareness when identifying true adversary activity.
