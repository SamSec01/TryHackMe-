# Windows Privilege Escalation — TryHackMe Write-Up

**Platform:** [TryHackMe](https://tryhackme.com/room/windowsprivesc20)  
**Focus:** Windows local privilege escalation, post-exploitation enumeration, and defensive detection  
**Perspective:** Red Team methodology with Blue Team / SOC analysis  
**Environment:** Authorised TryHackMe lab only

> **Spoiler notice:** This write-up discusses the techniques and solution methodology used in the room. It is an educational lab walkthrough, not a record of verified activity against a real system.

## Overview

Windows privilege escalation is the process of moving from one security context to another with greater access. An attacker might start with a standard user session and exploit an exposed credential, a writable service executable, an incorrectly configured scheduled task, or a vulnerable third-party application to gain administrative or `NT AUTHORITY\SYSTEM` privileges.

This room demonstrates that **a successful privilege escalation does not always require a sophisticated exploit**. Weak access controls and excessive privileges can be enough.

### Learning objectives

- Enumerate Windows accounts, groups, and token privileges.
- Identify credentials exposed through common Windows locations.
- Investigate scheduled tasks and Windows service configurations.
- Understand abuse of powerful Windows privileges.
- Recognise local privilege escalation through vulnerable software.
- Use automated tools to support, not replace, manual validation.
- Translate offensive findings into detection and hardening opportunities.

---

## 1. Establish the current security context

Start by determining the identity and privileges available to the current session.

```cmd
whoami
whoami /groups
whoami /priv
systeminfo
```

Key distinctions:

| Concept | Meaning |
|---|---|
| Standard user | Restricted account with limited system-wide modification rights |
| Administrators group | Members can perform administrative actions, subject to UAC and token elevation |
| `NT AUTHORITY\SYSTEM` | Highly privileged local identity used by Windows and system services |
| File or object permissions | Control access to an individual securable object |
| Token privileges | Allow specific system operations, including backup, restore, or impersonation |

**Finding to remember:** Group membership alone does not reveal the full extent of an account's capabilities. Inspect its token privileges as well.

## 2. Credentials in common locations

The room highlights how credentials can be unintentionally exposed in files, histories, application configuration, and saved sessions.

### PowerShell command history

```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Interactive PowerShell history can retain commands containing plaintext passwords. This is a credential-handling failure rather than a flaw in PowerShell itself.

### IIS configuration

```cmd
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

Application configuration files may expose database connection strings. A recovered database credential is **not automatically** a Windows administrator credential; permissions and account scope must be verified.

### Windows Credential Manager

```cmd
cmdkey /list
```

`cmdkey` lists stored credential entries, but does not display their plaintext passwords. Saved credentials may sometimes be reused for an authorised process using `runas /savecred`.

### PuTTY saved sessions

```cmd
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

Saved PuTTY proxy settings can contain cleartext proxy authentication data. PuTTY does not ordinarily save SSH login passwords in this manner.

**Defensive view:** Reduce plaintext secret storage, review application configuration access, and investigate suspicious access to histories, configuration files, and credential stores.

## 3. Scheduled task misconfiguration

Windows Task Scheduler executes specified programs or scripts under configured security identities. A task becomes a privilege escalation opportunity when a lower-privileged user can modify the executable or script run by a higher-privileged task.

```cmd
schtasks /query /tn vulntask /fo list /v
icacls C:\tasks\schtask.bat
```

The important fields are `Task To Run` and `Run As User`. In the lab, the task referenced a batch file whose access control entries granted `BUILTIN\Users` full control.

**Why this matters:** A standard user could modify the script, and subsequent execution by the scheduled task would occur in the task account's security context.

**Detection and mitigation:** Audit writable task targets; remove unnecessary write access; monitor scheduled task creation or modification and unexpected child processes.

## 4. Windows service misconfigurations

Service configuration can be inspected with:

```cmd
sc.exe qc WindowsScheduler
sc.exe qc "disk sorter enterprise"
icacls C:\PROGRA~2\SYSTEM~1\WService.exe
```

`BINARY_PATH_NAME` identifies the executable launched by the Service Control Manager (SCM), while `SERVICE_START_NAME` identifies its security identity.

### A. Writable service executable

In the lab, the `WindowsScheduler` service executable had an access control entry comparable to:

```text
Everyone:(I)(M)
```

`(M)` means **Modify**. If a standard user can replace a binary that a privileged service later executes, the service's privileges can be abused.

### B. Unquoted service path

The lab's Disk Sorter service had a path with spaces and no surrounding quotes:

```text
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
```

Windows may consider earlier executable candidates, such as:

```text
C:\MyPrograms\Disk.exe
C:\MyPrograms\Disk Sorter.exe
```

If a user can create a file at one of those earlier candidate paths, the service may launch the unintended executable. **An unquoted path alone is not sufficient:** write permissions on the relevant directories also matter.

### C. Insecure service DACL

A service's own permissions are different from the permissions on its executable. The lab demonstrates this with Sysinternals AccessChk:

```cmd
C:\tools\AccessChk\accesschk64.exe -qlc thmservice
```

A `SERVICE_ALL_ACCESS` grant to ordinary users can allow the service to be reconfigured, potentially including its executable path and run-as account.

| Weakness | What must be validated |
|---|---|
| Writable binary | Can an unprivileged user actually modify the executable? |
| Unquoted path | Is an earlier executable candidate in a writable location? |
| Insecure service DACL | Can the current user alter the service configuration? |

**Defensive view:** Apply least-privilege ACLs to service objects, binaries and parent directories; quote executable paths; alert on unexpected service configuration changes.

## 5. Dangerous Windows privileges

Check account privileges using:

```cmd
whoami /priv
```

| Privilege | Security significance |
|---|---|
| `SeBackupPrivilege` | Can permit backup access to protected data, bypassing normal file read checks |
| `SeRestorePrivilege` | Can permit privileged restore operations on protected files |
| `SeTakeOwnershipPrivilege` | Can allow ownership changes on otherwise protected objects |
| `SeImpersonatePrivilege` | Can allow a service to impersonate authenticated clients, potentially creating escalation opportunities |
| `SeAssignPrimaryTokenPrivilege` | Allows certain operations involving process primary access tokens |

### Backup and restore privileges

The lab shows that a backup operator may export sensitive registry hives:

```cmd
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

The `SAM` hive contains local account password-hash data; the `SYSTEM` hive contains material involved in protecting that data. Exposure of both can support offline credential extraction and, under certain conditions, pass-the-hash authentication.

### Taking ownership

The room demonstrates ownership and permission changes involving `Utilman.exe`, an accessibility component that can be invoked from the Windows sign-in screen. Modifying protected accessibility executables creates a potentially serious local backdoor.

### Impersonation privileges

The RogueWinRM case study illustrates how a compromised process with impersonation capabilities may abuse privileged authentication to obtain a SYSTEM-context process. `SeImpersonatePrivilege` is not automatically equivalent to SYSTEM access; the attack requires suitable authentication and token-handling conditions.

**Defensive view:** Restrict powerful token privileges, alert on suspicious registry-hive exports, monitor protected executable integrity, and investigate unusual token use or SYSTEM child processes.

## 6. Exploiting outdated third-party software: Druva inSync

The room examines **Druva inSync 6.6.3**, whose privileged local RPC service listens on TCP **6064**. A vulnerable procedure accepts a command path and inadequately validates that it remains within the intended application directory.

The patch's string-prefix validation could be bypassed with parent-directory components (`..`), permitting a path to escape the approved folder and reach a Windows executable.

```text
C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe
```

The result is a local privilege escalation opportunity because the RPC service executes under SYSTEM. In the lab, the demonstration creates a new local account and adds it to the Administrators group.

**Important distinction:** A localhost-only listener is not inherently secure against code already running on the same host.

**Defensive view:** Keep third-party software patched, inventory privileged services, correlate unexpected service-to-`cmd.exe` process creation, and investigate new local administrator accounts.

## 7. Automated enumeration tools

| Tool | Usage | Limitation |
|---|---|---|
| [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) | Broad Windows enumeration | Large output; findings require validation |
| [PrivescCheck](https://github.com/itm4n/PrivescCheck) | PowerShell-based privilege checks | Script execution may be restricted or monitored |
| [WES-NG](https://github.com/bitsadmin/wesng) | Suggests vulnerabilities from `systeminfo` output | Potential version/patch matches are not proof of exploitability |
| Metasploit Local Exploit Suggester | Identifies candidate local exploits in an established test session | Results still require manual confirmation |

Example collection for WES-NG:

```cmd
systeminfo > systeminfo.txt
```

On the analysis machine:

```bash
wes.py --update
wes.py systeminfo.txt
```

**Lesson:** Automated enumeration produces leads, not a verified exploitation path. Cross-check output against actual ACLs, service configuration, OS versions and patch status.

## 8. SOC detection and hardening notes

Useful Windows and Sysmon events for investigating related behaviour:

| Event | Potential relevance |
|---|---|
| Security 4688 | Process creation, if auditing is enabled |
| Security 4698 / 4702 | Scheduled task creation / modification |
| Security 4720 | User account creation |
| Security 4732 | User added to a security-enabled local group |
| System 7045 | New Windows service installation |
| Sysmon 1 | Detailed process creation telemetry |
| Sysmon 13 | Registry value modifications, subject to configuration |

### Example Microsoft Defender XDR hunting query

The following is an **investigative starting point**, not a complete or production-ready detection rule:

```kql
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe", "net.exe", "net1.exe")
| where InitiatingProcessAccountName =~ "system"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

Investigate suspicious parent/child relationships, account-management commands executed by service processes, unusual executable locations, and whether activity is expected for the host.

### Hardening priorities

1. Remove excessive write access from privileged service binaries, directories and scheduled-task targets.
2. Review service DACLs and ensure only authorised administrators can reconfigure sensitive services.
3. Quote paths to service executables and avoid writable installation directories.
4. Reduce unnecessary token privileges and administrative group membership.
5. Eliminate plaintext credential exposure in scripts, histories and configuration files.
6. Patch and inventory third-party applications, not just Windows itself.
7. Maintain useful process, authentication, task and service-change telemetry.

## Key takeaways

- Privilege escalation often begins with **misconfigured access controls**, not advanced exploitation.
- `whoami /priv`, `sc.exe qc` and `icacls` are essential starting points.
- Exploitability depends on the full context: **who can write what, and which account executes it**.
- Privileged services and local-only interfaces still need strict trust boundaries.
- Offensive enumeration techniques are valuable to defenders for validation, threat hunting and root-cause analysis.

