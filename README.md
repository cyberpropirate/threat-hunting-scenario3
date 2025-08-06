# threat-hunting-scenario3
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="1280" height="576" alt="image" src="https://github.com/user-attachments/assets/50864ba8-6c1f-4767-a029-6f1a1ff7dad0" />


# Threat Hunt Report: Unauthorized Remote Access Tool AnyDesk Usage
- [Scenario Creation](https://github.com/cyberpropirate/threat-hunting-scenario3/blob/main/threat-hunting-scenario-AnyDesk-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- AnyDesk Remote Access Tool

##  Scenario

Following an internal audit, IT management expressed concern over the possibility of employees using unauthorized remote access tools to connect to corporate machines from external locations. This concern was prompted by a recent security bulletin describing attackers leveraging tools like AnyDesk and TeamViewer for stealthy lateral movement and remote persistence. The goal was to identify installation, execution, network communication, and any file artifacts related to AnyDesk activity.

### High-Level AnyDesk Discovery Plan

- **Check `DeviceFileEvents`** for dropped AnyDesk installer files and suspicous documents.
- **Check `DeviceProcessEvents`** for any signs of AnyDesk execution or silent install attempts.
- **Check `DeviceNetworkEvents`** for outbound connections made by AnyDesk.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for the presence of the AnyDesk installer `AnyDesk.exe` and found that user ecorp downloaded the file to the downloads folder at `2025-08-06T16:40:05.880837Z`. Later, a session note file `anydesk-session-log.txt` was also created on the desk top. 


**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName in ("AnyDesk.exe", "anydesk-session-log.txt")
| where DeviceName == "accesskeymb"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName

```
<img width="2383" height="1391" alt="{881BF058-6928-45CD-AF1F-CFBF47C6B07B}" src="https://github.com/user-attachments/assets/e6fd2195-3e26-4c35-ab7c-3c8a42f70441" />


---

### 2. Searched the `DeviceProcessEvents` Table

Evidence showed that the user ran `AnyDesk.exe` from the downloads folder at `2025-08-06T16:49:30.4966935Z`. AnyDesk was then launched again from `C:\Program Files (x86)\AnyDesk\AnyDesk.exe` indicating a likely install or reuse attempt.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where FileName == "AnyDesk.exe"
| where DeviceName == "accesskeymb"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath

```
<img width="2773" height="1416" alt="{9D21CF19-E727-4DEE-B4B4-D289D7D30B7F}" src="https://github.com/user-attachments/assets/f218702d-5572-445d-b49e-03ee974a4382" />


---



### 3. Searched the `DeviceNetworkEvents` Table 

Connections from the `AnyDesk.exe` to known AnyDesk infrastructure were observed. At `2025-08-06T16:49:42.9181899Z`, an outbound connection to IP `141.95.145.210` over `port 443` was made by `AnyDesk.exe`


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("anydesk", "relay.anydesk.com")
| where DeviceName == "accesskeymb"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl

```
<img width="2737" height="1443" alt="{9A734962-C821-441D-B629-ECA51112C403}" src="https://github.com/user-attachments/assets/cfea8e0d-c5c4-45e6-9db7-4790bdc78134" />


---

## Chronological Event Timeline 

### 1. File Download - AnyDesk Installer

- **Timestamp:** `2025-08-06T16:40:05.880837Z`
- **Event:** The user "ecorp" downloaded the AnyDesk installer file `AnyDesk.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ecorp\Downloads\AnyDesk.exe`

### 2. Process Execution - AnyDesk Launched from Downloads

- **Timestamp:** `2025-08-06T16:49:30.4966935Z`
- **Event:** The user "ecorp" executed `AnyDesk.exe` from the Downloads folder, launching the application manually.
- **Action:** Process execution detected.
- **File Path:** `C:\Users\ecorp\Downloads\AnyDesk.exe`


### 3. Network Connection - Outbound to AnyDesk Infrastructure

- **Timestamp:** `2025-08-06T16:49:42.9181899Z`
- **Event:** `AnyDesk.exe` initiated a network connection to IP `141.95.145.210` over port `443`, associated with the known AnyDesk infrastructure.
- **Action:** Outbound network connection detected.
- **Process:** `AnyDesk.exe`
- **Remote URL:** `relay.anydesk.com`
- **Remote IP:** 141.95.145.210
- **Remote Port:** `443`


### 4. File Creation - Session Log created
- **TimeStamp:** `2025-08-06T16:52:41.606735Z`
- **Event:** A file named `anydesk-session-log.txt` was created on the desktop, potentially stimulating session tracking or logging.
- **Action:** File creation detected
- **File Path:** `C:\Users\ecorp\Desktop\anydesk-session-log.txt`



---

## Summary

The user "ecorp" on the "accesskeymb" device downloaded and executed the remote access tool AnyDesk. The program was launched multiple times and connected to known AnyDesk servers over port `443`. A file was created on the desktop titled `anydesk-session-log.txt`, potentially used to document or simulate a session. This activity matches patterns associated with unauthorized remote access tool usage, which could be used for off-network control, data exfiltration, or insider threat behavior.



---

## Response Taken

Unauthorized use of AnyDesk was confirmed on the "accesskeymb" device by user "ecorp". The device was isolated, AnyDesk was uninstalled, and the user’s access was restricted pending review. A full report was sent to the security lead and HR for further investigation. Alerts were added to Microsoft Defender to flag future AnyDesk executions.

---
