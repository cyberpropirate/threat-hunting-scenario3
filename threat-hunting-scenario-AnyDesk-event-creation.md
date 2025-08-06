# Threat Event (Unauthorized AnyDesk Usage)
**Unauthorized Remote Access Tool - AnyDesk Usage**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the AnyDesk installer: https://download.anydesk.com/AnyDesk.exe
2. Install it silently: ```.\AnyDesk.exe --install "C:\Program Files (x86)\AnyDesk" --start-with-win```
3. Launched AnyDesk manually or via command line: `Start-Process "C:\Program Files (x86)\AnyDesk\AnyDesk.exe`
4. Connected to a remote host using AnyDesk

5. Created a file on Desktop named `anydesk-session-log.txt` containing a fake session ID to simulate evidence: `Session ID: 123-456-789  
Connected to: attacker-machine  
Duration: 15 minutes`


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect AnyDesk installer and session log files dropped on disk. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect AnyDesk installation or launch activity.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Detect outbound connections initiated by AnyDesk.|

---

## Related Queries:
```kql
// Detect AnyDesk installer file dropped
DeviceFileEvents
| where FileName has "AnyDesk.exe"

// Detect installation or execution of AnyDesk
DeviceProcessEvents
| where FileName == "AnyDesk.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine

// Detect outbound connections from AnyDesk
DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl

// Detect fake AnyDesk session log (simulation artifact)
DeviceFileEvents
| where FileName == "anydesk-session-log.txt"

```

---

## Created By:
- **Author Name**: Musie Berhe
- **Author Contact**:
- **Date**: August 6, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August  6, 2025`  | `Musie Berhe`   
