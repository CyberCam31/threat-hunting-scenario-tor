<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/CyberCam31/threat-hunting-scenario-tor/blob/main/threat-hunting-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-05-11T18:09:33.880146Z`. These events began at `2026-05-11T18:58:52.7388868Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "cam-fp-th-win11"
| where InitiatingProcessAccountName == "ncobcam"
| where Timestamp >= datetime(2026-05-11T18:58:52.7388868Z)
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1190" height="459" alt="image" src="https://github.com/user-attachments/assets/f100d3cf-174d-4798-8d58-bb1f7e66da2a" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "Tor-browser-windows-x86_64-portable-15.0.13.exe". Based on the logs returned, at `2026-05-11T19:00:37.1001923Z`, an employee on the "cam-fp-th-win11" device ran the file `Tor-browser-windows-x86_64-portable-15.0.13.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "cam-fp-th-win11"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.13.exe"
| project Timestamp, DeviceName, ActionType, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1319" height="227" alt="image" src="https://github.com/user-attachments/assets/ebcc8724-d92d-4b58-bf87-6cb2ef012419" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "ncobcam" actually opened the TOR browser. There was evidence that they did open it at `2026-05-11T19:02:34.2787943Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cam-fp-th-win11"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1310" height="458" alt="image" src="https://github.com/user-attachments/assets/c9507a3d-987d-46dc-abff-eff802f2709f" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-05-11T19:02:53.0560975Z`, an employee on the "cam-fp-th-win11" device successfully established a connection to the remote IP address `107.208.159.58` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\ncobcam\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "cam-fp-th-win11"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1313" height="456" alt="image" src="https://github.com/user-attachments/assets/afd9c28f-5043-4558-a5ac-f6a346cf0d0a" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-11T18:58:52.7388868Z`
- **Event:** The user "employee" downloaded a file named `Tor-browser-windows-x86_64-portable-15.0.13.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `c:\users\ncobcam\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-11T19:00:37.1001923Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.13.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.13.exe /S`
- **File Path:** `c:\users\ncobcam\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-11T19:02:34.2787943Z`
- **Event:** User "ncobcam" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\ncobcam\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-11T19:02:53.0560975Z`
- **Event:** A network connection to IP `107.208.159.58` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ncobcam\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-05-11T19:08:33.4753099Z` - Connected to `192.42.116.155` on port `443`.
  - `2026-05-11T19:03:17.1964394Za` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-11T19:16:42.647923Z`
- **Event:** The user "ncobcam" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\NCOBCam\Desktop\tor-shopping-list.txt\tor-shopping-list.txt.txt`

---

## Summary

The user "ncobcam" on the "cam-fp-th-win11" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `cam-fp-th-win11` by the user `ncobcam`. The device was isolated, and the user's direct manager was notified.

---
