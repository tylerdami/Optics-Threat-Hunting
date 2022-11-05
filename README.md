# Optics-Threat-Hunting
Some threat hunting utilities for Cylance Optics. 

## Powershell Stuff
### Powershell Remoting Initiated 
```
scripting where powershell_trace.script_block like~ "New-PSSession -ComputerName*" or powershell_trace.script_block like~ "Enter-PsSession*"
```
### PowerShell making network connection
```
network where process.name in("powershell.exe", "pwsh.exe") and event.type == "connect"
```
## Living off the Land

### LOLBAS all activity 
```
process where process.name in("bitsadmin.exe","csvde.exe","dsquery.exe","ftp.exe","makecab.exe","nbtstat.exe","net1.exe","netstat.exe","nslookup.exe","ping.exe","quser.exe","route.exe","schtasks.exe","taskkill.exe","tasklist.exe","whoami.exe","xcopy.exe","psexec.exe")
```
## LOLBAS Making Network Connection
```
network where process.name in("bitsadmin.exe","csvde.exe","dsquery.exe","ftp.exe","makecab.exe","nbtstat.exe","net1.exe","netstat.exe","nslookup.exe","ping.exe","quser.exe","route.exe","schtasks.exe","taskkill.exe","tasklist.exe", "whoami.exe","xcopy.exe","psexec.exe") and event.type == "connect"
```
