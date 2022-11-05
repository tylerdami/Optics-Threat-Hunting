# Optics-Threat-Hunting
Some threat hunting queries for Cylance Optics advanced query mode. Cylance Official Advanced Query Mode Docs [Here](https://docs.blackberry.com/en/unified-endpoint-security/blackberry-ues/administration/administration/Analyzing-endpoint-data-collected-by-Optics/Using-InstaQuery-and-advanced-query/Create-an-advanced-query)

## Powershell 
### Powershell Remoting Initiated 
```
scripting where powershell_trace.script_block like~ "New-PSSession -ComputerName*" or powershell_trace.script_block like~ "Enter-PsSession*"
```
### PowerShell making network connection
```
network where process.name in("powershell.exe", "pwsh.exe") and event.type == "connect"
```
### PowerShell Base64 Command
```
process where process.command_line regex~ ".*powershell.*[--]+[Ee^]{1,2}[NnCcOoDdEeMmAa^]{5,}"
```
### PowerShell Base64 Inline Decode
```
process where process.command_line regex~ ".*GetString.*Convert.::FromBase64String.*"
```

## Living off the Land

### LOLBAS all activity 
```
process where process.name in("bitsadmin.exe","csvde.exe","dsquery.exe","ftp.exe","makecab.exe","nbtstat.exe","net1.exe","netstat.exe","nslookup.exe","ping.exe","quser.exe","route.exe","schtasks.exe","taskkill.exe","tasklist.exe","whoami.exe","xcopy.exe","psexec.exe")
```
### LOLBAS Making Network Connection
```
network where process.name in("bitsadmin.exe","csvde.exe","dsquery.exe","ftp.exe","makecab.exe","nbtstat.exe","net1.exe","netstat.exe","nslookup.exe","ping.exe","quser.exe","route.exe","schtasks.exe","taskkill.exe","tasklist.exe", "whoami.exe","xcopy.exe","psexec.exe") and event.type == "connect"
```
### Exectuable running from C:\Windows\Temp
```
process where process.command_line like~ "C:\\Windows\\Temp\\*.exe"
```

### AV and Security Product Enumeration
```
process where process.name == "wmic.exe" and process.command_line like~ "/Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List"
```
