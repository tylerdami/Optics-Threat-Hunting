# Optics-Threat-Hunting
Some threat hunting queries for Cylance Optics advanced query mode. 

[Cylance Official Advanced Query Mode Docs](https://docs.blackberry.com/en/unified-endpoint-security/blackberry-ues/administration/administration/Analyzing-endpoint-data-collected-by-Optics/Using-InstaQuery-and-advanced-query/Create-an-advanced-query)

## Windows General Threat Hunting
#### Services.exe launching scripting engine - https://car.mitre.org/analytics/CAR-2014-05-002/
```
process where process.name in~ ("cmd.exe", "powershell.exe","pwsh.exe","cscript.exe","wscript.exe") and process.parent.name like~ "services.exe"
```
#### Windows event logs cleared - https://car.mitre.org/analytics/CAR-2016-04-002/
```
process where process.command_line like~ "wevtutil* cl*"
```
#### Certutil used to encrypt or decrypt files - https://attack.mitre.org/techniques/T1140/
```
process where process.command_line in~("certutil* -encode*","certutil* -decode*")
```
#### BitsADMIN transfer or download. - https://attack.mitre.org/software/S0190/
```
process where process.name like~ "bitsadmin.exe" and process.command_line in~ ("*/Transfer*","*/Addfile*")
```
#### Command prompt used to disable Windows Firewall - https://attack.mitre.org/techniques/T1562/004/
```
process where process.command_line like~ "netsh* advfirewall* set* currentprofile* state* off*"
```
#### New Local User added or user added to administrators - https://attack.mitre.org/techniques/T1136/001/
```
process where process.command_line in~ ("*net user /add*","*New-LocalUser*","*net localgroup administrators*")
```
#### Visual basic script run via CMD. - https://attack.mitre.org/techniques/T1059/005/
```
process where process.name like~ "cmd.exe" and process.command_line like~ "*cscript*" 
```
### **Living off the Land**

#### LOLBAS all activity 
```
process where process.name in("bitsadmin.exe","csvde.exe","dsquery.exe","ftp.exe","makecab.exe","nbtstat.exe","net1.exe","netstat.exe","nslookup.exe","ping.exe","quser.exe","route.exe","schtasks.exe","taskkill.exe","tasklist.exe","whoami.exe","xcopy.exe","psexec.exe")
```
#### LOLBAS Making Network Connection
```
network where process.name in("bitsadmin.exe","csvde.exe","dsquery.exe","ftp.exe","makecab.exe","nbtstat.exe","net1.exe","netstat.exe","nslookup.exe","ping.exe","quser.exe","route.exe","schtasks.exe","taskkill.exe","tasklist.exe", "whoami.exe","xcopy.exe","psexec.exe") and event.type == "connect"
```
#### Exectuable running from C:\Windows\Temp
```
process where process.command_line like~ "C:\\Windows\\Temp\\*.exe"
```

#### AV and Security Product Enumeration
```
process where process.name == "wmic.exe" and process.command_line like~ "/Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List"
```
## Powershell 
#### Powershell Remoting Initiated - https://attack.mitre.org/techniques/T1021/006/
```
# Host based
scripting where powershell_trace.script_block like~ "New-PSSession -ComputerName*" or powershell_trace.script_block like~ "Enter-PsSession*"
# Network Based
network where network.destination.port in~("5986","5985")
```
#### PowerShell making network connection - https://attack.mitre.org/techniques/T1105/
```
network where process.name in("powershell.exe", "pwsh.exe") and event.type == "connect"
```
#### PowerShell Base64 Command - https://attack.mitre.org/techniques/T1027/
```
process where process.command_line regex~ ".*powershell.*[--]+[Ee^]{1,2}[NnCcOoDdEeMmAa^]+ [A-Za-z0-9+/=]{5,}"
```
#### PowerShell Base64 Inline Decode - https://attack.mitre.org/techniques/T1027/
```
scripting where powershell_trace.script_block regex~ ".*GetString.*Convert.::FromBase64String.*"
```
#### Powershell used to clear event logs - https://car.mitre.org/analytics/CAR-2016-04-002/
```
scripting where powershell_trace.script_block like~ "*Clear-EventLog*"
```

