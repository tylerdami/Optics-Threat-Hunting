# Optics-Threat-Hunting
Some threat hunting utilities for Cylance Optics. 

## Powershell Stuff
### Powershell Remoting Initiated 
```
scripting where powershell_trace.script_block like~ "New-PSSession -ComputerName*" or powershell_trace.script_block like~ "Enter-PsSession*"
```
