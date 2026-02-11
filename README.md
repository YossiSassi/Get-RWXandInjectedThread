# Get-RWXandInjectedThread
Inspect a process and flag privately committed RWX memory regions; show hex + ASCII sample; Pops balloon tip notification when suspicious thread is flagged.
default filter/scan is for MZ (4d 5a) yet can be any pattern you specify.<br><br>
Example syntax:
```
.\Get-RWXandInjectedThread.ps1 -ProcessID 1189 -StringToLookFor 'MZ'
```
Scan all processes:
```
ps | foreach { .\Get-RWXandInjectedThread.ps1 -ProcessID $_.id}
```
### Windows Memory Threat Analysis ###
For a more robust scan with threat analysis & a detailed html findings report, check out [https://github.com/YossiSassi/WindowsMemoryThreatAnalysis](https://github.com/YossiSassi/WindowsMemoryThreatAnalysis)
