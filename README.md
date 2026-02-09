# Get-RWXandInjectedThread
Inspect a process and flag privately committed RWX memory regions; show hex + ASCII sample; Pops balloon tip notification when suspicious thread is flagged.
default filter/scan is for MZ (4d 5a) yet can be any pattern you specify.<br><br>
Example syntax:
```
.\Get-RWXandInjectedThread.ps1 -ProcessID 1189 -StringToLookFor 'MZ'
```
