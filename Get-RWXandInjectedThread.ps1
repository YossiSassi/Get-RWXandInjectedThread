<#
.SYNOPSIS
    Inspect a process and flag privately committed RWX memory regions; show hex + ASCII sample.

.NOTES
    Run elevated. 64-bit PowerShell required to inspect 64-bit processes.
    Comments yossis@protonmail.com
    v1.0
#>

param(
    [Parameter(Mandatory=$true)][int]$ProcessID,
    [string]$StringToLookFor = 'MZ',
    [int]$ReadBytes = 256
)

# Win32 interop declarations
$signature = @'
using System;
using System.Runtime.InteropServices;

public static class NativeMethods {
    [Flags]
    public enum ProcessAccessFlags : uint {
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_VM_READ = 0x0010
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);
}
'@

Add-Type -TypeDefinition $signature -PassThru | Out-Null

# constants
$MEM_COMMIT   = 0x1000
$MEM_PRIVATE  = 0x20000

# protection flags (common)
$PAGE_NOACCESS          = 0x01
$PAGE_READONLY          = 0x02
$PAGE_READWRITE         = 0x04
$PAGE_WRITECOPY         = 0x08
$PAGE_EXECUTE           = 0x10
$PAGE_EXECUTE_READ      = 0x20
$PAGE_EXECUTE_READWRITE = 0x40
$PAGE_EXECUTE_WRITECOPY = 0x80
$PAGE_GUARD             = 0x100
$PAGE_NOCACHE           = 0x200
$PAGE_WRITECOMBINE      = 0x400

function Format-HexAscii {
    param([byte[]]$data, [int]$bytesPerLine = 16)
    $sb = New-Object System.Text.StringBuilder
    for ($i=0; $i -lt $data.Length; $i += $bytesPerLine) {
        $line = $data[$i..([Math]::Min($i+$bytesPerLine-1, $data.Length-1))]
        $hex = ($line | ForEach-Object { $_.ToString("x2") }) -join ' '
        $ascii = ($line | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join ''
        $sb.AppendLine(("0x{0:x8}: {1,-48}  {2}" -f $i, $hex, $ascii)) | Out-Null
    }
    return $sb.ToString()
}

# sanity checks
try {
    $proc = Get-Process -Id $ProcessID -ErrorAction Stop
} catch {
    Write-Error "Process with PID $ProcessID not found, or lack of permissions."
    return
}

# convert string to look for (default = MZ) to Hex bytes
$StringToLookFor | Format-Hex | select -ExpandProperty bytes | foreach { $HexToLookFor += "$([convert]::ToString($_,16)) "}

# warn about bitness mismatch
$psBit = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
Write-Host "`nPowerShell host: $psBit. Target PID $ProcessID - $($proc.ProcessName)" -ForegroundColor Cyan

# open process
$access = [uint32]([NativeMethods+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION) -bor [uint32]([NativeMethods+ProcessAccessFlags]::PROCESS_VM_READ)
$hProc = [NativeMethods]::OpenProcess($access, $false, [uint32]$ProcessID)
if ($hProc -eq [IntPtr]::Zero) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "OpenProcess failed (error $err). Try running elevated / with SeDebugPrivilege."
    return
}

Write-Host "Opened process $($proc.ProcessName) (PID $ProcessID). Enumerating memory..." -ForegroundColor Green

# iterate memory
$addr = [UIntPtr]::Zero
$maxAddress = if ([Environment]::Is64BitOperatingSystem) { [uint64]0x7FFFFFFFFFFFFFFF } else { [uint64]0x7FFFFFFF }

$found = $false
try {
    while ($true) {
        # Create an instance and get its size via Marshal.SizeOf(instance)
        $mbi = New-Object NativeMethods+MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
        $mbiSizePtr = [UIntPtr]::op_Explicit([uint64]$mbiSize)

        $ret = [NativeMethods]::VirtualQueryEx($hProc, $addr, [ref]$mbi, $mbiSizePtr)
        if ($ret -eq [UIntPtr]::Zero) { break }

        $basePtr = $mbi.BaseAddress
        $base = $basePtr.ToUInt64()
        $regionSize = $mbi.RegionSize.ToUInt64()
        $state = $mbi.State
        $type  = $mbi.Type
        $protect = $mbi.Protect

        # flag to detect: committed, private, and RWX (PAGE_EXECUTE_READWRITE)
        if (($state -band $MEM_COMMIT) -ne 0 -and ($type -band $MEM_PRIVATE) -ne 0 -and (($protect -band $PAGE_EXECUTE_READWRITE) -ne 0)) {
            $found = $true
            Write-Host "=== Suspicious RWX region detected ===" -ForegroundColor Red
            Write-Host ("BaseAddress : 0x{0:x16}" -f $base)
            Write-Host ("RegionSize  : {0} bytes" -f $regionSize)
            Write-Host ("Protect     : 0x{0:x} ({1})" -f $protect, "PAGE_EXECUTE_READWRITE")
            Write-Host ("State       : 0x{0:x}" -f $state)
            Write-Host ("Type        : 0x{0:x}" -f $type)

            # read a chunk (min of ReadBytes and region size)
            $toRead = [int][Math]::Min($ReadBytes, [int64]$regionSize)
            if ($toRead -gt 0) {
                $buf = New-Object byte[] $toRead
                $bytesRead = [UIntPtr]::Zero

                $baseUIntPtr = [UIntPtr]::op_Explicit([uint64]$base)
                $toReadPtr   = [UIntPtr]::op_Explicit([uint64]$toRead)

                $ok = [NativeMethods]::ReadProcessMemory($hProc, $baseUIntPtr, $buf, $toReadPtr, [ref]$bytesRead)
                if ($ok) {
                    $actual = $bytesRead.ToUInt64()
                    Write-Host ("Read {0} bytes from region start." -f $actual)
                    $sample = if ($actual -gt 0) { $buf[0..([int]$actual-1)] } else { @() }
                    $hexAscii = Format-HexAscii -data $sample -bytesPerLine 16
                    # Check for MZ (PE/Executable) in memory - highly suspicious, or any other ascii chars
                    if ($hexAscii -like "*$HexToLookFor*") {
                            Write-Host "[!] Suspicious region with '$StringToLookFor' detected [!]" -ForegroundColor Red;
                            # pop-up message
                            #Add-Type -AssemblyName Microsoft.VisualBasic;
                            #[Microsoft.VisualBasic.Interaction]::MsgBox("Process $($proc.ProcessName.ToUpper()) (PID $ProcessID) contains Private-Commit-RWX (PAGE_EXECUTE_READWRITE) region in memory, with MZ ascii", 'Exclamation,MsgBoxSetForeground,Critical', 'Suspicious MZ chars detected') | Out-Null
                            
                            # finally went with balloon tip notification, since msgbox waits for user to click it before continuing, and toast notification take too much code/xml :)
                            Add-Type -AssemblyName System.Windows.Forms;
                            $global:balloonMsg = New-Object System.Windows.Forms.NotifyIcon;
                            $path = (Get-Process -id $pid).Path;
                            $balloonMsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path);
                            $balloonMsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning;
                            $balloonMsg.BalloonTipText = "Process $($proc.ProcessName.ToUpper()) (PID $ProcessID) contains Private-Commit-RWX (PAGE_EXECUTE_READWRITE) region in memory, with $StringToLookFor in ascii";
                            $balloonMsg.BalloonTipTitle = "Suspicious region with $StringToLookFor chars detected";
                            $balloonMsg.Visible = $true;
                            $balloonMsg.ShowBalloonTip(30000)
                        }
                    Write-Host $hexAscii
                } else {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Warning "ReadProcessMemory failed (error $err)."
                }
            }
        }

        # advance address: next = base + regionSize
        $next = $base + $regionSize
        if ($next -ge $maxAddress) { break }

        $addr = [UIntPtr]::op_Explicit([uint64]$next)
    }
}
finally {
    [NativeMethods]::CloseHandle($hProc) | Out-Null
}

if (-not $found) {
    Write-Host "No private committed RWX regions (PAGE_EXECUTE_READWRITE) found for PID $ProcessID." -ForegroundColor Green
} else {
    Write-Host "Scan complete. Flagged RWX regions were printed above." -ForegroundColor Yellow
}