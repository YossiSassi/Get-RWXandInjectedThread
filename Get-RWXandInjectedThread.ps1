<#
.SYNOPSIS
    Inspect a process for privately committed RWX memory regions, injected threads,
    and suspicious byte patterns. Emits structured objects for automation/SIEM.

.DESCRIPTION
    v1.1 - Addresses all 10 issues from the v1.0 audit:
      Phase 1 - Bug fixes:
        1.1  Direct byte-array search replaces fragile Format-Hex + -like pipeline
        1.2  $HexToLookFor accumulation bug eliminated (variable removed)
        1.3  Default scan depth increased from 256 to 4096 bytes; -FullRegionScan switch added
      Phase 2 - Detection upgrades:
        2.1  PAGE_EXECUTE_WRITECOPY (0x80) now detected alongside PAGE_EXECUTE_READWRITE (0x40)
        2.2  Thread start-address analysis via NtQueryInformationThread flags injected threads
        2.3  Shannon entropy per region distinguishes packed/encrypted shellcode from benign allocations
      Phase 3 - Performance:
        3.1  Format-HexAscii rewritten with BitConverter + for-loop (10-50x faster)
        3.2  Balloon notification created once outside scan loop; disposed in finally block
      Phase 4 - Structured output:
        4.1  Each finding emitted as [PSCustomObject]; Write-Verbose for interactive detail

.PARAMETER ProcessID
    Target process ID to inspect.

.PARAMETER StringToLookFor
    ASCII string to search for in RWX regions (default: 'MZ' for PE headers).

.PARAMETER ReadBytes
    Number of bytes to read from each RWX region (default: 4096).

.PARAMETER FullRegionScan
    Read entire region instead of just ReadBytes (capped at 10 MB).

.PARAMETER EntropyThreshold
    Shannon entropy value (0.0-8.0) above which a region is flagged as high entropy (default: 6.0).

.EXAMPLE
    .\Get-RWXandInjectedThread2.ps1 -ProcessID 1234
    Scans PID 1234, emits PSCustomObject results to pipeline.

.EXAMPLE
    .\Get-RWXandInjectedThread2.ps1 -ProcessID 1234 -Verbose | ConvertTo-Json
    Full verbose output plus structured JSON for SIEM ingestion.

.EXAMPLE
    .\Get-RWXandInjectedThread2.ps1 -ProcessID 1234 -FullRegionScan -EntropyThreshold 5.5
    Deep scan with lower entropy sensitivity.

.NOTES
    Run elevated. 64-bit PowerShell required to inspect 64-bit processes.
    Original author: yossis@protonmail.com (v1.0)
    v1.1 rewrite per implementation plan.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][int]$ProcessID,
    [string]$StringToLookFor = 'MZ',
    [int]$ReadBytes = 4096,
    [switch]$FullRegionScan,
    [double]$EntropyThreshold = 6.0
)

# ─────────────────────────────────────────────────────────────────────────────
# Win32 / NT interop declarations
# ─────────────────────────────────────────────────────────────────────────────
$signature = @'
using System;
using System.Runtime.InteropServices;

public static class NativeMethods2 {

    // ── Access flags ──
    [Flags]
    public enum ProcessAccessFlags : uint {
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_VM_READ           = 0x0010
    }

    // ── Structs ──
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint    AllocationProtect;
        public UIntPtr RegionSize;
        public uint    State;
        public uint    Protect;
        public uint    Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32 {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int  tpBasePri;
        public int  tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO {
        public IntPtr lpBaseOfDll;
        public uint   SizeOfImage;
        public IntPtr EntryPoint;
    }

    // ── kernel32: Process & Memory ──
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress,
        byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    // ── kernel32: Thread enumeration ──
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    // ── ntdll: Thread info ──
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(
        IntPtr threadHandle, int threadInformationClass,
        ref IntPtr threadInformation, int threadInformationLength, IntPtr returnLength);

    // ── psapi: Module enumeration ──
    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool EnumProcessModulesEx(
        IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool GetModuleInformation(
        IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);
}
'@

try {
    Add-Type -TypeDefinition $signature -PassThru | Out-Null
} catch {
    # Type may already be loaded from a previous run in the same session
    if ($_.Exception.Message -notlike '*already exists*' -and
        $_.Exception -isnot [System.Reflection.ReflectionTypeLoadException]) { throw }
}

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
$MEM_COMMIT                = 0x1000
$MEM_PRIVATE               = 0x20000
$PAGE_EXECUTE_READWRITE    = 0x40
$PAGE_EXECUTE_WRITECOPY    = 0x80          # Phase 2.1
$RWX_MASK                  = $PAGE_EXECUTE_READWRITE -bor $PAGE_EXECUTE_WRITECOPY
$TH32CS_SNAPTHREAD         = 0x00000004
$THREAD_QUERY_INFORMATION  = 0x0040
$LIST_MODULES_ALL          = 0x03
$MAX_REGION_READ           = 10 * 1024 * 1024   # 10 MB cap for -FullRegionScan

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

# Phase 1.1: Direct byte-array subsequence search (replaces Format-Hex + -like)
function Find-ByteSequence {
    param([byte[]]$Data, [byte[]]$Pattern)
    if ($Pattern.Length -eq 0 -or $Data.Length -lt $Pattern.Length) { return $false }
    $limit = $Data.Length - $Pattern.Length
    for ($i = 0; $i -le $limit; $i++) {
        if ($Data[$i] -ne $Pattern[0]) { continue }
        $match = $true
        for ($j = 1; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) { return $true }
    }
    return $false
}

# Phase 2.3: Shannon entropy calculation
function Get-ShannonEntropy {
    param([byte[]]$Data)
    if ($null -eq $Data -or $Data.Length -eq 0) { return 0.0 }
    $freq = New-Object int[] 256
    foreach ($b in $Data) { $freq[$b]++ }
    $entropy = 0.0
    $len = [double]$Data.Length
    for ($i = 0; $i -lt 256; $i++) {
        if ($freq[$i] -eq 0) { continue }
        $p = $freq[$i] / $len
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 4)
}

# Phase 3.1: Optimized hex+ASCII formatter (BitConverter + for-loop)
function Format-HexAscii {
    param([byte[]]$Data, [int]$BytesPerLine = 16)
    if ($null -eq $Data -or $Data.Length -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder (($Data.Length / $BytesPerLine + 1) * 80)
    for ($i = 0; $i -lt $Data.Length; $i += $BytesPerLine) {
        $end = [Math]::Min($i + $BytesPerLine - 1, $Data.Length - 1)
        $lineLen = $end - $i + 1
        $lineBytes = $Data[$i..$end]

        # Hex via BitConverter (avoids per-byte pipeline)
        $hex = [System.BitConverter]::ToString($lineBytes).Replace('-', ' ').ToLower()

        # ASCII via for-loop
        $asciiSb = New-Object System.Text.StringBuilder $lineLen
        for ($j = 0; $j -lt $lineLen; $j++) {
            $b = $lineBytes[$j]
            if ($b -ge 32 -and $b -le 126) { [void]$asciiSb.Append([char]$b) }
            else { [void]$asciiSb.Append('.') }
        }

        [void]$sb.AppendLine(("0x{0:x8}: {1,-48}  {2}" -f $i, $hex, $asciiSb.ToString()))
    }
    return $sb.ToString()
}

# Dynamic protection-flag name resolver (Phase 2.1 support)
function Get-ProtectionName {
    param([uint32]$Protect)
    $names = @()
    $base = $Protect -band 0xFF
    switch ($base) {
        0x01 { $names += 'PAGE_NOACCESS' }
        0x02 { $names += 'PAGE_READONLY' }
        0x04 { $names += 'PAGE_READWRITE' }
        0x08 { $names += 'PAGE_WRITECOPY' }
        0x10 { $names += 'PAGE_EXECUTE' }
        0x20 { $names += 'PAGE_EXECUTE_READ' }
        0x40 { $names += 'PAGE_EXECUTE_READWRITE' }
        0x80 { $names += 'PAGE_EXECUTE_WRITECOPY' }
    }
    if ($Protect -band 0x100) { $names += 'PAGE_GUARD' }
    if ($Protect -band 0x200) { $names += 'PAGE_NOCACHE' }
    if ($Protect -band 0x400) { $names += 'PAGE_WRITECOMBINE' }
    if ($names.Count -eq 0) { return ("UNKNOWN(0x{0:x})" -f $Protect) }
    return ($names -join ' | ')
}

# ─────────────────────────────────────────────────────────────────────────────
# Main logic
# ─────────────────────────────────────────────────────────────────────────────

# Validate target process
try {
    $proc = Get-Process -Id $ProcessID -ErrorAction Stop
} catch {
    Write-Error "Process with PID $ProcessID not found, or lack of permissions."
    return
}

# Phase 1.1: Convert search string directly to byte array
$searchBytes = [System.Text.Encoding]::ASCII.GetBytes($StringToLookFor)

# Bitness info
$psBit = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
Write-Verbose ("PowerShell host: {0}. Target PID {1} - {2}" -f $psBit, $ProcessID, $proc.ProcessName)

# Open process handle
$access = [uint32]([NativeMethods2+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION) -bor `
           [uint32]([NativeMethods2+ProcessAccessFlags]::PROCESS_VM_READ)
$hProc  = [NativeMethods2]::OpenProcess($access, $false, [uint32]$ProcessID)
if ($hProc -eq [IntPtr]::Zero) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "OpenProcess failed (error $err). Try running elevated / with SeDebugPrivilege."
    return
}

Write-Verbose "Opened process $($proc.ProcessName) (PID $ProcessID). Scanning memory..."

# Phase 3.2: Create balloon notification ONCE before scan loop
$balloonMsg = $null
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $balloonMsg = New-Object System.Windows.Forms.NotifyIcon
    $selfPath = (Get-Process -Id $PID).Path
    $balloonMsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($selfPath)
    $balloonMsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $balloonMsg.Visible = $true
} catch {
    Write-Verbose "Balloon notifications unavailable (non-GUI or headless session)."
}

# Storage for scan results
$regionData   = @()   # Hashtables - converted to PSCustomObject at emit time
$rwxRegions   = @()   # Lightweight list for thread-analysis lookups

$addr       = [UIntPtr]::Zero
$maxAddress = if ([Environment]::Is64BitOperatingSystem) { [uint64]0x7FFFFFFFFFFFFFFF } else { [uint64]0x7FFFFFFF }

try {
    # ── Pass 1: Enumerate memory regions ────────────────────────────────────
    while ($true) {
        $mbi     = New-Object NativeMethods2+MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
        $ret     = [NativeMethods2]::VirtualQueryEx(
                        $hProc, $addr, [ref]$mbi,
                        [UIntPtr]::op_Explicit([uint64]$mbiSize))
        if ($ret -eq [UIntPtr]::Zero) { break }

        $base       = $mbi.BaseAddress.ToUInt64()
        $regionSize = $mbi.RegionSize.ToUInt64()
        $state      = $mbi.State
        $type       = $mbi.Type
        $protect    = $mbi.Protect

        # Phase 2.1: detect both PAGE_EXECUTE_READWRITE (0x40) and PAGE_EXECUTE_WRITECOPY (0x80)
        $isRwx = (($state   -band $MEM_COMMIT)  -ne 0) -and
                 (($type    -band $MEM_PRIVATE)  -ne 0) -and
                 (($protect -band $RWX_MASK)     -ne 0)

        if ($isRwx) {
            $protName = Get-ProtectionName $protect
            $rwxRegions += [PSCustomObject]@{ Base = $base; Size = $regionSize; Protect = $protect }

            Write-Verbose "=== Suspicious RWX region ==="
            Write-Verbose ("  BaseAddress : 0x{0:x16}" -f $base)
            Write-Verbose ("  RegionSize  : {0} bytes"  -f $regionSize)
            Write-Verbose ("  Protect     : 0x{0:x} ({1})" -f $protect, $protName)
            Write-Verbose ("  State       : 0x{0:x}" -f $state)
            Write-Verbose ("  Type        : 0x{0:x}" -f $type)

            # Phase 1.3: read up to 4096 bytes by default, or full region with -FullRegionScan
            $toRead = if ($FullRegionScan) {
                [int][Math]::Min([long]$regionSize, $MAX_REGION_READ)
            } else {
                [int][Math]::Min([long]$ReadBytes, [long]$regionSize)
            }

            $containsSearchString = $false
            $entropy      = 0.0
            $entropyLevel = 'N/A'
            $hexDump      = ''

            if ($toRead -gt 0) {
                $buf       = New-Object byte[] $toRead
                $bytesRead = [UIntPtr]::Zero
                $ok = [NativeMethods2]::ReadProcessMemory(
                        $hProc,
                        [UIntPtr]::op_Explicit([uint64]$base),
                        $buf,
                        [UIntPtr]::op_Explicit([uint64]$toRead),
                        [ref]$bytesRead)

                if ($ok) {
                    $actual = [int]$bytesRead.ToUInt64()
                    Write-Verbose ("  Read {0} bytes from region start." -f $actual)

                    if ($actual -gt 0) {
                        $sample = if ($actual -eq $toRead) { $buf } else { $buf[0..($actual - 1)] }

                        # Phase 1.1: direct byte-array search
                        $containsSearchString = Find-ByteSequence -Data $sample -Pattern $searchBytes

                        # Phase 2.3: entropy analysis
                        $entropy      = Get-ShannonEntropy -Data $sample
                        $entropyLevel = if ($entropy -ge $EntropyThreshold) { 'High' }
                                        elseif ($entropy -ge 3.0)           { 'Medium' }
                                        else                                { 'Low' }

                        # Phase 3.1: optimized hex dump
                        $hexDump = Format-HexAscii -Data $sample -BytesPerLine 16

                        if ($containsSearchString) {
                            Write-Verbose "  [!] Region contains '$StringToLookFor' [!]"
                        }
                        Write-Verbose ("  Entropy: {0:F4} ({1})" -f $entropy, $entropyLevel)
                        Write-Verbose $hexDump
                    }
                } else {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Warning ("ReadProcessMemory failed at 0x{0:x16} (error {1})." -f $base, $err)
                }
            }

            # Collect finding (hashtable; threads added in pass 2, emitted as PSCustomObject later)
            $regionData += [ordered]@{
                FindingType          = 'RwxRegion'
                ProcessName          = $proc.ProcessName
                ProcessId            = $ProcessID
                BaseAddress          = "0x{0:x16}" -f $base
                RegionSize           = $regionSize
                Protection           = "0x{0:x}" -f $protect
                ProtectionName       = $protName
                State                = "0x{0:x}" -f $state
                Type                 = "0x{0:x}" -f $type
                ContainsSearchString = $containsSearchString
                SearchString         = $StringToLookFor
                Entropy              = $entropy
                EntropyLevel         = $entropyLevel
                SuspiciousThreads    = @()
                HexDump              = $hexDump
                Timestamp            = (Get-Date -Format 'o')
            }
        }

        # Advance to next region
        $next = $base + $regionSize
        if ($next -ge $maxAddress) { break }
        $addr = [UIntPtr]::op_Explicit([uint64]$next)
    }

    # ── Pass 2: Thread start-address analysis (Phase 2.2) ──────────────────
    Write-Verbose "Enumerating threads for injected-thread detection..."

    # Build module-range table
    $moduleRanges = @()
    $cbNeeded   = [uint32]0
    $maxModules = 1024
    $modules    = New-Object IntPtr[] $maxModules
    $cb         = [uint32]($maxModules * [IntPtr]::Size)

    if ([NativeMethods2]::EnumProcessModulesEx($hProc, $modules, $cb, [ref]$cbNeeded, $LIST_MODULES_ALL)) {
        $moduleCount = [int]($cbNeeded / [IntPtr]::Size)
        for ($m = 0; $m -lt $moduleCount; $m++) {
            if ($modules[$m] -eq [IntPtr]::Zero) { continue }
            $modInfo     = New-Object NativeMethods2+MODULEINFO
            $modInfoSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($modInfo)
            if ([NativeMethods2]::GetModuleInformation($hProc, $modules[$m], [ref]$modInfo, $modInfoSize)) {
                $moduleRanges += [PSCustomObject]@{
                    Base = $modInfo.lpBaseOfDll.ToInt64()
                    Size = [uint64]$modInfo.SizeOfImage
                }
            }
        }
    }
    Write-Verbose "  Loaded $($moduleRanges.Count) module range(s) for thread analysis."

    # Enumerate threads via Toolhelp32
    $hSnap = [NativeMethods2]::CreateToolhelp32Snapshot($TH32CS_SNAPTHREAD, 0)
    if ($hSnap.ToInt64() -ne -1) {
        try {
            $te        = New-Object NativeMethods2+THREADENTRY32
            $te.dwSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($te)

            if ([NativeMethods2]::Thread32First($hSnap, [ref]$te)) {
                do {
                    if ($te.th32OwnerProcessID -ne [uint32]$ProcessID) { continue }

                    $hThread = [NativeMethods2]::OpenThread($THREAD_QUERY_INFORMATION, $false, $te.th32ThreadID)
                    if ($hThread -eq [IntPtr]::Zero) { continue }

                    try {
                        $startAddr = [IntPtr]::Zero
                        $status = [NativeMethods2]::NtQueryInformationThread(
                                    $hThread, 9, [ref]$startAddr,
                                    [IntPtr]::Size, [IntPtr]::Zero)

                        if ($status -eq 0 -and $startAddr -ne [IntPtr]::Zero) {
                            $addrVal = [uint64]$startAddr.ToInt64()

                            # Is the start address inside any known module?
                            $inModule = $false
                            foreach ($mod in $moduleRanges) {
                                $modBase = [uint64]$mod.Base
                                if ($addrVal -ge $modBase -and $addrVal -lt ($modBase + $mod.Size)) {
                                    $inModule = $true
                                    break
                                }
                            }

                            if (-not $inModule) {
                                # Is it inside an RWX region?
                                $inRwx = $false
                                $matchBase = $null
                                foreach ($rgn in $rwxRegions) {
                                    if ($addrVal -ge $rgn.Base -and $addrVal -lt ($rgn.Base + $rgn.Size)) {
                                        $inRwx = $true
                                        $matchBase = "0x{0:x16}" -f $rgn.Base
                                        break
                                    }
                                }

                                $threadInfo = [PSCustomObject]@{
                                    ThreadId      = $te.th32ThreadID
                                    StartAddress  = "0x{0:x16}" -f $addrVal
                                    InKnownModule = $false
                                    InRwxRegion   = $inRwx
                                }

                                $severity = if ($inRwx) { " (IN RWX REGION at $matchBase)" } else { '' }
                                Write-Verbose ("  [!] Suspicious thread {0} - start 0x{1:x16} not in any module{2}" -f `
                                    $te.th32ThreadID, $addrVal, $severity)

                                # Attach to matching RWX region finding
                                if ($matchBase) {
                                    foreach ($rd in $regionData) {
                                        if ($rd.BaseAddress -eq $matchBase) {
                                            $rd.SuspiciousThreads = @($rd.SuspiciousThreads) + $threadInfo
                                            break
                                        }
                                    }
                                } else {
                                    # Orphan suspicious thread (not in any RWX region) - emit standalone
                                    $regionData += [ordered]@{
                                        FindingType          = 'SuspiciousThread'
                                        ProcessName          = $proc.ProcessName
                                        ProcessId            = $ProcessID
                                        BaseAddress          = 'N/A'
                                        RegionSize           = 0
                                        Protection           = 'N/A'
                                        ProtectionName       = 'N/A'
                                        State                = 'N/A'
                                        Type                 = 'N/A'
                                        ContainsSearchString = $false
                                        SearchString         = $StringToLookFor
                                        Entropy              = 0.0
                                        EntropyLevel         = 'N/A'
                                        SuspiciousThreads    = @($threadInfo)
                                        HexDump              = ''
                                        Timestamp            = (Get-Date -Format 'o')
                                    }
                                }
                            }
                        }
                    } finally {
                        [NativeMethods2]::CloseHandle($hThread) | Out-Null
                    }
                } while ([NativeMethods2]::Thread32Next($hSnap, [ref]$te))
            }
        } finally {
            [NativeMethods2]::CloseHandle($hSnap) | Out-Null
        }
    } else {
        Write-Warning "CreateToolhelp32Snapshot failed; thread analysis skipped."
    }

    # ── Phase 3.2: Single balloon notification for all findings ─────────────
    $matchCount = ($regionData | Where-Object { $_.ContainsSearchString }).Count
    if ($matchCount -gt 0 -and $null -ne $balloonMsg) {
        $balloonMsg.BalloonTipTitle = "Suspicious RWX regions detected"
        $balloonMsg.BalloonTipText  = ("Process {0} (PID {1}): {2} region(s) contain '{3}'. {4} total RWX region(s) found." -f `
            $proc.ProcessName.ToUpper(), $ProcessID, $matchCount, $StringToLookFor, $regionData.Count)
        $balloonMsg.ShowBalloonTip(30000)
    }

    # ── Phase 4.1: Emit structured PSCustomObject results ───────────────────
    if ($regionData.Count -eq 0) {
        Write-Verbose "No private committed RWX regions found for PID $ProcessID."
    } else {
        $rwxCount    = ($regionData | Where-Object { $_.FindingType -eq 'RwxRegion' }).Count
        $threadCount = ($regionData | Where-Object { $_.FindingType -eq 'SuspiciousThread' }).Count
        $summary     = "Scan complete. {0} RWX region(s)" -f $rwxCount
        if ($threadCount -gt 0) { $summary += ", {0} orphan suspicious thread(s)" -f $threadCount }
        Write-Verbose $summary

        foreach ($rd in $regionData) {
            [PSCustomObject]$rd
        }
    }
}
finally {
    # Clean up handles and GDI objects
    [NativeMethods2]::CloseHandle($hProc) | Out-Null
    if ($null -ne $balloonMsg) {
        $balloonMsg.Visible = $false
        $balloonMsg.Dispose()
    }
}
