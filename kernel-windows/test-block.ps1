# test-block.ps1 - manage the driver's block lists.
#
# Usage:
#   .\test-block.ps1 -Action add    -Kind process -Pattern 'notepad.exe'
#   .\test-block.ps1 -Action remove -Kind file    -Pattern 'C:\\quarantine\\evil'
#   .\test-block.ps1 -Action clear  -Kind both
#   .\test-block.ps1 -Action clear  -Kind process
#   .\test-block.ps1 -SpawnTest                  # adds notepad.exe block, tries
#                                                # to spawn notepad, expects deny
param(
    [ValidateSet('add','remove','clear')]
    [string]$Action,
    [ValidateSet('process','file','both')]
    [string]$Kind = 'process',
    [string]$Pattern,
    [switch]$SpawnTest
)

$ErrorActionPreference = 'Stop'

$IOCTL_BLOCK_ADD    = 0x22200C   # CTL_CODE(0x22, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
$IOCTL_BLOCK_REMOVE = 0x222010   # 0x804
$IOCTL_BLOCK_CLEAR  = 0x222014   # 0x805

$KIND_PROCESS = 1
$KIND_FILE    = 2

if (-not ('Edr.NativeBlock' -as [type])) {
    Add-Type -Namespace Edr -Name NativeBlock -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr CreateFileW(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    System.IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool DeviceIoControl(
    System.IntPtr hDevice, uint dwIoControlCode,
    System.IntPtr lpInBuffer, uint nInBufferSize,
    System.IntPtr lpOutBuffer, uint nOutBufferSize,
    out uint lpBytesReturned, System.IntPtr lpOverlapped);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(System.IntPtr hObject);
'@
}

function Open-VigilDevice {
    $GENERIC_RW = [uint32]3221225472
    $h = [Edr.NativeBlock]::CreateFileW("\\.\Vigil", $GENERIC_RW, [uint32]3, [IntPtr]::Zero, [uint32]3, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::new(-1)) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw ('CreateFile \\.\Vigil failed: ' + $err)
    }
    return $h
}

function Send-Ioctl {
    param([IntPtr]$Handle, [uint32]$Code, [byte[]]$InBytes)
    $inLen = if ($InBytes) { $InBytes.Length } else { 0 }
    $inPtr = if ($inLen -gt 0) { [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inLen) } else { [IntPtr]::Zero }
    try {
        if ($inLen -gt 0) { [System.Runtime.InteropServices.Marshal]::Copy($InBytes, 0, $inPtr, $inLen) }
        $bytesReturned = 0
        $ok = [Edr.NativeBlock]::DeviceIoControl($Handle, $Code, $inPtr, $inLen, [IntPtr]::Zero, 0, [ref]$bytesReturned, [IntPtr]::Zero)
        if (-not $ok) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw ('DeviceIoControl(0x' + $Code.ToString('X') + ') failed: ' + $err)
        }
    } finally {
        if ($inPtr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inPtr) }
    }
}

function Block-Add {
    param([int]$KindNum, [string]$Pattern)
    $patternBytes = [System.Text.Encoding]::Unicode.GetBytes($Pattern)
    # VIGIL_BLOCK_REQ: UINT32 Kind, UINT32 PatternBytes, then pattern.
    $hdr = New-Object byte[] 8
    [BitConverter]::GetBytes([uint32]$KindNum).CopyTo($hdr, 0)
    [BitConverter]::GetBytes([uint32]$patternBytes.Length).CopyTo($hdr, 4)
    $body = New-Object byte[] ($hdr.Length + $patternBytes.Length)
    $hdr.CopyTo($body, 0)
    $patternBytes.CopyTo($body, $hdr.Length)
    $h = Open-VigilDevice
    try { Send-Ioctl -Handle $h -Code $IOCTL_BLOCK_ADD -InBytes $body } finally { [void][Edr.NativeBlock]::CloseHandle($h) }
}

function Block-Remove {
    param([int]$KindNum, [string]$Pattern)
    $patternBytes = [System.Text.Encoding]::Unicode.GetBytes($Pattern)
    $hdr = New-Object byte[] 8
    [BitConverter]::GetBytes([uint32]$KindNum).CopyTo($hdr, 0)
    [BitConverter]::GetBytes([uint32]$patternBytes.Length).CopyTo($hdr, 4)
    $body = New-Object byte[] ($hdr.Length + $patternBytes.Length)
    $hdr.CopyTo($body, 0)
    $patternBytes.CopyTo($body, $hdr.Length)
    $h = Open-VigilDevice
    try { Send-Ioctl -Handle $h -Code $IOCTL_BLOCK_REMOVE -InBytes $body } finally { [void][Edr.NativeBlock]::CloseHandle($h) }
}

function Block-Clear {
    param([int]$KindNum)
    $body = New-Object byte[] 4
    [BitConverter]::GetBytes([uint32]$KindNum).CopyTo($body, 0)
    $h = Open-VigilDevice
    try { Send-Ioctl -Handle $h -Code $IOCTL_BLOCK_CLEAR -InBytes $body } finally { [void][Edr.NativeBlock]::CloseHandle($h) }
}

function Resolve-Kind {
    param([string]$K)
    switch ($K) {
        'process' { return $KIND_PROCESS }
        'file'    { return $KIND_FILE }
        'both'    { return 0 }
        default   { throw ('unknown kind: ' + $K) }
    }
}

if ($SpawnTest) {
    Write-Host 'block notepad.exe (process kind)'
    Block-Add -KindNum $KIND_PROCESS -Pattern 'notepad.exe'
    Start-Sleep -Milliseconds 200
    Write-Host 'attempting to spawn notepad...'
    try {
        $p = Start-Process -PassThru -FilePath notepad.exe -ErrorAction Stop
        Start-Sleep -Milliseconds 300
        $still = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
        if ($still) {
            Write-Host ('FAIL: notepad pid=' + $p.Id + ' still alive after block was set')
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $exit = 1
        } else {
            Write-Host 'OK: notepad started but exited (rejected)'
            $exit = 0
        }
    } catch {
        Write-Host ('OK: spawn rejected: ' + $_.Exception.Message)
        $exit = 0
    }
    Write-Host 'cleanup: removing notepad.exe block'
    Block-Remove -KindNum $KIND_PROCESS -Pattern 'notepad.exe'
    exit $exit
}

if (-not $Action) {
    Write-Host 'usage: -Action add|remove|clear -Kind process|file|both [-Pattern <str>] | -SpawnTest'
    exit 1
}

switch ($Action) {
    'add'    { if (-not $Pattern) { throw 'add needs -Pattern' };    Block-Add    -KindNum (Resolve-Kind $Kind) -Pattern $Pattern }
    'remove' { if (-not $Pattern) { throw 'remove needs -Pattern' }; Block-Remove -KindNum (Resolve-Kind $Kind) -Pattern $Pattern }
    'clear'  { Block-Clear -KindNum (Resolve-Kind $Kind) }
}
Write-Host 'OK'
