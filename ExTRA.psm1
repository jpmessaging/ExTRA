<#
.SYNOPSIS
Collect Exchange Server ETW trace

.DESCRIPTION
This script contains functions to collect an ETW trace on an Exchange Server. The main function to use is Collect-ExTRA:

    Collect-ExTRA -Path <output folder> -ComponentAndTags <hash table of components & tags to trace>

You can Import-Module the script to load these functions.

e.g.
Import-Module C:\temp\ExTRA.psm1 -DisableNameChecking

See more on:
https://github.com/jpmessaging/ExTRA

.EXAMPLE
Collect-ExTRA -Path C:\temp -ComponentAndTags @{'ADProvider'='*';'Data.Storage'='*';'InfoWorker.Sharing'='LocalFolder,SharingEngine'}

.NOTES
Copyright (c) 2020 Ryusuke Fujita

This software is released under the MIT License.
http://opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

#requires -Version 2.0

function Get-ExchangeTraceComponent {
    [CmdletBinding()]
    param(
        $ComponentName
    )

    # Make sure "Microsoft.Exchange.Diagnostics.dll" is loaded.
    $diagAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.FullName -like "Microsoft.Exchange.Diagnostics*"}
    if (-not $diagAssembly) {
        if ($env:ExchangeInstallPath) {
                $dll = Join-Path $env:ExchangeInstallPath -ChildPath 'bin\Microsoft.Exchange.Diagnostics.dll' -ErrorAction Stop
                Import-Module $dll -ErrorAction Stop
        }
        else {
           throw "Environment Variable `"ExchangeInstallPath`" is not defined"
        }
    }

    $components = [Microsoft.exchange.Diagnostics.AvailableTraces]::InnerDictionary.Values

    if ($ComponentName.Count) {
        foreach ($name in $ComponentName) {
            $components | Where-Object {$_.PrettyName -like "$name" }
        }
    }
    else {
        [Microsoft.exchange.Diagnostics.AvailableTraces]::InnerDictionary.Values
    }
}

function Start-ExTRA {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        $Path,
        [Parameter(Mandatory = $true, ParameterSetName='ComponentAndTag')]
        [Hashtable]$ComponentAndTags,
        [Parameter(Mandatory = $true, ParameterSetName='ComponentOnly')]
        [string[]]$Components,
        $TraceFileName,
        [int]$MaxFileSizeMB = 512
    )

    if (-not (Test-Path $Path)) {
        $err = $(New-Item -Path $Path -ItemType directory -ErrorAction Stop | Out-Null) 2>&1
        if ($err) {
            throw $err
        }
    }
    $Path = Resolve-Path $Path

    if (-not $TraceFileName) {
        $currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
        $TraceFileName = "ExTRA_$($env:COMPUTERNAME)_$($currentDateTime)_%d.etl"
    }
    else {
        # Since EVENT_TRACE_FILE_MODE_NEWFILE is used, add "_%d"
        $fileName = [IO.Path]::GetFileNameWithoutExtension($TraceFileName)
        $fileName += '_%d'
        $TraceFileName = $fileName + '.etl'
    }

    # Create EnabledTraces.Config
    $sb = New-Object 'System.Text.StringBuilder'
    $sb.AppendLine("TraceLevels:Debug,Warning,Error,Fatal,Info,Performance,Function,Pfd") | Out-Null

    if ($PSCmdlet.ParameterSetName -eq 'ComponentOnly') {        
        $ComponentAndTags = @{}
        $Components | ForEach-Object {$ComponentAndTags.Add($_, '*')}        
    }

    foreach ($entry in $ComponentAndTags.GetEnumerator()) {
        $component = $entry.Name
        $tags = $entry.Value -split ','

        # Given component name can include a wildcard (*), and might match multple components
        $knownComponents = @(Get-ExchangeTraceComponent -ComponentName $component)
        if ($knownComponents.Count -eq 0) {
            throw "Cannot find component `"$component`""
        }

        foreach ($knownComponent in $knownComponents) {
            $component = $knownComponent.PrettyName
            $knownTags = @($knownComponent.TagInfoList | Where-Object {$_.PrettyName} | Select-Object -ExpandProperty PrettyName)

            if ($tags.Count -and $tags[0] -eq '*') {
                # Add all the known tags except FaultInjection* (e.g. FaultInjectionConfiguration)
                $knownTagsWithoutFaultInjection = $knownTags | Where-Object {$_ -notlike 'FaultInjection*'}
                $sb.AppendLine("$($component):$($knownTagsWithoutFaultInjection -join ',')") | Out-Null
            }
            else {
                # Validate tag names and add them.
                for ($i = 0; $i -lt $tags.Count; $i++) {
                    $tag = $knownTags | Where-Object {$_ -eq $tags[$i]}
                    if (-not $tag) {
                        throw  "Tag `"$($tags[$i])`" is not valid for component `"$($knownComponent.PrettyName)`""
                    }
                    $tags[$i] = $tag
                }
                $sb.AppendLine("$($component):$($tags -join ',')") | Out-Null
            }
        }
    }

    $sb.AppendLine('FilteredTracing:No') | Out-Null
    $sb.AppendLine('InMemoryTracing:No') | Out-Null

    $ConfigFile = "C:\EnabledTraces.Config"
    Set-Content -Path $ConfigFile -Value $sb.ToString() -Confirm:$false -ErrorAction Stop

    # Start ETW session
    $ETWSessionName = "ExchangeDebugTraces"
    $ProviderName = '{79BB49E6-2A2C-46E4-9167-FA122525D540}'
    $TraceOutputPath = Join-Path $Path -ChildPath $TraceFileName
    $BufferSizeKB = 128

    # mode = EVENT_TRACE_USE_GLOBAL_SEQUENCE (0x4000) | EVENT_TRACE_FILE_MODE_NEWFILE (8)
    # see https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
    # Note: must use "globalsequence" instead of "EVENT_TRACE_USE_GLOBAL_SEQUENCE".
    $logFileMode = "globalsequence | EVENT_TRACE_FILE_MODE_NEWFILE"

    $logmanCommand = "logman.exe start $ETWSessionName -p `"$ProviderName`" -o `"$TraceOutputPath`" -bs $BufferSizeKB -max $MaxFileSizeMB -mode `"$logFileMode`" -ets"
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,$logmanCommand)) {
        Write-Verbose "executing $logmanCommand"
        $logmanResult = Invoke-Expression $logmanCommand

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start a ETW session `"$ETWSessionName`". Error: 0x$("{0:X}" -f $LASTEXITCODE)"
        }
    }

    New-Object PSCustomObject -Property @{
        LogmanResult = $logmanResult
        LogmanCommand = $logmanCommand
        ETWSessionName = $ETWSessionName
        TraceOutputPath =$TraceOutputPath
        ConfigFile = $ConfigFile
        MaxFileSizeMB = $MaxFileSizeMB
    }
}

function Stop-ExTRA {
    [CmdletBinding()]
    param(
        [string]$ETWSessionName = "ExchangeDebugTraces"
    )

    $session = Stop-EtwSession $ETWSessionName

    # Remove EnabledTraces.Config
    $ConfigFile = "C:\EnabledTraces.Config"
    $err = $(Remove-Item $ConfigFile -Force) 2>&1
    if ($err) {
        Write-Warning "Please remove $ConfigFile.`n$err"
    }

    New-Object PSCustomObject -Property @{
        Session = $session
        ConfigFileRemoved = $($null -eq $err)
        OutputFile = $session.LogFileName
    }
}

$ETWType = @'
// https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
[StructLayout(LayoutKind.Sequential)]
public struct WNODE_HEADER
{
    public uint BufferSize;
    public uint ProviderId;
    public ulong HistoricalContext;
    public ulong KernelHandle;
    public Guid Guid;
    public uint ClientContext;
    public uint Flags;
}

// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct EVENT_TRACE_PROPERTIES
{
    public WNODE_HEADER Wnode;
    public uint BufferSize;
    public uint MinimumBuffers;
    public uint MaximumBuffers;
    public uint MaximumFileSize;
    public uint LogFileMode;
    public uint FlushTimer;
    public uint EnableFlags;
    public int AgeLimit;
    public uint NumberOfBuffers;
    public uint FreeBuffers;
    public uint EventsLost;
    public uint BuffersWritten;
    public uint LogBuffersLost;
    public uint RealTimeBuffersLost;
    public IntPtr LoggerThreadId;
    public int LogFileNameOffset;
    public int LoggerNameOffset;
}

public struct EventTraceProperties
{
    public EVENT_TRACE_PROPERTIES Properties;
    public string SessionName;
    public string LogFileName;

    public EventTraceProperties(EVENT_TRACE_PROPERTIES properties, string sessionName, string logFileName)
    {
        Properties = properties;
        SessionName = sessionName;
        LogFileName = logFileName;
    }
}

[DllImport("kernel32.dll", ExactSpelling = true)]
public static extern void RtlZeroMemory(IntPtr dst, int length);

[DllImport("Advapi32.dll", ExactSpelling = true)]
public static extern int QueryAllTracesW(IntPtr[] PropertyArray, uint PropertyArrayCount, ref int LoggerCount);

[DllImport("Advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
public static extern int StopTraceW(ulong TraceHandle, string InstanceName, IntPtr Properties); // TRACEHANDLE is defined as ULONG64

const int MAX_SESSIONS = 64;
const int MAX_NAME_COUNT = 1024; // max char count for LogFileName & SessionName
const uint ERROR_SUCCESS = 0;

// https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
// > The size of memory must include the room for the EVENT_TRACE_PROPERTIES structure plus the session name string and log file name string that follow the structure in memory.
static readonly int PropertiesSize = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES)) + 2 * sizeof(char) * MAX_NAME_COUNT; // EVENT_TRACE_PROPERTIES + LogFileName & LoggerName
static readonly int LoggerNameOffset = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
static readonly int LogFileNameOffset = LoggerNameOffset + sizeof(char) * MAX_NAME_COUNT;

public static List<EventTraceProperties> QueryAllTraces()
{
    IntPtr pBuffer = IntPtr.Zero;
    List<EventTraceProperties> eventProperties = null;
    try
    {
        // Allocate native memorty to hold the entire data.
        int BufferSize = PropertiesSize * MAX_SESSIONS;
        pBuffer = Marshal.AllocCoTaskMem(BufferSize);
        RtlZeroMemory(pBuffer, BufferSize);

        IntPtr[] sessions = new IntPtr[64];

        for (int i = 0; i < 64; ++i)
        {
            //sessions[i] = pBuffer + (i * PropertiesSize); // This does not compile in .NET 2.0
            sessions[i] = new IntPtr(pBuffer.ToInt64() + (i * PropertiesSize));

            // Marshal from managed to native
            EVENT_TRACE_PROPERTIES props = new EVENT_TRACE_PROPERTIES();
            props.Wnode.BufferSize = (uint)PropertiesSize;
            props.LoggerNameOffset = LoggerNameOffset;
            props.LogFileNameOffset = LogFileNameOffset;
            Marshal.StructureToPtr(props, sessions[i], false);
        }

        int loggerCount = 0;
        int status = QueryAllTracesW(sessions, MAX_SESSIONS, ref loggerCount);

        if (status != ERROR_SUCCESS)
        {
            throw new Win32Exception(status);
        }

        eventProperties = new List<EventTraceProperties>();
        for (int i = 0; i < loggerCount; ++i)
        {
            // Marshal back from native to managed.
            EVENT_TRACE_PROPERTIES props = (EVENT_TRACE_PROPERTIES)Marshal.PtrToStructure(sessions[i], typeof(EVENT_TRACE_PROPERTIES));
            string sessionName = Marshal.PtrToStringUni(new IntPtr(sessions[i].ToInt64() + LoggerNameOffset));
            string logFileName = Marshal.PtrToStringUni(new IntPtr(sessions[i].ToInt64() + LogFileNameOffset));

            //eventProperties.Add(new EventTraceProperties { Properties = props, SessionName = sessionName, LogFileName = logFileName });
            eventProperties.Add(new EventTraceProperties(props,sessionName, logFileName));
        }
    }
    finally
    {
        if (pBuffer != IntPtr.Zero)
        {
            Marshal.FreeCoTaskMem(pBuffer);
            pBuffer = IntPtr.Zero;
        }
    }

    return eventProperties;
}

public static EventTraceProperties StopTrace(string SessionName)
{
    IntPtr pProps = IntPtr.Zero;
    try
    {
        pProps = Marshal.AllocCoTaskMem(PropertiesSize);
        RtlZeroMemory(pProps, PropertiesSize);

        EVENT_TRACE_PROPERTIES props = new EVENT_TRACE_PROPERTIES();
        props.Wnode.BufferSize = (uint)PropertiesSize;
        props.LoggerNameOffset = LoggerNameOffset;
        props.LogFileNameOffset = LogFileNameOffset;
        Marshal.StructureToPtr(props, pProps, false);

        int status = StopTraceW(0, SessionName, pProps);
        if (status != ERROR_SUCCESS)
        {
            throw new Win32Exception(status);
        }

        props = (EVENT_TRACE_PROPERTIES)Marshal.PtrToStructure(pProps, typeof(EVENT_TRACE_PROPERTIES));
        string sessionName = Marshal.PtrToStringUni(new IntPtr(pProps.ToInt64() + LoggerNameOffset));
        string logFileName = Marshal.PtrToStringUni(new IntPtr(pProps.ToInt64() + LogFileNameOffset));

        //return new EventTraceProperties { Properties = props, SessionName = sessionName, LogFileName = logFileName };
        return new EventTraceProperties(props, sessionName, logFileName);
    }
    finally
    {
        if (pProps != IntPtr.Zero)
        {
            Marshal.FreeCoTaskMem(pProps);
        }
    }
}
'@


function Get-EtwSession {
    [CmdletBinding()]
    param()

    if (-not ('Win32.ETW' -as [type])) {
        Add-type -MemberDefinition $ETWType -Namespace Win32 -Name ETW -UsingNamespace System.Collections.Generic, System.ComponentModel
    }

    try {
        $traces = [Win32.ETW]::QueryAllTraces()
        return $traces
    }
    catch {
        Write-Error "QueryAllTraces failed. $_"
    }
}

function Stop-EtwSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionName
    )

    if (-not ('Win32.ETW' -as [type])) {
        Add-type -MemberDefinition $ETWType -Namespace Win32 -Name ETW -UsingNamespace System.Collections.Generic, System.ComponentModel
    }

    try {
        return [Win32.ETW]::StopTrace($SessionName)
    }
    catch {
        Write-Error "StopTrace for $SessionName failed. $_"
    }
}

function Compress-Folder {
    [CmdletBinding()]
    param(
        # Specifies a path to one or more locations.
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$Destination,
        [string]$ZipFileName,
        [switch]$IncludeDateTime,
        [switch]$RemoveFiles,
        [switch]$UseShellApplication
    )

    $Path = Resolve-Path $Path
    $zipFileNameWithouExt = [System.IO.Path]::GetFileNameWithoutExtension($ZipFileName)
    if ($IncludeDateTime) {
        $zipFileName = $zipFileNameWithouExt + "_" + "$(Get-Date -Format "yyyyMMdd_HHmmss").zip"
    }
    else {
        $zipFileName = "$zipFileNameWithouExt.zip"
    }

    # If Destination is not given, use %TEMP% folder.
    if (-not $Destination) {
        $Destination = $env:TEMP
    }

    if (-not (Test-Path $Destination)) {
        New-Item $Destination -ItemType Directory -ErrorAction Stop | Out-Null
    }

    $Destination = Resolve-Path $Destination
    $zipFilePath = Join-Path $Destination -ChildPath $zipFileName

    $NETFileSystemAvailable = $false

    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        # Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $NETFileSystemAvailable = $true
    }
    catch {
        Write-Verbose "System.IO.Compression.FileSystem wasn't found. Using alternate method"
    }

    if ($NETFileSystemAvailable -and $UseShellApplication -eq $false) {
        # Note: [System.IO.Compression.ZipFile]::CreateFromDirectory() fails when one or more files in the directory is locked.
        #[System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $zipFilePath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

        try {
            New-Item $zipFilePath -ItemType file | Out-Null

            $zipStream = New-Object System.IO.FileStream -ArgumentList $zipFilePath, ([IO.FileMode]::Open)
            $zipArchive = New-Object System.IO.Compression.ZipArchive -ArgumentList $zipStream, ([IO.Compression.ZipArchiveMode]::Create)

            $files = @(Get-ChildItem $Path -Recurse | Where-Object {-not $_.PSIsContainer})
            $count = 0

            foreach ($file in $files) {
                Write-Progress -Activity "Creating a zip file $zipFilePath" -Status "Adding $($file.FullName)" -PercentComplete (100 * $count / $files.Count)

                try {
                    $fileStream = New-Object System.IO.FileStream -ArgumentList $file.FullName, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::ReadWrite)
                    $zipEntry = $zipArchive.CreateEntry($file.FullName.Substring($Path.Length + 1))
                    $zipEntryStream = $zipEntry.Open()
                    $fileStream.CopyTo($zipEntryStream)

                    ++$count
                }
                catch {
                    Write-Error "Failed to add $($file.FullName). $_"
                }
                finally {
                    if ($fileStream) {
                        $fileStream.Dispose()
                    }

                    if ($zipEntryStream) {
                        $zipEntryStream.Dispose()
                    }
                }
            }
        }
        finally {
            if ($zipArchive) {
                $zipArchive.Dispose()
            }

            if ($zipStream) {
                $zipStream.Dispose()
            }

            Write-Progress -Activity "Creating a zip file $zipFilePath" -Completed
        }
    }
    else {
        # Use Shell.Application COM

        # Create a zip file manually
        $shellApp = New-Object -ComObject Shell.Application
        Set-Content $zipFilePath ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
        (Get-Item $zipFilePath).IsReadOnly = $false

        $zipFile = $shellApp.NameSpace($zipFilePath)

        # If target folder is empty, CopyHere() fails. So make sure it's not empty
        if (@(Get-ChildItem $Path).Count -gt 0) {
            # Start copying the whole and wait until it's done. CopyHere works asynchronously.
            $zipFile.CopyHere($Path)

            # Now wait and poll
            $inProgress = $true
            $delayMilliseconds = 200
            Start-Sleep -Milliseconds 3000
            [System.IO.FileStream]$file = $null
            while ($inProgress) {
                Start-Sleep -Milliseconds $delayMilliseconds

                try {
                    $file = [System.IO.File]::Open($zipFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
                    $inProgress = $false
                }
                catch [System.IO.IOException] {
                    Write-Debug $_.Exception.Message
                }
                finally {
                    if ($file) {
                        $file.Close()
                    }
                }
            }
        }
    }

    if (Test-Path $zipFilePath) {
        # If requested, remove zipped files
        if ($RemoveFiles) {
            Write-Verbose "Removing zipped files"
            Get-ChildItem $Path -Exclude $ZipFileName | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            $filesRemoved = $true
        }

        New-Object PSCustomObject -Property @{
            ZipFilePath = $zipFilePath.ToString()
            FilesRemoved = $filesRemoved -eq $true
        }
    }
    else {
        throw "Zip file wasn't successfully created at $zipFilePath"
    }
}


function Collect-ExTRA {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        $Path,
        [Parameter(Mandatory = $true)]
        [Hashtable]$ComponentAndTags
    )

    if (-not (Test-Path $Path)) {
        New-Item $Path -ItemType directory -ErrorAction Stop | Out-Null
    }

    $Path = Resolve-Path $Path
    $tempPath = Join-Path $Path -ChildPath $([Guid]::NewGuid().ToString())
    New-Item $tempPath -ItemType directory -ErrorAction Stop | Out-Null

    try {
        Get-WmiObject win32_process | Export-Clixml -Path $(Join-Path $tempPath -ChildPath "Processes_$($env:COMPUTERNAME)_$(Get-Date -Format "yyyyMMdd_HHmmss").xml")
        $sessionInfo = Start-ExTRA -Path $tempPath -ComponentAndTags $ComponentAndTags

        Read-Host "ExTRA has successfully started. Hit enter to stop ExTRA"

        $stopResult = Stop-ExTRA -ETWSessionName $sessionInfo.ETWSessionName
        Get-WmiObject win32_process | Export-Clixml -Path $(Join-Path $tempPath -ChildPath "Processes_$($env:COMPUTERNAME)_$(Get-Date -Format "yyyyMMdd_HHmmss").xml")
        $zipFileName = "ExTRA_$($env:COMPUTERNAME)_$(Get-Date -Format "yyyyMMdd_HHmmss")"
        Compress-Folder -Path $tempPath -ZipFileName $zipFileName -Destination $Path -RemoveFiles | Out-Null
        Remove-Item $tempPath -Force
        Write-Host "The collected data is in `"$(Join-Path $Path $zipFileName).zip`""
        Invoke-Item $Path
    }
    finally {
        if ($sessionInfo -and -not $stopResult) {
            Write-Verbose "Stopping $($sessionInfo.ETWSessionName)"
            Stop-ExTRA -ETWSessionName $sessionInfo.ETWSessionName | Out-Null
            Write-Warning "ExTRA was canceled. Please remove files in `"$tempPath`" if not needed."
        }
    }
}


Export-ModuleMember -Function Get-ExchangeTraceComponent, Start-ExTRA, Stop-ExTRA, Get-EtwSession, Stop-EtwSession, Collect-ExTRA