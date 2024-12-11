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

function Open-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$AutoFlush,
        [switch]$WithBOM
    )

    if ($Script:LogWriter) {
        Close-Log
    }

    # Open a file & add header
    try {
        $utf8Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $WithBOM.IsPresent
        $Script:LogWriter = New-Object System.IO.StreamWriter -ArgumentList $Path, <# append #> $true, $utf8Encoding

        if ($AutoFlush) {
            $Script:LogWriter.AutoFlush = $true
        }

        $Script:LogWriter.WriteLine("datetime,thread_relative_delta,thread,function,category,message")
    }
    catch {
        Write-Error -ErrorRecord $_
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]$Message,
        [Parameter(ValueFromPipeline = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [ValidateSet('Information', 'Warning', 'Error')]
        $Category = 'Information',
        # Output the given ErrorRecord
        [Switch]$PassThru
    )

    process {
        # If ErrorRecord is provided, use it.
        if ($ErrorRecord) {
            $errorDetails = $null

            if ($ErrorRecord.ErrorDetails.Message -ne $ErrorRecord.Exception.Message) {
                $errorDetails = $ErrorRecord.ErrorDetails.Message
            }

            $Message = "$Message; [ErrorRecord] $(if ($errorDetails) { "ErrorDetails:$errorDetails, " })ExceptionType:$($ErrorRecord.Exception.GetType().Name), Exception.Message:$($ErrorRecord.Exception.Message), InvocationInfo.Line:'$($ErrorRecord.InvocationInfo.Line.Trim())', ScriptStackTrace:$($ErrorRecord.ScriptStackTrace.Replace([Environment]::NewLine, ' '))"
        }

        # Ignore null or an empty string.
        if (-not $Message) {
            return
        }

        # If Open-Log is not called beforehand, just output to verbose.
        if (-not $Script:LogWriter) {
            Write-Verbose $Message
            return
        }

        # If LogWriter exists but disposed already, something went wrong.
        if (-not $Script:LogWriter.BaseStream.CanWrite) {
            Write-Warning "LogWriter has been disposed already"
            return
        }

        $currentTime = Get-Date
        $currentTimeFormatted = $currentTime.ToString('o')

        # Delta time is relative to thread.
        # Each thread has it's own copy of LastLogTime now.
        [TimeSpan]$delta = 0

        if ($Script:LastLogTime) {
            $delta = $currentTime.Subtract($Script:LastLogTime)
        }

        $caller = '<ScriptBlock>'
        $caller = Get-PSCallStack | Select-Object -Skip 1 | & {
            process {
                if (-not $_.Command.StartsWith('<ScriptBlock>')) {
                    $_.Command
                }
            }
        } | Select-Object -First 1

        # Format as CSV:
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append($currentTimeFormatted).Append(',')
        $null = $sb.Append($delta).Append(',')
        $null = $sb.Append([System.Threading.Thread]::CurrentThread.ManagedThreadId).Append(',')
        $null = $sb.Append($caller).Append(',')

        $categoryEmoji = switch ($Category) {
            'Information' { $Script:Emoji.Information; break }
            'Warning' { $Script:Emoji.Warning; break }
            'Error' { $Script:Emoji.Error; break }
        }

        $null = $sb.Append($categoryEmoji).Append(',')

        $null = $sb.Append('"').Append($Message.Replace('"', "'")).Append('"')

        # Protect from concurrent write
        [System.Threading.Monitor]::Enter($Script:LogWriter)

        try {
            $Script:LogWriter.WriteLine($sb.ToString())
        }
        finally {
            [System.Threading.Monitor]::Exit($Script:LogWriter)
        }

        $sb = $null
        $Script:LastLogTime = $currentTime

        if ($PassThru) {
            $ErrorRecord
        }
    }
}

function Close-Log {
    if ($Script:LogWriter) {
        if ($Script:LogWriter.BaseStream.CanWrite) {
            Write-Log "Closing LogWriter"
            $Script:LogWriter.Close()
        }

        $Script:LogWriter = $null
        $Script:LastLogTime = $null
    }
}

<#
.SYNOPSIS
    Start enumerating processes
.DESCRIPTION
    This command starts enumerating Win32 processes until canceled via an EventWaitHandle, and it repeats with the given interval.
#>
function Start-ProcessCapture {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        # Folder path to save process list
        [string]$Path,
        [Parameter(Mandatory = $true)]
        # Name of EventWaitHandle. When signaled, this command exits.
        [string]$CancelEventName,
        [TimeSpan]$Interval = [TimeSpan]::FromSeconds(1)
    )

    if (-not (Test-Path $Path)) {
        $null = New-Item $Path -ItemType Directory -ErrorAction Stop
    }

    try {
        $stopEvent = [System.Threading.EventWaitHandle]::OpenExisting($CancelEventName)
    }
    catch {
        Write-Error -Message "OpenExisting failed for `"$CancelEventName`". $_" -Exception $_.Exception
        return
    }

    # Using a Hash table is much faster than Where-Object.
    $hashSet = @{}

    while ($true) {
        Get-CimInstance Win32_Process | & {
            param ([Parameter(ValueFromPipeline)]$win32Process)
            process {
                try {
                    $key = "$($win32Process.ProcessId),$($win32Process.CreationDate)"

                    if ($hashSet.ContainsKey($key)) {
                        return
                    }

                    $obj = @{
                        Name            = $win32Process.Name
                        Id              = $win32Process.ProcessId
                        CreationDate    = $win32Process.CreationDate
                        Path            = $win32Process.Path
                        CommandLine     = $win32Process.CommandLine
                        ParentProcessId = $win32Process.ParentProcessId
                    }

                    $hashSet.Add($key, [PSCustomObject]$obj)
                }
                finally {
                    $win32Process.Dispose()
                }
            }
        }

        # If event is signaled, exit
        if ($stopEvent.WaitOne(0)) {
            "Cancel request acknowledged"
            break
        }

        Start-Sleep -Seconds $Interval.TotalSeconds
    }

    $hashSet.Values | Export-Clixml -Path (Join-Path $Path 'Win32_Process.xml')
}

# ETW Logging Mode Constants for logman
# https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
$LogmanMode = [PSCustomObject]@{
    EVENT_TRACE_FILE_MODE_SEQUENTIAL = "sequential"
    EVENT_TRACE_FILE_MODE_CIRCULAR   = 'circular'
    EVENT_TRACE_FILE_MODE_APPEND     = 'append'
    EVENT_TRACE_FILE_MODE_NEWFILE    = 'newfile'
    EVENT_TRACE_USE_GLOBAL_SEQUENCE  = 'globalsequence'
    EVENT_TRACE_USE_LOCAL_SEQUENCE   = 'localsequence'
}

function Get-ExchangeTraceComponent {
    [CmdletBinding()]
    param(
        $ComponentName
    )

    # Make sure "Microsoft.Exchange.Diagnostics.dll" is loaded.
    $diagAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like "Microsoft.Exchange.Diagnostics*" }
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
            $components | Where-Object { $_.PrettyName -like "$name" }
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
        [string[]]$Components,
        [Hashtable]$ComponentAndTags,
        [string]$FileName = "ExTRA_$($env:COMPUTERNAME)_$(Get-Date -f "yyyyMMdd_HHmmss").etl",
        [int]$MaxFileSizeMB = 512,
        [ValidateSet('NewFile', 'Circular')]
        [string]$LogFileMode = 'NewFile'
    )

    if (-not (Test-Path $Path)) {
        $err = $($null = New-Item -Path $Path -ItemType directory -ErrorAction Stop) 2>&1
        if ($err) {
            throw $err
        }
    }
    $Path = Resolve-Path $Path

    # Create EnabledTraces.Config
    $sb = New-Object 'System.Text.StringBuilder'
    $null = $sb.AppendLine("TraceLevels:Debug,Warning,Error,Fatal,Info,Performance,Function,Pfd")

    if ($null -eq $ComponentAndTags) {
        $ComponentAndTags = @{}
    }

    # Merge $Components to $ComponentAndTags.
    # If there is any duplicate component, write error and bail.
    $dupCount = 0
    foreach ($comp in $Components) {
        if ($ComponentAndTags.ContainsKey($comp)) {
            Write-Error -Message "Component `"$comp`" is already in ComponentAndTags table."
            $dupCount++
        }
        else {
            $ComponentAndTags.Add($comp, '*')
        }
    }

    if ($dupCount) {
        return
    }

    if ($ComponentAndTags.Count -eq 0) {
        Write-Error -Message "Both Components and ComponentAndTags cannot be empty at the same time."
        return
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
            $knownTags = @($knownComponent.TagInfoList | Where-Object { $_.PrettyName } | Select-Object -ExpandProperty PrettyName)

            if ($tags.Count -and $tags[0].Trim() -eq '*') {
                # Add all the known tags except FaultInjection* (e.g. FaultInjectionConfiguration)
                $knownTagsWithoutFaultInjection = $knownTags | Where-Object { $_ -notlike 'FaultInjection*' }
                $null = $sb.AppendLine("$($component):$($knownTagsWithoutFaultInjection -join ',')")
            }
            else {
                # Validate tag names and add them.
                for ($i = 0; $i -lt $tags.Count; $i++) {
                    $tag = $knownTags | Where-Object { $_ -eq $tags[$i].Trim() }
                    if (-not $tag) {
                        throw  "Tag `"$($tags[$i].Trim())`" is not valid for component `"$($knownComponent.PrettyName)`""
                    }
                    $tags[$i] = $tag
                }
                $null = $sb.AppendLine("$($component):$($tags -join ',')")
            }
        }
    }

    $null = $sb.AppendLine('FilteredTracing:No')
    $null = $sb.AppendLine('InMemoryTracing:No')

    $ConfigFile = "C:\EnabledTraces.Config"
    Set-Content -Path $ConfigFile -Value $sb.ToString() -Confirm:$false -ErrorAction Stop


    # Configure ETW session
    switch ($LogFileMode) {
        'NewFile' {
            $mode = @($LogmanMode.EVENT_TRACE_USE_GLOBAL_SEQUENCE, $LogmanMode.EVENT_TRACE_FILE_MODE_NEWFILE) -join ','

            # In order to use newfile, file name must contain "%d"
            if ($FileName -notlike "*%d*") {
                $FileName = [System.IO.Path]::GetFileNameWithoutExtension($FileName) + "_%d.etl"
            }
            break
        }

        'Circular' {
            $mode = @($LogmanMode.EVENT_TRACE_USE_GLOBAL_SEQUENCE, $LogmanMode.EVENT_TRACE_FILE_MODE_CIRCULAR) -join ','

            if (-not $PSBoundParameters.ContainsKey('MaxFileSizeMB')) {
                $MaxFileSizeMB = 2048
            }
            break
        }
    }

    $ETWSessionName = "ExchangeDebugTraces"
    $ProviderName = '{79BB49E6-2A2C-46E4-9167-FA122525D540}'
    $BufferSizeKB = 128
    $TraceOutputPath = Join-Path $Path -ChildPath $FileName

    $logmanArgs = @(
        'start', $ETWSessionName,
        '-p', $ProviderName,
        '-o', $TraceOutputPath,
        '-bs', $BufferSizeKB,
        '-max', $MaxFileSizeMB,
        '-mode', $mode,
        '-ets'
    )

    $logmanCommand = "logman.exe $logmanArgs"

    # Start ETW session
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $logmanCommand)) {
        # Write-Verbose "executing $logmanCommand"
        # $logmanResult = Invoke-Expression $logmanCommand

        Write-Log "Invoking: logman.exe $logmanArgs"
        $logmanResult = & logman.exe $logmanArgs

        if ($LASTEXITCODE -ne 0) {
            Write-Error -Message "Failed to start an ETW session `"$ETWSessionName`". Error: 0x$("{0:X}" -f $LASTEXITCODE)"
            return
        }
    }

    New-Object PSCustomObject -Property @{
        LogmanResult    = $logmanResult
        LogmanCommand   = $logmanCommand
        ETWSessionName  = $ETWSessionName
        TraceOutputPath = $TraceOutputPath
        ConfigFile      = $ConfigFile
        MaxFileSizeMB   = $MaxFileSizeMB
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
        Session           = $session
        ConfigFileRemoved = $($null -eq $err)
        Path              = $session.LogFileName
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
        [Parameter(Mandatory = $true)]
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
        $null = New-Item $Destination -ItemType Directory -ErrorAction Stop
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
            $null = New-Item $zipFilePath -ItemType file

            $zipStream = New-Object System.IO.FileStream -ArgumentList $zipFilePath, ([IO.FileMode]::Open)
            $zipArchive = New-Object System.IO.Compression.ZipArchive -ArgumentList $zipStream, ([IO.Compression.ZipArchiveMode]::Create)

            $files = @(Get-ChildItem $Path -Recurse | Where-Object { -not $_.PSIsContainer })
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
            ZipFilePath  = $zipFilePath.ToString()
            FilesRemoved = $filesRemoved -eq $true
        }
    }
    else {
        throw "Zip file wasn't successfully created at $zipFilePath"
    }
}

function Save-Process {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $win32Process = Get-CimInstance Win32_Process
    $win32Process | Export-Clixml -Path $(Join-Path $Path -ChildPath "Win32_Process_$($env:COMPUTERNAME)_$(Get-Date -Format "yyyyMMdd_HHmmss").xml")

    foreach ($proc in $win32Process) {
        $proc.Dispose()
    }
}

<#
.SYNOPSIS
Wait until user enters Enter key or Ctrl+C.
This is only possible when Console is available.
Console is not available in PowerShell ISE and in this case Ctrl+C will interrupt.
#>
function Wait-EnterOrControlC {
    [CmdletBinding()]
    param()

    # Check if a console is available, and if so, manually detect Enter key and Ctrl+C.
    $consoleAvailable = $false

    try {
        $Host.UI.RawUI.FlushInputBuffer()
        [Console]::TreatControlCAsInput = $true
        $consoleAvailable = $true
    }
    catch {
        # Ignore
    }

    if ($consoleAvailable) {
        $detectedKey = $null

        while ($true) {
            [ConsoleKeyInfo]$keyInfo = [Console]::ReadKey(<# intercept #> $true)

            # Enter or Ctrl+C exits the wait loop
            if ($keyInfo.Key -eq [ConsoleKey]::Enter) {
                Write-Log "Enter key is detected"
                $detectedKey = 'Enter'
            }
            elseif (($keyInfo.Modifiers -band [ConsoleModifiers]'Control') -and ($keyInfo.Key -eq [ConsoleKey]::C)) {
                Write-Log "Ctrl+C is detected"
                $detectedKey = 'Ctrl+C'
            }

            if ($detectedKey) {
                break
            }
        }

        [Console]::TreatControlCAsInput = $false
        Write-Host
    }
    else {
        # Read-Host is not used here because it'd block background tasks.
        # When using UI.ReadLine(), Ctrl+C cannot be detected.
        $null = $host.UI.ReadLine()
        $detectedKey = 'Enter'
    }

    [PSCustomObject]@{
        Key                = $detectedKey
        IsConsoleAvailable = $consoleAvailable
    }
}

<#
.SYNOPSIS
    Helper function that returns a string of command expression with given parameters.

.EXAMPLE
    Get-CommandExpression -Command Get-Process -Parameters @{ Name = 'Outlook' }

.EXAMPLE
    Get-CommandExpression -Invocation $MyInvocation

.NOTES
    This function does not check if the given parameters belong to the same ParameterSet.
    So, there is no guarantee that the output expression runs successfully.

    For example, the following returns "Get-Process -Name Outlook -Id 123", but "Name" & "Id" parameters cannot be used simultaneously.

    Get-CommandExpression -Command Get-Process -Parameters @{ Name = 'Outlook'; Id = '123' }
#>
function Get-CommandExpression {
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([string])]
    param(
        [Parameter(ParameterSetName = 'Command', Mandatory)]
        $Command,
        [Parameter(ParameterSetName = 'Command', Mandatory)]
        [Hashtable]$Parameters,
        [Parameter(ParameterSetName = 'Invocation', Mandatory)]
        [System.Management.Automation.InvocationInfo]
        $Invocation
    )

    if ($PSCmdlet.ParameterSetName -eq 'Invocation') {
        $Command = $Invocation.MyCommand
        $Parameters = $Invocation.BoundParameters
    }

    if ($Command -is [string]) {
        $Command = Get-Command $Command -ErrorAction SilentlyContinue

        if (-not $Command) {
            Write-Error "Cannot find $Command"
            return
        }
    }

    if ($Command -isnot [System.Management.Automation.CommandInfo]) {
        Write-Error "Need a CommandInfo for Command paramter"
        return
    }

    # It is expected to be passed a FunctionInfo or CmdletInfo. Anything else (such as ScriptInfo) is not really expected while it just returns an empty string
    if ($Command -isnot [System.Management.Automation.FunctionInfo] -or $Command -isnot [System.Management.Automation.CmdletInfo]) {
        Write-Verbose "Passed Command is of type $($Command.GetType().FullName)"
    }

    $sb = New-Object System.Text.StringBuilder -ArgumentList $Command.Name

    foreach ($param in $Parameters.GetEnumerator()) {
        # Skip if the given parameter name is not available
        if (-not $Command.Parameters.ContainsKey($param.Key)) {
            continue
        }

        $null = $sb.Append(" -$($param.Key)")

        # If this is a Switch parameter, no need to add value
        if ($Command.Parameters[$param.Key].SwitchParameter) {
            continue
        }

        $value = $param.Value

        if ($value -is [string] -and $value.IndexOf(' ') -ge 0) {
            $value = "'$value'"
        }
        elseif ($value -is [System.Collections.IDictionary]) {
            $tmp = New-Object System.Text.StringBuilder -ArgumentList '@{'

            foreach ($entry in $value.GetEnumerator()) {
                $null = $tmp.Append("'$($entry.Key)' = ").Append("'$($entry.Value)'").Append(';')
            }

            $null = $tmp.Remove($tmp.Length - 1, 1)
            $null = $tmp.Append('}')
            $value = $tmp.ToString()
        }
        elseif ($value -is [System.Collections.ICollection]) {
            $value = $value -join ', '
        }

        $null = $sb.Append(" $value")
    }

    $sb.ToString()
}

function Collect-ExTRA {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param(
        [Parameter(Mandatory = $true)]
        $Path,
        [string[]]$Components,
        [Hashtable]$ComponentAndTags,
        [ValidateSet('NewFile', 'Circular')]
        [string]$LogFileMode = 'NewFile',
        [int]$MaxFileSizeMB = 512,
        [switch]$SkipArchive
    )

    if (-not $Components.Count -and -not $ComponentAndTags.Count) {
        Write-Error "Both Components and ComponentAndTags parameters cannot be empty at the same time."
        return
    }

    if (-not (Test-Path $Path)) {
        $null = New-Item $Path -ItemType directory -ErrorAction Stop
    }

    $Path = Resolve-Path $Path
    $tempPath = Join-Path $Path -ChildPath $([Guid]::NewGuid().ToString())
    $null = New-Item $tempPath -ItemType directory -ErrorAction Stop

    $currentUser = Resolve-User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

    # Open log file
    Open-Log -Path (Join-Path $tempPath 'Log.csv') -WithBOM
    Write-Log "COMPUTERNAME:$env:COMPUTERNAME"
    Write-Log "PSVersion:$($PSVersionTable.PSVersion); CLRVersion:$($PSVersionTable.CLRVersion)"
    Write-Log "PROCESSOR_ARCHITECTURE:$env:PROCESSOR_ARCHITECTURE; PROCESSOR_ARCHITEW6432:$env:PROCESSOR_ARCHITEW6432"
    Write-Log "Running as $($currentUser.Name) ($($currentUser.Sid))"
    Write-Log "Invocation:$(Get-CommandExpression -Invocation $MyInvocation)"

    $sessionInfo = $null
    $processCaptureJob = $null

    try {
        Write-Log "Starting Start-ProcessCapture as a job"
        # Start Start-ProcessCapture as a job (Named event is for inter PS process communication)
        $processCaptureEventName = [Guid]::NewGuid().ToString()
        $processCaptureEvent = New-Object System.Threading.EventWaitHandle($false, [Threading.EventResetMode]::ManualReset, $processCaptureEventName)
        $processCaptureJob = Start-Job -ScriptBlock ${Function:Start-ProcessCapture} -ArgumentList $tempPath, $processCaptureEventName

        if (-not $PSBoundParameters.ContainsKey('MaxFileSizeMB') -and $LogFileMode -eq 'Circular') {
            $MaxFileSizeMB = 2048
        }

        Write-Log "Starting ExTRA"
        $err = $($sessionInfo = Start-ExTRA -Path $tempPath -Components $Components -ComponentAndTags $ComponentAndTags -LogFileMode $LogFileMode -MaxFileSizeMB $MaxFileSizeMB) 2>&1

        # In case of 0x803000b7 == "Data Collector Set already exists", stop the running sesssion and try one more time.
        if ($err -and $LASTEXITCODE -eq 0x803000b7) {
            Write-Log "Start-ExTRA's LastExitCode was 0x803000b7 and retrying..."
            $stopError = $($null = Stop-ExTRA) 2>&1

            if (-not $stopError) {
                $sessionInfo = Start-ExTRA -Path $tempPath -Components $Components -ComponentAndTags $ComponentAndTags -LogFileMode $LogFileMode -MaxFileSizeMB $MaxFileSizeMB -ErrorAction Stop
            }
        }

        if (-not $sessionInfo) {
            Write-Error "Failed to start ExTRA. ExitCode:$LASTEXITCODE"
            return
        }

        Write-Log "ExTRA has successfully started"
        Write-Host "ExTRA has successfully started" -ForegroundColor Green
        Write-Host "Press enter to stop: " -NoNewline

        $waitResult = Wait-EnterOrControlC

        if ($waitResult.Key -eq 'Ctrl+C') {
            Write-Log "Ctrl+C is detected"
            Write-Warning "Ctrl+C is detected"
        }
        else {
            $startSuccess = $true
        }
    }
    finally {
        if ($sessionInfo) {
            # Save Config file
            Copy-Item $sessionInfo.ConfigFile -Destination $tempPath -ErrorAction SilentlyContinue

            $null = Stop-ExTRA -ETWSessionName $sessionInfo.ETWSessionName
        }

        if ($processCaptureJob) {
            $null = $processCaptureEvent.Set()
            Wait-Job -Job $processCaptureJob | Remove-Job
            $processCaptureEvent.Close()
        }

        Close-Log
    }

    if (-not $startSuccess) {
        Write-Warning "ExTRA was canceled. Please remove files in `"$tempPath`" if not needed."
        return
    }

    $archiveName = "ExTRA_$($env:COMPUTERNAME)_$(Get-Date -Format "yyyyMMdd_HHmmss")"

    if ($SkipArchive) {
        Rename-Item $tempPath -NewName $archiveName
        return
    }

    $null = Compress-Folder -Path $tempPath -ZipFileName $archiveName -Destination $Path -RemoveFiles
    Remove-Item $tempPath -Force

    Write-Host "The collected data is in `"$(Join-Path $Path $zipFileName).zip`""
    Invoke-Item $Path
}

# Some emoji chars (https://unicode.org/emoji/charts/full-emoji-list.html)
$Script:Emoji = @{
    Information = [Char]::ConvertFromUtf32(0x2139)
    Warning     = [Char]::ConvertFromUtf32(0x26A0)
    Error       = [Char]::ConvertFromUtf32(0x26D4) # This is actually "NoEntry" emoji
}

Export-ModuleMember -Function Get-ExchangeTraceComponent, Start-ExTRA, Stop-ExTRA, Get-EtwSession, Stop-EtwSession, Collect-ExTRA