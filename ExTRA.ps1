#requires -Version 3.0

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
        [Parameter(Mandatory = $true)]
        [Hashtable]$ComponentAndTags,
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
    $ProviderName = "Microsoft Exchange Server 2010" # Provider Guid: {79BB49E6-2A2C-46E4-9167-FA122525D540}
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

    [PSCustomObject]@{
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
    param (
        [string]
        $ETWSessionName = "ExchangeDebugTraces"
    )

    $sess = & logman.exe -ets
    $extraSession = $sess | Where-Object {$_ -like "*$ETWSessionName*"}
    if (-not $extraSession) {
        Write-Warning "Cannot find a session `"$ETWSessionName`""
        return
    }

    $logmanResult = & logman.exe stop $ETWSessionName -ets

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to stop ETW session. Error: 0x$("{0:X}" -f $LASTEXITCODE)"
    }

    # Remove EnabledTraces.Config
    $ConfigFile = "C:\EnabledTraces.Config"
    $err = $(Remove-Item $ConfigFile -Force) 2>&1
    if ($err) {
        Write-Warning "Please remove $ConfigFile.`n$err"
    }

    [PSCustomObject]@{
        LogmanResult = $logmanResult
        ConfigFileRemoved = $($null -eq $err)
    }
}

function Compress-Folder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$Path,
        [string]$Destination,
        [string]$ZipFileName,
        [bool]$IncludeDateTime,
        [switch]$RemoveFiles
    )

    $Path = Resolve-Path $Path

    $zipFileNameWithouExt = [System.IO.Path]::GetFileNameWithoutExtension($ZipFileName)
    if ($IncludeDateTime) {
        # Create a zip file in TEMP folder with current date time in the name
        # e.g. Contoso_20160521_193455.zip
        $currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
        $zipFileName = $zipFileNameWithouExt + "_" + "$currentDateTime.zip"
    }
    else {
        $zipFileName = "$zipFileNameWithouExt.zip"
    }
    $zipFilePath = Join-Path ((Get-Item ($env:TEMP)).FullName) -ChildPath $zipFileName

    $NETFileSystemAvailable = $true

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    }
    catch {
        Write-Warning "System.IO.Compression.FileSystem wasn't found. Using alternate method"
        $NETFileSystemAvailable = $false
    }

    if ($NETFileSystemAvailable) {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $zipFilePath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    }
    else {
        # Use Shell.Application COM
        $delayMilliseconds = 200

        # Create a zip file manually
        $shellApp = New-Object -ComObject Shell.Application
        Set-Content $zipFilePath ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
        (Get-Item $zipFilePath).IsReadOnly = $false

        $zipFile = $shellApp.NameSpace($zipFilePath)

        # Start copying the whole and wait until it's done. Note: CopyHere works asynchronously.
        $zipFile.CopyHere($Path)

        # Now wait
        $inProgress = $true
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

    # Move the zip file from TEMP folder to Destination (if Destination is not given, then move it to Path)
    if (Test-Path $zipFilePath) {
        # If Destination doesn't exist, create it. In case of failure, use Path.
        if ($Destination -and -not (Test-Path $Destination)) {
            $newDir = New-Item $Destination -ItemType directory -ErrorAction SilentlyContinue
            if (-not $newDir) {
                $Destination = $null
            }
        }

        if ($Destination) {
            Move-Item $zipFilePath -Destination $Destination
        }
        else {
            Move-Item $zipFilePath -Destination $Path
        }

        # If requested, remove zipped files
        if ($RemoveFiles) {
            # At this point, don't use Write-Log since the log file will be deleted too
            Write-Verbose "Removing zipped files"
            Get-ChildItem $Path -Exclude $ZipFileName | Remove-Item -Recurse -Force
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
        Compress-Folder -Path $tempPath -ZipFileName $zipFileName -Destination $Path -RemoveFiles
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