# Overview

ExTRA.ps1 contains functions to collect a ETW trace on a Exchange Server

# How to use

1. Download ExTRA.ps1 and unblock the file

    [Download](https://github.com/jpmessaging/ExTRA/releases/download/v2019-10-04/ExTRA.ps1)

    1.1. Right-click the ps1 file and click [Property]  
    1.2. In the [General] tab, if you see "This file came from another computer and might be blocked to help protect this computer], check [Unblock]

2. Place ExTRA.ps1 on a Exchange Server
3. Start a PowerShell console
4. Dot source the ExTRA.ps1

    ```PowerShell
    . <path to ExTRA.ps1>

    e.g.
    . C:\temp\ExTRA.ps1
    ```

5. Run Collect-ExTRA

    Note: Follow Microsoft engieer's instruction regarding which components & tags to trace.  
    When the trace has successfully started, it shows `"ExTRA has successfully started. Hit enter to stop ExTRA"`  

    ```PowerShell
    Collect-ExTRA -Path <output folder> -ComponentAndTags <hash table of components & tags to trace>

    e.g.
    Collect-ExTRA -Path C:\temp -ComponentAndTags @{'ADProvider'='*';'Data.Storage'='*';'InfoWorker.Sharing'='LocalFolder,SharingEngine'}
    ```

    
6.  Reproduce the issue

7. Hit Enter to stop tacing

A zip file `"ExTRA_<ServerName>_<DateTime>.zip"` is created in the output folder specified in step 5.  
Please send this to a Microsoft engineer for analysis.