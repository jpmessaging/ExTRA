## Overview

ExTRA.psm1 contains functions to collect ETW traces on an Exchange Server

[Download](https://github.com/jpmessaging/ExTRA/releases/download/v2024-12-20/ExTRA.psm1)

SHA256: `74AA42748A41644F80C18134384A69081BF6B07BB296EA1BAAF576F40A325EBF`

You can get the file hash with `Get-FileHash`:

  ```PowerShell
  Get-FileHash <Path to .psm1 file> -Algorithm SHA256
  ```

## How to use

1. Right-click ExTRA.psm1 file and click Property

    In the General tab, if you see `This file came from another computer and might be blocked to help protect this computer`, check `Unblock`

2. Place ExTRA.psm1 on an Exchange Server
3. Start a PowerShell console as administrator
4. Import ExTRA.psm1

    ```PowerShell
    Import-Module <path to ExTRA.psm1> -DisableNameChecking
    ```

    e.g.
    ```PowerShell
    Import-Module C:\temp\ExTRA.psm1 -DisableNameChecking
    ```

5. Run Collect-ExTRA

    Note: Follow Microsoft engineer's instruction regarding which components & tags to trace.
    When the trace has successfully started, it shows `ExTRA has successfully started. Press enter to stop:`

    ```
    Collect-ExTRA -Path <output folder> -Components <array of component names> -ComponentAndTags <hash table of components & tags to trace>
    ```

    e.g.
    ```
    Collect-ExTRA -Path C:\temp -Components ADProvider, Data.Storage -ComponentAndTags @{'SystemLogging'= 'SystemNet,SystemNetSocket'}
    ```

    ⚠️ For components listed in `Components` parameter, trace is enabled for all tags.  For those in `ComponentAndTags` parameter, trace is enabled only for the specified tags.


6.  Reproduce the issue

7. Press Enter key to stop tacing

A zip file `"ExTRA_<ServerName>_<DateTime>.zip"` is created in the output folder specified in step 5.
Please send this to a Microsoft engineer for analysis.

## License
Copyright (c) 2020 Ryusuke Fujita

This software is released under the MIT License.  
http://opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

