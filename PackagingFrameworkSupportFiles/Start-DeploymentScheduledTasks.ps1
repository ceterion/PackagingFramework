#Requires -Version 4.0
#Requires -RunAsAdministrator

Try {

    ### Show basic online help (only when ScheduleTask is not running)
    Cls
    Write-host "-------------------------------------------------------------------------"
    Write-host ""
    Write-host "NOTE: "
    Write-host ""
    Write-host "Please make sure you have set the variables in the .json file."
    Write-host ""
    Write-host "Please also make sure to start this script with local admin permissions."
    Write-host ""
    Write-host "Please also make sure the PowerShell execution policy is configured in"
    Write-host "a way that allows script execution (i.e. Set-ExecutionPolicy RemoteSigned)"
    Write-host ""
    Write-host "When UAC is enabled make sure to start this script elevated, when using a"
    Write-host "built-in administrator account make sure the policy User Account Control"
    Write-host "Admin Approval Mode for Built-in Administrators account is disabled."
    Write-host ""
    Write-host "If something general fails please check [$LogFile]"
    Write-host "and [$WorkDir\Install-MultiplePackages.log] for details."
    Write-host ""
    Write-host "If a specific package fails please check the package log, typical at"
    Write-host "[$env:WinDir\Logs\Software\<PackageName>\<PackageName>_Install.log]"
    Write-host ""
    Write-host "-------------------------------------------------------------------------"
    Write-host ""
    If ((Get-ScheduledTask Start-DeploymentScheduledTasks -ErrorAction SilentlyContinue).State -eq 'Running') { Start-Sleep 15 }

    # Read Json file, create variables, and resolve environment Variables)
    $JsonObject = Get-Content '.\Start-DeploymentScheduledTasks.json' | ConvertFrom-Json 
    ForEach ($Parameter in $JsonObject.psobject.Properties) {
        $Name = $Parameter.Name
        $value = $Parameter.value
        #$JsonObject.$Name = [System.Environment]::ExpandEnvironmentVariables($value)
        $value = [System.Environment]::ExpandEnvironmentVariables($value)
        Set-Variable -Name $name -Value $value
    }

    ### Create temp folder for log file and temp files
    If (-not(Test-Path -path "$WorkDir" -PathType Container)) {New-Item -path "$WorkDir" -type directory}

    ### Start transcript logging
    Start-Transcript -Path "$LogFile" -append

    ### Startup delay after reboot to give system time to startup properly (only when ScheduledTasks is running)
    If ((Get-ScheduledTask Start-DeploymentScheduledTasks -ErrorAction SilentlyContinue).State -eq 'Running') { Write-Host "$StartupDelay seconds startup delay" ; Start-Sleep $StartupDelay }

    ### Map network drive (if not already mapped, when params specified
    If (-not (Test-Path -Path $NetworkShareDriveLetter`:\ -PathType Container)) {
        if (($NetworkShare) -and ($NetworkShareDriveLetter) -and ($NetworkShareUser) -and ($NetworkSharePassword))
        {
            Write-Host "Connect network share [$NetworkShare] to drive [$NetworkShareDriveLetter] as [$NetworkShareUser]"
            $NetworkSharePasswordSecureString = ConvertTo-SecureString $NetworkSharePassword -AsPlainText -Force
            $NetworkShareCredential = New-Object System.Management.Automation.PsCredential ("$NetworkShareUser",$NetworkSharePasswordSecureString)
            New-PSDrive -Name $NetworkShareDriveLetter -Root $NetworkShare -Persist -PSProvider "FileSystem" -Credential $NetworkShareCredential -ErrorAction Stop
        } 
        elseif (($NetworkShare) -and ($NetworkShareDriveLetter) -and (-not($NetworkShareUser)) -and (-not($NetworkSharePassword)))
        {
            Write-Host "Connect network share [$NetworkShare] to drive [$NetworkShareDriveLetter] as [Integrated]"
            New-PSDrive -Name $NetworkShareDriveLetter -Root $NetworkShare -Persist -PSProvider "FileSystem" -ErrorAction Stop
        }
        else
        {
            Write-host 'Skip network drive mapping, not all parameters where specified, assuming you are using local folders or drive is already mapped'
        }
    } else {Write-Host "Drive[$NetworkShareDriveLetter] already connected"}

    ### Install package framework (if not already installed in current version)
    if ((Get-Module -ListAvailable -Name PackagingFramework).Version -lt $PackageFrameworkVersion) {
        Write-Host "Module does not exist in expected version, starting [$DeployScriptsFolder\PackagingFrameworkSetup.exe] setup"
        $env:SEE_MASK_NOZONECHECKS = '1'     # https://support.microsoft.com/en-us/help/889815
        $Process = Start-Process -FilePath "$DeployScriptsFolder\PackagingFrameworkSetup.exe" -PassThru -ArgumentList '/S' -ErrorAction Stop
        Wait-Process -InputObject $Process  -ErrorAction Stop
        if ($Process.ExitCode -ne 0) { Write-Host "Installation of [$DeployScriptsFolder\PackagingFrameworkSetup.exe] failed with return code [$($Process.ExitCode)]" ; Throw  "Installation of [$DeployScriptsFolder\PackagingFrameworkSetup.exe] failed with return code [$($Process.ExitCode)]" } else { Write-Host "Installed [$DeployScriptsFolder\PackagingFrameworkSetup.exe] was successful" }
    }

    ### Make a local copy of this ps1 and cmd file to call it later via a Scheduled task
    Write-host "Copy [$DeployScriptsFolder\Start-DeploymentScheduledTasks.ps1] to [$WorkDir\Start-DeploymentScheduledTasks.ps1]"
    Copy-Item -Path "$DeployScriptsFolder\Start-DeploymentScheduledTasks.ps1" -Destination "$WorkDir\Start-DeploymentScheduledTasks.ps1" -ErrorAction Stop
    Write-host "Copy [$DeployScriptsFolder\Start-DeploymentScheduledTasks.cmd] to [$WorkDir\Start-DeploymentScheduledTasks.cmd]"
    Copy-Item -Path "$DeployScriptsFolder\Start-DeploymentScheduledTasks.cmd" -Destination "$WorkDir\Start-DeploymentScheduledTasks.cmd" -ErrorAction Stop
    Write-host "Copy [$DeployScriptsFolder\Start-DeploymentScheduledTasks.json] to [$WorkDir\Start-DeploymentScheduledTasks.json]"
    Copy-Item -Path "$DeployScriptsFolder\Start-DeploymentScheduledTasks.json" -Destination "$WorkDir\Start-DeploymentScheduledTasks.json" -ErrorAction Stop

    ### Make a local copy of the csv file (%computername%.csv wins over default.csv over Start-DeploymentScheduledTasks.csv, never overwrite if already exists)
    If (-not (Test-Path -Path "$WorkDir\Start-DeploymentScheduledTasks.csv" -PathType Leaf))
    {
        If (Test-Path -Path "$DeployScriptsFolder\$env:COMPUTERNAME.csv"){
            Write-host "Copy [$DeployScriptsFolder\$env:COMPUTERNAME.csv] to [$WorkDir\Start-DeploymentScheduledTasks.csv]"
            Copy-Item -Path "$DeployScriptsFolder\$env:COMPUTERNAME.csv" -Destination "$WorkDir\Start-DeploymentScheduledTasks.csv" -ErrorAction Stop
        }
        elseif (Test-Path -Path "$DeployScriptsFolder\Default.csv"){
            Write-host "Copy [$DeployScriptsFolder\Default.csv] to [$WorkDir\Start-DeploymentScheduledTasks.csv]"
            Copy-Item -Path "$DeployScriptsFolder\Default.csv" -Destination "$WorkDir\Start-DeploymentScheduledTasks.csv" -ErrorAction Stop
        }
        elseif (Test-Path -Path "$DeployScriptsFolder\Start-DeploymentScheduledTasks.csv"){
            Write-host "Copy [$DeployScriptsFolder\Start-DeploymentScheduledTasks.csv] to [$WorkDir\Start-DeploymentScheduledTasks.csv]"
            Copy-Item -Path "$DeployScriptsFolder\Start-DeploymentScheduledTasks.csv" -Destination "$WorkDir\Start-DeploymentScheduledTasks.csv" -ErrorAction Stop
        }
        else
        {
            Write-host "No matching .csv file found at [$DeployScriptsFolder]" 
            throw "No matching .csv file found at [$DeployScriptsFolder]"
        }
    }

    ### Create Scheduled task (if not already exists) 
    If (-not ((Get-ScheduledTask Start-DeploymentScheduledTasks -ErrorAction SilentlyContinue).State))
    {
        Write-Host "Create Scheduled Task [Start-DeploymentScheduledTasks]"
        $ScheduledTaskAction = New-ScheduledTaskAction –Execute "$env:WinDir\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NonInteractive -NoLogo -NoProfile -ExecutionPolicy Bypass -File ""$WorkDir\Start-DeploymentScheduledTasks.ps1""" -WorkingDirectory "$WorkDir" -ErrorAction Stop
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -AtStartup -ErrorAction Stop 
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction  -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet
        Register-ScheduledTask -TaskName 'Start-DeploymentScheduledTasks' -InputObject $ScheduledTask -User $SchTasksUser -Password $SchTasksPassword -ErrorAction Stop 
    }

    ### Start deployment
    Write-Host "Start [PowerShell.exe] with [Install-MultiplePackages] command"
    $Process = Start-Process -FilePath "$env:WinDir\System32\WindowsPowerShell\v1.0\PowerShell.exe" -PassThru -ArgumentList "-ExecutionPolicy Bypass -Command & {Import-Module PackagingFramework -force ; Install-MultiplePackages -CSVFile $WorkDir\Start-DeploymentScheduledTasks.csv -PackageFolder $PackagesFolder -silent}" -ErrorAction Stop
    Wait-Process -InputObject $Process -ErrorAction Stop
    if ($Process.ExitCode -ne 0) { Write-Host "Execution of Install-MultiplePackages failed with return code [$($Process.ExitCode)], please check [Install-MultiplePackages.log] and [<Packagename>_install.log]" ; Throw  "Execution of Install-MultiplePackages failed with return code [$($Process.ExitCode)], please check [Install-MultiplePackages.log] and [<Packagename>_install.log]" } else { Write-Host "Execution of Install-MultiplePackages returned with return code [$($Process.ExitCode)]" }

    ### Remove scheduled task and temp file (but only when complete)
    $CSVFile = Get-Content -Path "$WorkDir\Start-DeploymentScheduledTasks.csv" -ErrorAction Stop
    $SearchResult = Select-String -InputObject $CSVFile -Pattern "COMPLETED" -ErrorAction Stop
    if($SearchResult) {
        Write-Host "CSV file [$WorkDir\Start-DeploymentScheduledTasks.csv] processed completly"
        Write-Host "Removing ScheduledTask [Start-DeploymentScheduledTasks]"
        Unregister-ScheduledTask -TaskName 'Start-DeploymentScheduledTasks' -Confirm:$false -ErrorAction Stop
        Remove-Item -Path "$WorkDir\Start-DeploymentScheduledTasks.ps1" -ErrorAction Stop
        Remove-Item -Path "$WorkDir\Start-DeploymentScheduledTasks.cmd" -ErrorAction Stop
        Remove-Item -Path "$WorkDir\Start-DeploymentScheduledTasks.json" -ErrorAction Stop
        if($NetworkShareDriveLetter){ Remove-PSDrive -Name $NetworkShareDriveLetter -Force -ErrorAction Stop}
    } 

    # Stop Transcript logfile
    Stop-Transcript

}
Catch
{
    Write-Host "Unexpected error:"
    Write-host $Error
    Stop-Transcript
    Start-Process "notepad.exe" -ArgumentList $LogFile
}

