[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter, [Parameter(Mandatory=$false)] [switch]$AllowRebootPassThru = $true)
Try {

    # Import Packaging Framework module
    $Global:DeploymentType=$Script:DeploymentType ; $Global:DeployMode=$Script:DeployMode ; $Global:CustomParameter=$Script:CustomParameter ; $Global:AllowRebootPassThru = $Script:AllowRebootPassThru ; Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; Remove-Module PackagingFrameworkExtension -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script} ; Invoke-PackageStart

    # Install
    If ($deploymentType -ieq 'Install') {
        # No install        
	}

    # Uninstall
    If ($deploymentType -ieq 'Uninstall') {
        # No uninstall        
	}

    ############################################################################################################################
    # Example section, it's recoment not to run the whole script, run it example by example in ISE with "Run selection (F8)"
    ############################################################################################################################
    $RunAllExamples = $false
    if ($RunAllExamples -eq $true)
    {

    #region Variables

        # Show some variables
        Write-Log 'Show some general variables:'
        Write-Log "Computer Name:                     $ComputerName"
        Write-Log "User Name:                         $UserName"
        Write-Log "Windows Directory:                 $WinDir"
        Write-Log "Windows System32 Directory:        $SysDir"
        Write-Log "Temp Directory:                    $Temp"
        Write-Log "Program Files Directory:           $ProgramFiles"
        Write-Log "Program Files (x86) Directory:     $ProgramFilesX86"
        Write-Log "Is64Bit:                           $Is64Bit"
        Write-Log "IsServerOS:                        $IsServerOS"
        Write-Log "IsWorkStationOS:                   $IsWorkStationOS"
        Write-Log "Applications:                      $Applications"
        Write-Log "Application Accounts:              $Accounts"

        # List all variables as strig
        Get-Variable | Out-String

        # List all variables as grid view
        Get-Variable | Out-GridView

        # Some examples with the "Is..." boolean variables
        If ($IsCitrixAgent -eq $true) {Write-Log "This system is a Citrix Agent"} else {Write-Log "This system is NOT a Citrix Agent"}
        If ($IsCitrixBroker -eq $true) {Write-Log "This system is a Citrix Broker"} else {Write-Log "This system is NOT a Citrix Broker"}
        If ($IsRDHost -eq $true) {Write-Log "This system is a RDS Host in Application Mode"} else {Write-Log "This system is NOT a RDS Host in Application Mode"}
    
        # Example how to resolve variables in text strings when needed
        $MyTestString = 'Environemnt variable %USERNAME%, powershell variable $PSHOME and a powershell environment variable $:WINDIR'
        Write-Host (Expand-Variable -InputString $MyTestString) # Resolve all environment and powershell variables
        Write-Host (Expand-Variable -InputString $MyTestString -VarType environment)   #resolve environment variables only
        Write-Host (Expand-Variable -InputString $MyTestString -VarType powershell)    #resolve powershell variables only

        # Access a buil-in SCCM variable, e.g. _SMSTSLogPath
        Write-Log $SMSTSEnvironment.Value("_SMSTSLogPath")

        # List all SCCM variables (Note: Will only work when running inside a SCCM task sequence)
        $SMSTSEnvironment.GetVariables() | % { Write-Log "$_ = $($SMSTSEnvironment.Value($_))" } 

        # Is<OSversion> variables
        Write-Log "IsWinVista=$IsWinVista"
        Write-Log "IsWin2008=$IsWin2008"
        Write-Log "IsWin7=$IsWin7"
        Write-Log "IsWin2008R2=$IsWin2008R2"
        Write-Log "IsWin8=$IsWin8"
        Write-Log "IsWin2012=$IsWin2012"
        Write-Log "IsWin81=$IsWin81"
        Write-Log "IsWin2012R2=$IsWin2012R2"
        Write-Log "IsWin10=$IsWin10"
        Write-Log "IsWin11=$IsWin11"
        Write-Log "IsWin2016=$IsWin2016"
        Write-Log "IsWin2019=$IsWin2019"
        Write-Log "IsWin2022=$IsWin2022"
        
        # IsAtLeast<OSVersion>
        Write-Log "IsAtLeastWinVista=$IsAtLeastWinVista"
        Write-Log "IsAtLeastWin2008=$IsAtLeastWin2008"
        Write-Log "IsAtLeastWin7=$IsAtLeastWin7"
        Write-Log "IsAtLeastWin2008R2=$IsAtLeastWin2008R2"
        Write-Log "IsAtLeastWin8=$IsAtLeastWin8"
        Write-Log "IsAtLeastWin2012=$IsAtLeastWin2012"
        Write-Log "IsAtLeastWin81=$IsAtLeastWin81"
        Write-Log "IsAtLeastWin2012R2=$IsAtLeastWin2012R2"
        Write-Log "IsAtLeastWin10=$IsAtLeastWin10"
        Write-Log "IsAtLeastWin11=$IsAtLeastWin11"
        Write-Log "IsAtLeastWin2016=$IsAtLeastWin2016"
        Write-Log "IsAtLeastWin2019=$IsAtLeastWin2019"
        Write-Log "IsAtLeastWin2022=$IsAtLeastWin2022"

        # IsAtMoast<OSVersion>
        Write-Log "### IsAtMost ###" 
        Write-Log "IsAtMostWinVista=$IsAtMostWinVista"
        Write-Log "IsAtMostWin2008=$IsAtMostWin2008"
        Write-Log "IsAtMostWin7=$IsAtMostWin7"
        Write-Log "IsAtMostWin2008R2=$IsAtMostWin2008R2"
        Write-Log "IsAtMostWin8=$IsAtMostWin8"
        Write-Log "IsAtMostWin2012=$IsAtMostWin2012"
        Write-Log "IsAtMostWin81=$IsAtMostWin81"
        Write-Log "IsAtMostWin2012R2=$IsAtMostWin2012R2"
        Write-Log "IsAtMostWin10=$IsAtMostWin10"
        Write-Log "IsAtMostWin11=$IsAtMostWin11"
        Write-Log "IsAtMostWin2016=$IsAtMostWin2016"
        Write-Log "IsAtMostWin2019=$IsAtMostWin2019"
        Write-Log "IsAtMostWin2022=$IsAtMostWin2022"

        # Office C2R Details
        Write-Log "### Office C2R ###" 
        Write-Log "OfficeVersion=$OfficeVersion"
        Write-Log "OfficeVersionMajor=$OfficeVersionMajor"
        Write-Log "OfficeVersionMinor=$OfficeVersionMinor"
        Write-Log "OfficeVersionBuild=$OfficeVersionBuild"
        Write-Log "OfficeVersionRevision=$OfficeVersionRevision"
        Write-Log "OfficeBitness=$OfficeBitness"
        Write-Log "OfficeCDNBaseURL=$OfficeCDNBaseURL"
        Write-Log "OfficeChannel=$OfficeChannel"
    
        # OS Version Deatils
        Write-Log "### OSVersion Deatils ###"
        Write-Log "OSVersion=$OSVersion"
        Write-Log "OSVersionMajor=$OSVersionMajor"
        Write-Log "OSVersionMinor=$OSVersionMinor"
        Write-Log "OSVersionBuild=$OSVersionBuild"
        Write-Log "OSVersionRevision=$OSVersionRevision"

        # Various Get-Parameter examples
        Get-Parameter 'TestParam'
        Get-Parameter 'TestParamBool'
        Get-Parameter 'TestParamInteger'
        Get-Parameter 'TestParamWithVariables' -Expand
        Get-Parameter 'TestParamThatDoseNotExist' -Default 'MyExampleDefaultValue'
        Get-Parameter 'TestParam' -Source Json
        Get-Parameter 'TestParam' -Source SCCM
        Get-Parameter 'TestParam' -Source CloudShaper
        Get-Parameter 'TestParamThatDoseNotExist' -Source All
        Get-Parameter 'TestParam2'
        Get-Parameter 'TestParam' -Variable 'TestParamMyCustomVarName'
        Get-Parameter 'PackageDescription' -Section 'Package' -Source Json -Variable 'TestParamPackageDescription'
        Get-Parameter 'INST_LOG_DIR' -Section 'Install' -Source CloudShaper -Variable 'TestParamInstLogDir'
        Get-Parameter 'TestParam3' -force

        # Example for Get-ParameterFromRegKey
        Get-ParameterFromRegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Prefix "_" -Force -DetailedLog
    
        # Example how to add parameters via command line
        # Powershell.exe -file .\<PackageName>.ps1 -CustomParameter "AddLocal=ALL;TargetDir=""C:\Program Files\Test"";LicenseKey=12345-67890-ABCDEF"


        # List all TestParam variables from the example above
        Get-Variable TestParam* -ValueOnly | out-string | Write-Log

        # Example how to use a Get-Parameter for a If condition
        If ((Get-Parameter -Parameter 'TestParamBool') -eq $true){ Write-host "Param is TRUE" }

        # Example how to get parameters to an existing variable withou auto generating a new variable
        $Return = Get-Parameter 'TestParam' -NoAutoGeneratedVariable
        Write-Log "Return: $Return"

        # Example how to get parameters to an existing variable via pipe/stdout
        $Return = Get-Parameter 'TestParam'
        Write-Log "Return: $Return"

        # Example how to suppress the pipe(stdOut for security reason, e.g. if you whant to hide things like passwords
        $Return = Get-Parameter 'TestParam' -NoWriteOutput
        Write-Log "TestParam: $TestParam"
        Write-Log "Return: $Return"

        # Get ALL params from the JSON file parameters section
        ForEach ($Param in $PackageConfigFile.Parameters.psobject.Properties | where {$_.name} -like '*') { Get-Parameter -Parameter $Param.name }

    #endregion Variables

    #region Logfile
 
        # Write log examples (Serverity Options: 1=Info, 2=Warning, 3=Error; LogType Options: Legacy/CMTrace)
        Write-Log -Message "This example is an INFORMATION" -Severity 1
        Write-Log -Message "This example is an WARNING" -Severity 2
        Write-Log -Message "This example is an ERROR" -Severity 3
        Write-Log -Message "This example has a diffrent source" -Source "MyCustomSource"
        Write-Log -Message "This example is written only to the log when debug mode is active" -DebugMessage -LogDebugMessage $true
        Write-Log -Message "This example is a entry in a seperate legacty log" -LogType Legacy -LogFileDirectory "$temp" -LogFileName 'Legacy.log'
        Write-Log -Message "This example is a entry in a seperate CMtrace log" -LogType CMTrace -LogFileDirectory "$temp" -LogFileName 'CMtrace.log'
    
        # Install Phase string (for logfile secition, etc.)
        Write-Log -Message "bla bla"
        Set-InstallPhase "Installation"
        Write-Log -Message "bla bla"
        Set-InstallPhase "Uninstallation"
        Write-Log -Message "bla bla"

    #endregion Logfile

    #region GetInfos

        # Get the version of the specified file
        $Result = Get-FileVersion -File "$SystemDirectory\Notepad.exe"

        # Retrieves information about the hardware platform and do diffrent things based on the platform (possible return values: Virtual:Hyper-V, Virtual:Virtual PC, Virtual:Xen, Virtual:VMWare, Virtual, Physical)
        $Result = Get-HardwarePlatform
        If ($Result -like '*VMware*') { Write-Log 'VMware' }
        ElseIf ($Result -like '*Hyper-V*') { Write-Log 'Hyper-V' }
        ElseIf ($Result -like '*Xen*') { Write-Log 'XenServer' }
        ElseIf ($Result -eq 'Physical') { Write-Log 'Physical Hardware'}
        Else { Write-Log 'Unknown' }

        # Retrieves the free disk space on a particular drive (in MB)
        $Result = Get-FreeDiskSpace -Drive $Systemdrive

        # Retrieves information about installed applications with wildcards
        $Result = Get-InstalledApplication -Name '*Microsoft Office*' -WildCard
        if ($Result) {
            Write-Log $Result.DisplayName
            Write-Log $Result.DisplayVersion
            Write-Log $Result.InstallLocation
            Write-Log $Result.UninstallString
        }
        Else {
            Write-Log 'Software not found'
        }
        
        # Get session details for all local and RDP logged on users (NTAccount, SID, UserName, DomainName, SessionId, SessionName, ConnectState, IsCurrentSession, IsConsoleSession, IsUserSession, IsActiveUserSession, IsRdpSession, IsLocalAdmin, LogonTime, IdleTime, DisconnectTime, ClientName, ClientProtocolType, ClientDirectory, ClientBuildNumber)
        $Result = Get-LoggedOnUser
        if ($Result) {
            Write-Log $Result.NTAccount
            Write-Log $Result.UserName
            Write-Log $Result.SessionId
        }
        Else {
            Write-Log 'No user session found'
        }
    
        # Get the pending reboot status on a local computer. Returns custom object ComputerName, LastBootUpTime, IsSystemRebootPending, IsCBServicingRebootPending, IsWindowsUpdateRebootPending, IsSCCMClientRebootPending, IsFileRenameRebootPending, PendingFileRenameOperations, ErrorMsg
        if ((Get-PendingReboot).IsSystemRebootPending -Or (Get-PendingReboot).IsWindowsUpdateRebootPending -Or (Get-PendingReboot).IsCBServicingRebootPending  -Or (Get-PendingReboot).IsFileRenameRebootPending -Or (Get-PendingReboot).IsSCCMClientRebootPending)
        { Write-Log "Reboot is pending!" -Severity 2 }
        else { Write-Log "No reboot is pending" -Severity 1 }

    #endregion GetInfos

    #region GUI
        
        # Display a custom dialog box with optional title, buttons, icon and timeout
        Show-DialogBox -Title 'Installed Complete' -Text 'Installation has completed. Please click OK and restart your computer.' -Icon 'Information'
        $Result = Show-DialogBox -Title 'Installation Notice' -Text 'Installation will take approximately 30 minutes. Do you wish to proceed?' -Buttons 'OKCancel' -DefaultButton 'Second' -Icon 'Exclamation' -Timeout 600
        Write-Log "Result = $Result"

        # Display a custom ballon tip
        Show-BalloonTip -BalloonTipText 'My custom ballon tip' -BalloonTipTitle 'My Package'
        Start-Sleep -Seconds 2

        # Display Toast Notification with Custom Text & Icon
        Start-Sleep -Seconds 2
        Show-BalloonTip -BalloonTipText "Toast Notification with Info Icon" -BalloonTipTitle "Toast Notification" -BalloonTipIcon Info -BalloonTipTime 2000 -UseToast:$true
        Start-Sleep -Seconds 2
        Show-BalloonTip -BalloonTipText "Toast Notification with Warning Icon" -BalloonTipTitle "Toast Notification" -BalloonTipIcon Warning -BalloonTipTime 2000 -UseToast:$true
        Start-Sleep -Seconds 2
        Show-BalloonTip -BalloonTipText "Toast Notification with Error Icon" -BalloonTipTitle "Toast Notification" -BalloonTipIcon Error -BalloonTipTime 2000 -UseToast:$true
        Start-Sleep -Seconds 2
        Show-BalloonTip -BalloonTipText "Toast Notification with None Icon" -BalloonTipTitle "Toast Notification" -BalloonTipIcon None -BalloonTipTime 2000 -UseToast:$true
        Start-Sleep -Seconds 2


    #endregion GUI

    #region PackageWithGUI

        # Show welcome dialog, close apps, allow defer, checl diskspace, etc.
        Show-InstallationWelcome -CloseApps 'notepad' -CloseAppsCountdown 10 -AllowDefer -DeferTimes 3 -CheckDiskSpace -RequiredDiskSpace 10000 -ForceCloseAppsCountdown 20 -PromptToSave -PersistPrompt 
    
        # Show progess disalog
        Show-InstallationProgress -StatusMessage "Installation in Progress..."
    
        # Installation
        # < PLACE YOUR INSTALL CODE HERE> 

        # Close progress dialog
        Close-InstallationProgress

        # Show complete message
        Show-InstallationPrompt -Message 'Installation Completely' -ButtonRightText 'OK' -Icon Information 

        # Show restart prompt (but only when reboot is pending)
        if ((Get-PendingReboot).IsSystemRebootPending){ Show-InstallationRestartPrompt } 
    
    #endregion PackagewithGUI

    #region Execute

        # Execution example.cmd from the package "Files" folder
	    Start-Program -path "$Files\Example.cmd"
    
        # Execution example incl. command line parameter and no wait
	    Start-Program -Path "$SystemDirectory\cmd.exe" -Parameters '/C Echo Hello World' -NoWait

        # Execution example incl. suppress parameters in logfile (e.g. to suppress passwords)
	    Start-Program -Path "$SystemDirectory\cmd.exe" -Parameters '/C Echo My Secret Parameter' -SecureParameters

        # Execution example with no window (use TaskMgr to kill CMD.exe, will not work for all apps)
        Start-Program -Path "$SystemDirectory\cmd.exe" -Parameters '/C' -CreateNoWindow

        # Execution example with diffrent working directory and using the DIR command and PassThour to capture StdOut as a proof that the working directory is set
        [psobject]$ExecuteResult = Start-Program -Path "$SystemDirectory\cmd.exe" -Parameters '/C dir' -WorkingDirectory "$Temp" -PassThru
        Write-Log -Message $ExecuteResult.StdOut    

        # Execution with ignored error codes, this example will cause error code 2 which will be ignored
        Start-Program -Path 'Net.exe' -Parameters 'use * \\dummy\dummy' -IgnoreExitCodes '2'
    
        # Launch InstallShield "setup.exe" from the ".\Files" sub-directory and force log files to the logging folder. 
        Start-Program -Path 'setup.exe' -Parameters "-s -f2`"$LogDir\$PackageName.log`""

        # Launch InstallShield "setup.exe" with embedded MSI and force log files to the logging folder.
        Start-Program -Path 'setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$LogDir\$PackageName.log`"`""

        # Launch Notepad, wait a maximum of 5 seconds
        Start-Program -Path "Notepad.exe" -MaxWaitTime 5

        # Launch Notepad, wait a maximum of 5 seconds, ignore the 258 timeout exit code
        Start-Program -Path "Notepad.exe" -MaxWaitTime 5 -IgnoreExitCodes 258


    #endregion Execute

    #region MSI
    
        # Installs an MSI
        Start-MSI -Action 'Install' -Path "$Files\Setup.msi"
        
        # Uninstalls an MSI using the MSI
        Start-MSI -Action 'Uninstall' -Path "$Files\Setup.msi"

        # Insall an MSI ans speify a custom name for the log file (without folder and .log extension!)
        Start-MSI -Action 'Install' -Path "$Files\Setup.msi" -LogName "MyCustomLogName" 

        # Installs an MSI, applying a transform and overriding the default MSI toolkit parameter. Hint: Don't specify the "Files" or "Source" folder for the MST!
        Start-MSI -Action 'Install' -Path "$Files\Setup.msi" -Transform 'Example.mst' -AddParameters 'KEY=123'

        # Uninstalls an MSI using a product code
        Start-MSI -Action 'Uninstall' -Path '{3A39516D-74D5-4789-AE45-B80F1EE1723C}'

        #Installs an MSI and stores the result of the execution into a variable by using the -PassThru option
        [psobject]$ExecuteMSIResult = Start-MSI -Action 'Install' -Path "$Files\Setup.msi" -PassThru
        Write-Log -Message $ExecuteMSIResult.ExitCode
    
        # Removes all MSI applications matching the specified application name (e.g specify the application name without the included version number)
        Remove-MSIApplications -Name 'Wise InstallTailor'

        # Installs an MSP
        Start-MSI -Action 'Patch' -Path "$Files\Patch.msp"

        # Removes all versions of software that match the name "Java 8 Update" and also have "Oracle Corporation" as the Publisher; however, it does not uninstall "Java 8 Update 45" of the software. NOTE: if only specifying a single array in an array of arrays, the array must be preceded by two commas as in this example
        Remove-MSIApplications -Name 'Java 8 Update' -FilterApplication @(,,@('Publisher', 'Oracle Corporation','Exact')) -ExcludeFromUninstall @(,,@('DisplayName','Java 8 Update 45','RegEx'))

        # Get infos from installed MSI apps    
        Get-InstalledApplication -Name 'Adobe Flash'
        Get-InstalledApplication -ProductCode '{3D82C954-2957-418B-908F-FE78BF3A8BEB}'


    #endregion MSI

    #region Files

        # Create a new folder.
        New-Folder "$SystemDrive\Temp"

        # Copy a single file
        Copy-File -Path "$Windir\Win.ini" -Destination "$SystemDrive\Temp\Win.ini"

        # Copy multiple files using wildcards to a new folder
        Copy-File -Path "$Windir\Logs\Software\*.log" -Destination "$SystemDrive\temp\New Folder 1"
    
        # Copy multiple folders including subfolders (Recurse)
        Copy-File -Path "$Windir\Logs\Software\*.*" -Destination "$SystemDrive\temp\New Folder 2" -Recurse

        # Remove/Delete a file or all files recursively in a given path.
        Remove-File -Path "$SystemDrive\Temp\Win.ini"

        # Remove folder and all files recursively in a given path.
        Remove-Folder -Path "$SystemDrive\Temp\New Folder 2"

        # Creates a new shortcut .lnk or .url file, with configurable options.
        New-Shortcut -Path "$CommonStartMenuPrograms\My Test Shortcut.lnk" -TargetPath "$SystemDirectory\notepad.exe" -IconLocation "$SystemDirectory\notepad.exe" -Description 'Notepad' -WorkingDirectory "$HomeDrive\$HomePath"

    #endregion Files
 
    #region Registry
    
        # Retrieve a registry value
        $Result = Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Value 'Common AppData'
        if ($Result) {Write-Log "Result= $Result"}

        # Retrieve multiple values from a registry key
        $Result = Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{071c9b48-7c32-4621-a0ac-3f809523288f}'
        if ($Result) {
            Write-Log $Result.DisplayName
            Write-Log $Result.DisplayVersion
        }

        # Retrieve a REG_EXPAND_SZ registry value and expand it.
        $Result = Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Value 'Common AppData'
        if ($Result) {Write-Log "Result= $Result"}

        # Retrieve a REG_EXPAND_SZ registry value and don't expand it.
        $Result = Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Value 'Common AppData' -DoNotExpandEnvironmentNames
        if ($Result) {Write-Log "Result= $Result"}
    
        # Deletes the specified registry key or value
        Remove-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Test' -Name 'Test'
        Remove-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Test' -Recurse

        # Creates a registry key name, value, and value data; it sets the same if it already exists. Type options: 'Binary', 'DWord', 'ExpandString', 'MultiString', 'None', 'QWord', 'String', 'Unknown'. Default: String.
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test' -Name 'TestString' -Value Test -Type String
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Test' -Name 'TestBinary' -Value (0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x01,0x01,0x01,0x02,0x02,0x02) -Type 'Binary'
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Test' -Name 'TestExpand' -Value '%ProgramFiles%\test\test.exe' -Type 'ExpandString'
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Test' -Name 'TestDWord' -Value 1024 -Type 'DWord'
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Test' -Name 'TestDWordHex' -Value 0x400 -Type 'DWord'
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\Software\Test' -Name 'TestMulti' -Value @("value1", "value2", "value3") -Type 'MultiString'

        # Test if a registry value exists
        $Result = Test-RegistryKey -Key 'HKEY_LOCAL_MACHINE\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations'
        Write-Log "Result = $Result"

        # Write a HKEY_USERS to s specific user SID
        Set-RegistryKey -Key 'HKCU\Software\Test\' -Name 'test' -Value 123 -Type DWord -SID S-1-5-21-980134340-1614562238-3248706570-1001

        # Key exists tests inside a IF condition (returns $true when key exists)
        if (Test-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full") {
            Write-Log "Key exists"
        }

        # Value exist tests (returns $true when value exists)
        if (Test-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Install) {
            Write-Log "Value exists"
        }

        # Value Type tests (returns $true when value exists and type is DWord)
        if (Test-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Install -Type DWord) {
            Write-Log "Value is DWORD"
        }

        # Value Content tests (returns $true when default value exists and content is 1)
        if (Test-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Install -Value 1) {
            Write-Log "Value is 1"
        }

        # Import reg file
        Import-RegFile $Files\Example.reg 

        # Import reg file with some optional options
        Import-RegFile -file "$Files\Example.reg" -ResolveVars -Use32BitRegistry -DetailedLog -ContinueOnError
        

    #endregion Registry

    #region INIs

        # Read INI file and returns the value of the specified section and key
        $Result = Get-IniValue -FilePath "$WinDir\Win.ini" -Section 'Mail' -Key 'MAPI'
        Write-Log "MAPI value in Mail section of Win.ini is = $Result" 

        # Write value to INI file entry
        Set-IniValue -FilePath "$WinDir\Win.ini" -Section 'TestSection' -Key 'TestKey' -Value 'TestValue'

        # Delete a value from ini file
        Set-IniValue -FilePath "$WinDir\Win.ini" -Section 'TestSection' -Key 'TestKey' -Value ''

    #endregion INIs

    #region Services

        # Retrieve the start method of a service
        Get-ServiceStartMode -Name 'wuauserv'

        # Set the service startup mode, Options: Automatic, Automatic (Delayed Start), Manual, Disabled, Boot, System
        Set-ServiceStartMode -Name 'Spooler' -StartMode 'Automatic'

        # Start Windows service and its dependencies
        Start-ServiceAndDependencies -Name 'wuauserv'

        # Stop Windows service and its dependencies
        Stop-ServiceAndDependencies -Name 'wuauserv'

        # Check if a service exists
        $Result = Test-ServiceExists -Name 'wuauserv'
        Write-Log "Result = $Result"

        # Check if a service exists and then delete it by using the -PassThru parameter.
        Test-ServiceExists -Name 'testservice' -PassThru | Where-Object {$_ } | ForEach-Object {$_.Delete() }

    #endregion Services

    #region Accounts

        # Get the Well Known SID from a built in user/group
        $Result = ConvertTo-NTAccountOrSID -WellKnownSIDName 'NetworkServiceSid'
        Write-Log -Message "Network Service SID = $Result"
    
        # Get the SID from a account
        $Result = ConvertTo-NTAccountOrSID -AccountName 'Andreas-PC\Administrator'
        Write-Log -Message $Result

        # Get the account from a SID
        $Result = ConvertTo-NTAccountOrSID -SID 'S-1-5-21-980134340-1614562238-3248706570-500'
        Write-Log -Message $Result

        # List all WellKnownSID's to the log
        [enum]::GetNames([Security.Principal.WellKnownSidType]) | Write-Log

    #endregion Accounts
    
    #region JSON

        # Get some properties from the package section of the json file
        # Note: the the package json file is already loaded to $PackageConfigFile and module json in $ModuleConfigFile

        # Output the object
        Write-Host $PackageConfigFile
    
        # Output some of the package parameters
        $PackageConfigFile.Package.PackageDescription
        $PackageConfigFile.Package.PackageDate
        $PackageConfigFile.Package.PackageAuthor

        # Output some of the package parameters from parameters section
        $PackageConfigFile.Parameters.TestParam
        $PackageConfigFile.Parameters.TestParamWithVariables
    
        # Output a parameter with variables and resolve the variables
        Write-Host "String with vars:  " $PackageConfigFile.Parameters.TestParamWithVariables
        $result = Expand-Variable $PackageConfigFile.Parameters.TestParamWithVariables
        Write-Host "String with resolved vars:  " $result

        # Get some properties from all apps
        Write-Host "Access proprties of multiple published apps"
        foreach($App in $PackageConfigFile.Applications)
        {
            Write-Host "*********************************"
            Write-Host "AppName: " $App.AppName
            Write-Host "AppCommandLineExecutable: " $App.AppCommandLineExecutable
            Write-Host "AppWorkingDirectory: " $App.AppWorkingDirectory
            foreach($Account in $App.AppAccounts)
            {
                Write-Host "Account" $App.AppAccounts.IndexOf($Account) ":" $Account
            }
        }
        Write-Host "*********************************"

        # Read some settingg from  a custom JSON file from the files folder
        [psobject]$ExampleJsonFile = get-content "$Files\Example.json" | ConvertFrom-Json 

        # Get some individual parameters from the JSON file
        Write-host "Herausgeber: $ExampleJsonFile.Herausgeber"
        Write-host "Nummer: $ExampleJsonFile.Nummer"
        Write-host "Inhaber Name: $ExampleJsonFile.Inhaber.Name"
        Write-host "Inhaber Vorname: $ExampleJsonFile.Inhaber.Vorname"

        # Output the whole "Inhaber" sub-object
        $ExampleJsonFile.Inhaber

        # Output the whole Json object
        $ExampleJsonFile

        # Webservis REST API request with JSON response
        $JsonResponse = Invoke-RestMethod -Uri "http://date.jsontest.com"
        ForEach($subject in $JsonResponse)
        {
            Write-Host "Time: " $Subject.Time
            Write-Host "Date: " $Subject.Date
        }
        $JsonResponse | ConvertTo-Json | Out-File $Files\DateTime.json

        # A more complex example based on http://powershelldistrict.com/powershell-json/
        # First have a look at the $Files\Example2.json file, you will see:
        # One object called SiteType with the two properties Internal and External
        # One object called Author which contains an array of two author objects Andreas and Jens with five properties each
        
        # Read whole package JSON file
        [psobject]$JsonObject = get-content "$Files\Example2.json" -raw | ConvertFrom-Json 

        Write-Host "Show the whole JSON object as a list:"
        $JsonObject| Format-List

        Write-Host "Access a unique property ""external"" from the ""SiteType"" object from the JSON object (in this case the external URL):"
        $JsonObject.SiteType.External

        Write-Host "Access proprties of multiple authors"
        foreach($subject in $JsonObject.Author)
        {
            Write-Host "Author Name: " $subject.name
            Write-Host "Author Age: " $subject.age
            Write-Host "Author City: " $subject.city
            Write-Host "Author Country: " $subject.Country
        }

        Write-Host "Change a unique property external URL to a new URL"
        $JsonObject.SiteType.External = "http://www.mariotti.de"
    
        Write-Host "Add one more SiteType (the DMZ URL)"
        $JsonObject.SiteType | Add-Member -Type "NoteProperty" -Name "Test" -Value "http://test.ceterion.com"
    
        Write-Host "Show the whole JSON object as proof for modification:"
        $JsonObject | Format-List

        #Write-Host "Add one more author object to the author array"
        $AuthorObject = new-object psobject
        $AuthorObject | add-member –membertype NoteProperty –name "Name" –Value "Christian"
        $AuthorObject | add-member –membertype NoteProperty –name "Age" –Value "35"
        $AuthorObject | add-member –membertype NoteProperty –name "City" –Value "Eschborn"
        $AuthorObject | add-member –membertype NoteProperty –name "Country" –Value "Germany"
        $AuthorObject | add-member –membertype NoteProperty –name "FavoriteColor" –Value "Red"
        $JsonObject.author += $AuthorObject

        #Write-Host "Change a property on authors based on array index (change City for Andreas)"
        $JsonObject.author[0].City = "Alzenau i.UFr."

        # List all propertie names
        write-host "List all author names"
        $JsonObject.author | select Name

        #List all properties that match a creteria
        write-host "List all older than 40"
        $JsonObject.author | Where-Object {$_.age -gt '40'}

        # Show the whole JSON object as proof for modification
        Write-Host "Show the whole JSON object as proof for modification:"
        $JsonObject | Format-List

        # Save modified object as JSON file
        Write-Host "Save modified object as JSON file"
        $JsonObject | ConvertTo-Json | Out-File $Files\Example2_Modified.json -Encoding ascii

    #endregion JSON

    #region XML
    
        ### EXAMPLE 1 ###

        # How to create a XML inline from scratch (incl. some vars)
	    [string]$XmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo />
  <Triggers />
  <Settings>
	<MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
	<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
	<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
	<AllowHardTerminate>true</AllowHardTerminate>
	<StartWhenAvailable>false</StartWhenAvailable>
	<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
	<IdleSettings>
	  <StopOnIdleEnd>false</StopOnIdleEnd>
	  <RestartOnIdle>false</RestartOnIdle>
	</IdleSettings>
	<AllowStartOnDemand>true</AllowStartOnDemand>
	<Enabled>true</Enabled>
	<Hidden>false</Hidden>
	<RunOnlyIfIdle>false</RunOnlyIfIdle>
	<WakeToRun>false</WakeToRun>
	<ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
	<Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
	<Exec>
	  <Command>$WinDir\cmd.exe</Command>
	  <Arguments>/D</Arguments>
	</Exec>
  </Actions>
  <Principals>
	<Principal id="Author">
	  <UserId>$UserName</UserId>
	  <LogonType>InteractiveToken</LogonType>
	  <RunLevel>High</RunLevel>
	</Principal>
  </Principals>
</Task>
"@ | Out-File -FilePath $Files\Example1.xml -Encoding utf8
    

        ### EXAMPLE 2 ###
    
        # How to work with XML files, based on https://blogs.technet.microsoft.com/chitpro-de/2007/10/09/windows-powershell-in-der-praxis-xml-verarbeitung-von-jan-moser/

        # Read XML example
        [xml]$XMLfile = Get-Content $Files\Example2.xml

        # Access a speific element (e.g. DomainPrefix)
        Write-Host "Show DomainPrefix:"
        Write-Host $XMLfile.Region.DomainPrefix
    
        # Count how many "Location" elements are below "Locations"
        Write-Host "Show locations count:"
        Write-Host $XMLfile.Region.Locations.Location.Count
    
        # Access the individul "Location" elements in the "Locations" array it's position in the array
        Write-Host "Show name elements for each single location:"
        Write-Host $XMLfile.region.locations.location[0].name 
        Write-Host $XMLfile.region.locations.location[1].name 
        write-Host $XMLfile.region.locations.location[2].name 

        # Access the individul "Location" elements in the "Locations" array via XPath search
        Write-Host "Show name elements for each single location 2:"
        $XMLSearch = $XMLfile.SelectNodes(“/region/locations/location”)
        foreach ($location in $XMLSearch) {
            Write-Host $location.name
        }

        # List the server names and the servers operating systems in location Zurich
        Write-Host "Show server names in location Zurich:"
        write-Host $XMLfile.region.locations.location[0].server.Name
        Write-Host "Show server OS in location Zurich:"
        write-Host $XMLfile.region.locations.location[0].server.OS

        Write-Host "Add new Location Luzern to region Switzerland"
        $addElem = $XMLfile.CreateElement("Location")
        $addAtt = $XMLfile.CreateAttribute("name")
        $addAtt.Value = "Luzern"
        $addElem.Attributes.Append($addAtt)
        $XMLfile.region.locations.AppendChild($addElem)

        # Modify now some data in the XML object by search and replace (replace "Windows" with "Windows2016" and replace "Unix" with "Linux" for all servers in Zurich)
        $XMLfile.region.locations.location[0].server | 
        % { if ($_.OS –like “Windows”){$_.OS = “Windows2016”} 
        elseif ($_.OS -like “Unix”) { $_.OS = “Linux”}}

        # List the operating systems of all servers in location Zurich again (as proof for the change)
        Write-Host "Show server OS in location Zurich:"
        write-Host $XMLfile.region.locations.location[0].server.OS
    
        # Add a new element by cloing and existing element and modify the clone
        Write-Host "Add a new element by cloing the server Dali and  modify the name and IP of the clone to Duerer and 192.168.55.55"
        $NewServer = $XMLfile.region.locations.location[0].server[0].Clone()
        $NewServer.name = “Duerer” 
        $NewServer.ip_address = “192.168.55.55” 
        Write-Host $NewServer.name
        Write-Host $NewServer.ip_address

        # Add the freshly cloned server to the existing XML to location Geneva
        Write-Host "Add the freshly cloned server Duerer to the existing XML to location Geneva"
        $Return = $XMLfile.region.locations.location[2].AppendChild($newserver)

        # List location Geneva as proof
        Write-Host "List servers in location Geneva as proof that server Duerer was added"
        Write-Host $XMLfile.region.locations.location[2].Server.name

        #Save XML file
        $XMLfile.save(“$Files\Example2_Result.xml”)

        ### EXAMPLE 3 ###

        # How to modify a XML file with complex hierachy of nodes and attributes, based on https://blogs.msdn.microsoft.com/sonam_rastogi_blogs/2014/05/14/update-xml-file-using-powershell/

        # 1. Define the variable which are required to be modified:-
        $ManagementServer = 'NewManagementServer'
        $SQLServer = 'NewSQLServer'
        $SQLAdmin = 'Domain\NewSQlAdmin'
        $DNSServerVMName = 'NewDNSServer'
        $NewNumber = 'NewContactNumber'

        # 2. Reading the content of XML file.
        $xml = [xml](Get-Content "$Files\Example3.xml")

        # 3. Reading List of Subject: Read Child Tags of Course Node
        $xml.Data.Course.Subject

        # 4. Update ‘ManagementServer’: Changing Attribute value of node at level 3 based on ‘Name’ attribute on same level.
        $node = $xml.Data.Roles.Role | where {$_.Name -eq 'ManagementServer'}
        $node.Value = $ManagementServer

        # 5. Update ‘SQLServer’: Changing Attribute value of node at level 3.
        $node = $xml.Data.SQL.Instance
        $node.Server = $SQLServer

        # 6. Update ‘SQLAdmin’: Changing Attribute value of node at level 4 based on ‘Name’ attribute on same level.
        $node = $xml.Data.SQL.Instance.Variable | where {$_.Name -eq 'SQLAdmin'}
        $node.Value = $SQLAdmin

        # 7. Update ‘DNSServerVM’: Changing Attribute value of node at level 4 based on ‘VMType’ attribute at above level.
        $node = $xml.Data.VMs.VM | where {$_.Type -eq 'DNSServerVM'}
        $node.VMName = $DNSServerVMName

        # 8. Update Subject Maths: Update Child nodes based on ‘Text’ property where no attribute is available to differentiate.
        $node = $xml.Data.Course.ChildNodes
        foreach($subject in $node)
        {
            if ($subject.'#text' -eq "Maths") 
            {
                $newChild = $xml.CreateElement("Subject")
                $newChild.set_InnerXML("History") 
                $xml.Data.Course.ReplaceChild($newChild, $subject)     
            }
        }

        # 9. Update Subject Science: Update Child node based on position of Child node
        $node = $xml.Data.Course.ChildNodes
        $newChild = $xml.CreateElement("Subject")
        $newChild.set_InnerXML("Computers") 
        $xml.Data.Course.ReplaceChild($newChild, $node.Item(1))

        # 10. Adding Role: Adding New Node in XML Hierarchy
        $newRole = $xml.CreateElement("Role")
        $xml.Data.Roles.AppendChild($newRole)


        # 11. Adding ‘Name’ and ‘Value’ attributes to Role node: Adding Attributes to XML node
        $newRole.SetAttribute(“Name”,”ADServer”);
        $newRole.SetAttribute(“Value”,”NewADServer”);

        # 12. Updating Contact Number when Type is Mobile
        $allContactsNodes = $xml.Data.AllContacts.Contact
        foreach($node in $allContactsNodes)
        {
           if($node.ContactType.Type -eq 'Mobile')
           {
               $updateNode = $node.Details
               $updateNode.Number = $NewNumber
               break
           }
        }

        # 13. Saving changes to XML file.
        $xml.Save("$Files\Example3_Result.xml")

    #endregion XML
    
    #region Security

        # Create test group
        $TestAccount = "TestGroup1"
        New-LocalGroup $TestAccount

        # Folder permissions
        New-Folder -Path "$SystemDrive\temp\test1"
        New-Folder -Path "$SystemDrive\temp\test2"
        New-Folder -Path "$SystemDrive\temp\test3"
        Set-Inheritance -Action Disable -Path "$SystemDrive\temp\test1"
        Set-Inheritance -Action Disable -Path "$SystemDrive\temp\test2"
        Update-FolderPermission -Action "Add" -Path "$SystemDrive\temp\test1" -Trustee "$TestAccount" -Permissions "FullControl"
        Update-FolderPermission -Action "Add" -Path "$SystemDrive\temp\test2" -Trustee "$TestAccount" -Permissions "ReadAndExecute"

        # File permissions
        Copy-File -Path "$WinDir\win.ini" -Destination "$SystemDrive\temp\test1\test1.ini"
        Copy-File -Path "$WinDir\win.ini" -Destination "$SystemDrive\temp\test1\test2.ini"
        Update-FilePermission -Action "Add" -Path "$SystemDrive\temp\test1" -File "test1.ini" -Trustee "$TestAccount" -Permissions "FullControl"
        Update-FilePermission -Action "Add" -Path "$SystemDrive\temp\test1" -File "test2.ini" -Trustee "$TestAccount" -Permissions "ReadAndExecute"

        # Registry permissions
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test1' -Name 'TestString' -Value Test -Type String
        Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Test2' -Name 'TestString' -Value Test -Type String
        Set-Inheritance -Action Disable -Path "HKLM\SOFTWARE\Test1"
        Set-Inheritance -Action Disable -Path "HKLM\SOFTWARE\Test2"
        Update-RegistryPermission -Action "Add" -Key "HKLM\SOFTWARE\Test1" -Trustee "$TestAccount" -Permissions "FullControl"
        Update-RegistryPermission -Action "Add" -Key "HKLM\SOFTWARE\Test2" -Trustee "$TestAccount" -Permissions "ReadKey"

        # Printer permissions
        Update-PrinterPermission -Action "Add" -Printer "PDFCreator" -Trustee "$TestAccount" -Permissions "FullControl"

        # Example how to set multiple permissions from the 'Permissions' section of the package json file
        Add-PermissionFromJson



    #endregion Security

    #region Firewall

        # Example usage of Add-FirewallRule with some cmdlet params
        Add-FirewallRule -DisplayName "Notepad Test 1" -Program "C:\Windows\Notepad.exe" -Direction Inbound -Action Block
        Add-FirewallRule -DisplayName "Notepad Test 2" -Description "My Descripton" -Program "$Env:WinDir\Notepad.exe $Env:Temp\Test.txt" -Direction Outbound -Action Allow -RemoteAddress $_ProxyIP -RemotePort 8080 -Profile Any -Protocol TCP

        # Example usage of Add-FirewallRule with default $DefaultFirewallRule<ParameterName> variables.  Hint: you can put this default into your extension file
        $Global:DefaultFirewallRuleDescription = "Packaging Framework Default Rule - $PackageName"
        $Global:DefaultFirewallRuleDisplayName = "Packaging Framework Default Rule - $PackageName"
        $Global:DefaultFirewallRuleAction = "Allow"
        $Global:DefaultFirewallRuleDirection = "Outbound"
        $Global:DefaultFirewallRuleProtocol = "TCP"
        $Global:DefaultFirewallRuleProfile = "Any"
        Add-FirewallRule -Program "C:\Windows\Notepad.exe"
        Add-FirewallRule -Program "C:\Windows\Regedit.exe"
        Add-FirewallRule -Program "C:\Windows\Write.exe"
    
        # Example how to multiple rules from the 'FirewallRules' section of the package json file
        Add-FirewallRuleFromJson

        # Example usage of Remove-FirewallRule
        Remove-FirewallRule -DisplayName "Notepad Test 1"
        Remove-FirewallRule -DisplayName "Notepad Test 2"
        Remove-FirewallRule -DisplayName "Notepad Test 3"
        Remove-FirewallRule -DisplayName "Notepad Test 4"
        Remove-FirewallRule -DisplayName "Notepad Test 5"

    #endregion Firewall

    #region ActiveSetup

        ### INSTALL ###

        # Create target folder
        New-Folder -path "$ProgramFiles\ExampleActiveSetup"

        # Create a active setup entry for a power shell script (for all users)
        Set-ActiveSetup -StubExePath "$ProgramFiles\ExampleActiveSetup\Example.ps1"

        # Create a active setup entry for a power shell script (for a specific user groups only)
        Set-ActiveSetup -StubExePath "$ProgramFiles\ExampleActiveSetup\Exampe.ps1" -UserGroups 'TestGroup1'

        # Create a active setup entry for a power shell script (for multiple user groups)
        Set-ActiveSetup -StubExePath "$ProgramFiles\ExampleActiveSetup\Example.ps1" -UserGroups @('TestGroup1','TestGroup2')

        # Create a active setup entry with increassed version number (e.g. update scenarios to let it run again for existing users, please note, version nuber needs coma as seperator!)
        Set-ActiveSetup -StubExePath "$ProgramFiles\ExampleActiveSetup\Example.ps1" -Version 'V1.1.0.0'
        
        ### UNINSTALL ####

        # Remove active setup entry
        Set-ActiveSetup -PurgeActiveSetupKey

    #endregion ActiveSetup

    #region Encryption

        # Example how to generate a new key file (An existing key will not be overwritten, you have to delete an old key first)
	    Invoke-Encryption -Action GenerateKey -KeyFile "$files\Example.key"

        # Example how to install a existing key file into the HKCU registry of the current user for later use
        Invoke-Encryption -Action InstallKey -KeyFile "$files\Example.key"

        # Example how to encrypt data with an key file
        $return = Invoke-Encryption -Action Encrypt -String "This is a test string" -KeyFile "$Files\Example.key"
        Write-Host "Return: $return"

        # Example how to encrypt data with an installed key from HKCU registry
        $return = Invoke-Encryption -Action Encrypt -String "This is a test string"
        Write-Host "Return: $return"

        # Example how to decrypt data with an key file
        $return = Invoke-Encryption -Action Decrypt -KeyFile "$files\Example.key" -String "ENCRYPTAES25676492d1116743f0423413b16050a5345MgB8AEsARAB2AHMARwBkAHcAZgBMAFgAZABHAFcAMQBhAGcAZgBCADgAVwBwAFEAPQA9AHwAOQA0AGMAZABmADIANgBkADMAOQA0ADkAMgAxAGMAOQBhAGIAZgA5ADQANABiADUAMAA3AGEAZAAxAGUANQA3AGYAMQA4ADIAMwBiAGYANQA2ADUAMABiAGUAMQA2AGIANQBiADkANgA5AGMAMABlADIAMgA5AGMAYgBmADcAMwAzADYANABlADkAYQA4AGMANQA4AGMAMgA0ADQAOQAzADEAMQA1ADMAYgAyADcAZgAyAGUAYgBhADQAYgBkAGEA"
        Write-Host "Return: $return"

        # Example how to decrypt data with an installed key from HKCU registry
        $return = Invoke-Encryption -Action Decrypt -String "ENCRYPTAES25676492d1116743f0423413b16050a5345MgB8AEsARAB2AHMARwBkAHcAZgBMAFgAZABHAFcAMQBhAGcAZgBCADgAVwBwAFEAPQA9AHwAOQA0AGMAZABmADIANgBkADMAOQA0ADkAMgAxAGMAOQBhAGIAZgA5ADQANABiADUAMAA3AGEAZAAxAGUANQA3AGYAMQA4ADIAMwBiAGYANQA2ADUAMABiAGUAMQA2AGIANQBiADkANgA5AGMAMABlADIAMgA5AGMAYgBmADcAMwAzADYANABlADkAYQA4AGMANQA4AGMAMgA0ADQAOQAzADEAMQA1ADMAYgAyADcAZgAyAGUAYgBhADQAYgBkAGEA"
        Write-Host "Return: $return"
    
        # Example how to get an encrypted parameter automaticaly decrypt by Get-Parameter
        Get-Parameter TestParamEncrypted -SecureParameters
        Write-Host "Result: $TestParamEncrypted"

    #endregion Encryption

    #region EnvironmentVariables

         # Example how to get an environment variable
        $result = Get-EnvironmentVariable -Name 'Username'
        Write-Host $result

        # Exammple how to get environment variables from diffrent targets
        $result1 = Get-EnvironmentVariable -Name 'Temp' -Target 'Machine'
        $result2 = Get-EnvironmentVariable -Name 'Temp' -Target 'User'
        Write-Host "Machin Temp is [$result1] and User Temp is [$result2]"

        # Example how to set an environment variable for the current process
        Set-EnvironmentVariable 'TestVar1' 'This is a test value'

        # Example how to set an permanent environment variable on machine level
        Set-EnvironmentVariable -Name 'TestVar2' -Value 'This is a test value' -Target 'Machine'

        # Example how to remove an environment variable (line 3 is the remove, the other lines are to show the proof)
        Set-EnvironmentVariable -Name 'TestVar3' -Value 'This is a test value'
        Get-EnvironmentVariable -Name 'TestVar3'
        Remove-EnvironmentVariable -Name 'TestVar3'
        Get-EnvironmentVariable -Name 'TestVar3'

        # Updates the environment variables changes in exsting process (line 3 is the update, the other lines are to show the proof)
        Set-EnvironmentVariable -Name 'TestVar4' -Value 'This is a test value' -Target 'Machine'
        Get-EnvironmentVariable -Name 'TestVar4'  # existing processes will not see it now
        Update-SessionEnvironmentVariables # The update will refresh the vars in existing processes
        Get-EnvironmentVariable -Name 'TestVar4' # Now existing processes will see the variable


        # Example how to get the PATH variable
        $Path = (Get-Path)
        Write-Host "Path: $Path"

        # Example how to extend the PATH environment variable
        New-Folder -Path "$SystemDrive\TestFolder"
        Add-Path "$SystemDrive\TestFolder"
        Add-Path "%SystemDrive%\TestFolder"

        # Example how to remove a folder from the PATH environment variable
        Remove-Path "$SystemDrive\TestFolder"
        Remove-Path "%SystemDrive%\TestFolder"
        Remove-Folder -Path "$SystemDrive\TestFolder"

    #endregion EnvironmentVariables

    #region Misc

        # Exit with an specified exit code (e.g. 0 for success, 1 for error, 3010 for reboot req., etc)
        Exit-Script -ExitCode 0     # Successful 
        Exit-Script -ExitCode 1     # General error
        Exit-Script -ExitCode 2     # File not found
        Exit-Script -ExitCode 5     # Access denied
        Exit-Script -ExitCode 3010  # Reboot req.

        # Get Window Title
        Get-WindowTitle -WindowTitle 'Word'
        Get-WindowTitle -GetAllWindowTitles
        Get-WindowTitle -GetAllWindowTitles | Where-Object { $_.ParentProcess -eq 'WINWORD' }
    
        # Register or unregister a DLL file
        Invoke-RegisterOrUnregisterDLL -FilePath "$SystemDirectory\mstscax.dll" -DLLAction Unregister
        Invoke-RegisterOrUnregisterDLL -FilePath "$SystemDirectory\mstscax.dll" -DLLAction Register

        # Refresh the Windows Explorer Shell, which causes the desktop icons and the environment variables to be reloaded.
        Update-Desktop  

        # Enumerate error record details. (Options for Property: *, Message, FullyQualifiedErrorId, ScriptStackTrace, PositionMessage, InnerException)
        Resolve-Error
        Resolve-Error -Property *
        Resolve-Error -Property InnerException
        Resolve-Error -GetErrorInvocation $false

        # Sendkey example
        Start-Program -Path 'notepad.exe' -NoWait
        Start-Sleep -seconds 1
        Send-Keys -WindowTitle 'Unbenannt - Editor' -Key '123' -WaitSeconds 2
        Send-Keys -WindowTitle 'Unbenannt - Editor' -Key '{BACKSPACE}{BACKSPACE}{BACKSPACE}' -WaitSeconds 2
        Send-Keys -WindowTitle 'Unbenannt - Editor' -Key '%{F4}' -WaitSeconds 2   

        # Pins or unpins a shortcut to the start menu or task bar. This should typically be run in the user context, as pinned items are stored in the user profile, Options: 'PintoStartMenu', 'UnpinfromStartMenu', 'PintoTaskbar', 'UnpinfromTaskbar'.
        Set-PinnedApplication -Action 'PintoStartMenu' -FilePath "$WinDir\Notepad.exe"
        Set-PinnedApplication -Action 'UnpinfromStartMenu' -FilePath "$WinDir\Notepad.exe"
        Set-PinnedApplication -Action 'PintoStartMenu' -FilePath "$CommonStartMenuPrograms\Acrobat Reader DC.lnk"
        
        # Test whether a Microsoft Windows update is installed
        Test-MSUpdates -KBNumber 'KB2549864'

        # Install all Microsoft Updates of type ".exe", ".msu", or ".msp" in a given directory (recursively search directory).
        Install-MSUpdates -Directory "$Files\MSUpdates"

        # Triggers SCCM to invoke the requested schedule task id. Options: HardwareInventory, SoftwareInventory, HeartbeatDiscovery, SoftwareInventoryFileCollection, RequestMachinePolicy, EvaluateMachinePolicy, LocationServicesCleanup, SoftwareMeteringReport, SourceUpdate, PolicyAgentCleanup, RequestMachinePolicy2, CertificateMaintenance, PeerDistributionPointStatus, PeerDistributionPointProvisioning, ComplianceIntervalEnforcement, SoftwareUpdatesAgentAssignmentEvaluation, UploadStateMessage, StateMessageManager, SoftwareUpdatesScan, AMTProvisionCycle, UpdateStorePolicy, StateSystemBulkSend, ApplicationManagerPolicyAction, PowerManagementStartSummarizer
        Invoke-SCCMTask 'SoftwareUpdatesScan'

        # Scans for outstanding SCCM updates to be installed and installs the pending updates. Only compatible with SCCM 2012 Client or higher. This function can take several minutes to run
        Install-SCCMSoftwareUpdates

   
        ### Search/Replace in text files ###

        # First create a simple 10 line example in diffrent encodigs to have something where we can test the Edit-StringInFile command
        For ($i=0; $i -le 10; $i++) {Out-File -FilePath $SystemDrive\temp\ascii.txt -Encoding ascii -InputObject "The quick brown fox jumps over the lazy dog" -Append}
        For ($i=0; $i -le 10; $i++) {Out-File -FilePath $SystemDrive\temp\Unicode.txt -Encoding Unicode -InputObject "The quick brown fox jumps over the lazy dog" -Append}
        For ($i=0; $i -le 10; $i++) {Out-File -FilePath $SystemDrive\temp\UTF8.txt -Encoding UTF8 -InputObject "The quick brown fox jumps over the lazy dog" -Append}

        #Replace fox with tiger in ANSI/ASCII file
        Edit-StringInFile -Pattern 'fox' -Replacement 'tiger' -LiteralPath $SystemDrive\temp\ASCII.txt -Overwrite -CaseSensitive

        #Replace fox with tiger in a Unicode file
        Edit-StringInFile -Pattern 'fox' -Replacement 'tiger' -LiteralPath $SystemDrive\temp\Unicode.txt -Overwrite -CaseSensitive -Encoding Unicode

        #Replace fox with tiger in a UTF8 file
        Edit-StringInFile -Pattern 'fox' -Replacement 'tiger' -LiteralPath $SystemDrive\temp\UTF8.txt -Overwrite -CaseSensitive -Encoding UTF8

    
        ### Check Remote System status via Ping ###

        # Test ping on a computer name
        $Return = Test-Ping -ComputerName www.google.com
        Write-Host "Ping result is: $Return"

        # Test ping on a IP addresse
        $Return = Test-Ping -ComputerName 8.8.8.8
        Write-Host "Ping result is: $Return"

        # Use Test-Ping to retrive an object with some details about the remote host (e.g. use it to resolve hostname from IP address or vice versa)
        $ReturnObject = Test-Ping -ComputerName 216.58.209.36 -PassThru
        write-Host "The hostname of IP: " $ReturnObject.AddressUsed " is: " $ReturnObject.Hostname

    
        ### Base 64 Encode/Decode  ###

        # Base64 Encode example
	    $Return = Convert-Base64 -Action Encode -String "This is a test string"

        # Base64 Decode example
	    $Return = Convert-Base64 -Action Decode -String "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n"

        # Base64 Decode example not showing up in the log file for security reason
	    $Return = Convert-Base64 -Action Encode -String "My Secret, should not shown in the logfile" -SecureParameters

        # Base64 Decode example with error and Continue On Error
	    $Return = Convert-Base64 -Action Decode -String "This is not a Base64 string and this will throw an error, this is only a test to test the error handler" -ContinueOnError
        Write-host "When you can read this ContinueOnError is working"

        
        ### Fonts  ###

        # Example how to install a font
        Add-Font "$Files\Example.ttf"

        # Example how to uninstall a font
        Remove-Font "Example.ttf"


        ### File Verbs  ###

        # Example how to get file verbs from an exe file
        Get-FileVerb -file "$WinDir\notepad.exe"

        # Example how to get file verbs from an pdf file
        Get-FileVerb -file "$files\example.zip"

        # Example how to use a file verb of a EXE file like "Run as admin"
        Invoke-FileVerb -file "$WinDir\notepad.exe" -verb '&Als Administrator ausführen'

        # Example how to use a file verb of a ZIP file like "Extract all..."
        Invoke-FileVerb -file "$files\example.zip" -verb 'Alle extra&hieren...'


        ### Update module in packages  ###

        # Exampe how to update the framework file in multiple packages
        Update-FrameworkInPackages -ModuleFolder "$Systemdrive\OneDrive\Documents\WindowsPowerShell\Modules" -PackagesFolder "$SystemDrive\Test"

        ### Convert from/to INI  ###

        # Example 1 Convert ini content to object
        $IniFileContent = Get-content -Path "$Files\Example.ini"
        $IniObject = ConvertFrom-Ini -InputObject $IniFileContent
        $IniObject
    
        # Example 2 Convert ini content to object (same as example 1 but in 1 line)
        $IniObject2 = ConvertFrom-Ini (Get-Content -Path "$Files\Example.ini") 
        $IniObject2

        # Example read ini content to object , modify some settings, convert it back from object to ini and write it to disk    
        $IniFileContent = Get-content -Path "$Files\Example.ini"
        $IniObject = ConvertFrom-Ini -InputObject $IniFileContent
        $IniObject.Section1.Key1 = "test"
        $IniObject.Section1 | add-member –membertype NoteProperty –name "TestKey99" –Value "TestValue99"
        $IniObject | add-member –membertype NoteProperty –name "Section99" -Value ""
        $IniFileContent = ConvertTo-Ini -InputObject $IniObject
        $IniFileContent | Out-File "$Files\ExampleOutput.ini" -Encoding ascii
   
        # Example INI to JSON convert
        $IniFileContent = Get-content -Path "$Files\Example.ini"
        $IniObject = ConvertFrom-Ini -InputObject $IniFileContent
        $JSONObject = ConvertTo-Json -InputObject $IniObject
        $JSONObject | Out-File "$Files\ExampleOutput.json"

        # Example AAP.ini to AAP.json convert
        $IniFileContent = Get-content -Path "$Files\ExampleAAP.ini"
        $IniObject = ConvertFrom-Ini -InputObject $IniFileContent
        $JSONObject = ConvertTo-Json -InputObject $IniObject
        $JSONObject | Out-File "$Files\ExampleAAPOutput.json"

        # Example Work with AAP.json
        [psobject]$JsonObject = get-content "$Files\ExampleAAPOutput.json" -raw | ConvertFrom-Json 
        [array]$PublApps = (Get-Member -InputObject $JsonObject -MemberType NoteProperty).Name
        ForEach ($PublApp in $PublApps) {
                Write-Host "`r`n[$PublApp]"
                Write-host  $JsonObject.$PublApp.psobject.properties['AppName'].value
                Write-host  $JsonObject.$PublApp.psobject.properties['PNFolder'].value
                Write-host  $JsonObject.$PublApp.psobject.properties['DefaultInitProg'].value
        }


        ### Layout Modification ###

        # Example how to pin the startmenu entry "Utilities\PuTTY.lnk"
        New-LayoutmodificationXML -AppFolder "Utilities" -AppName "PuTTY"

        # Example more complex example with some optional parameters
        New-LayoutmodificationXML -AppName "PuTTY" -FolderName "Utilities" -TemplatePath "$SystemDrive\Temp\LayoutModificationTemplate.xml" -exportpath "$SystemDrive\Temp\LayoutModification.xml" -ForcePin -StartMenuPath "$env:Programdata\Microsoft\Windows\Start Menu\Programs"

        # Example with AAP.ini
        $MyAAPObject = ConvertFrom-AAPINI -Path "$ProgramFilesX86\visionapp\vCT\AAP.ini"
        New-LayoutmodificationXML -InputObject $MyAAPObject

        # Example with AAP.ini and some options
        $MyAAPObject = ConvertFrom-AAPINI -Path "$ProgramFilesX86\visionapp\vCT\AAP.ini"
        $MyAAPObject | New-LayoutmodificationXML -exportpath "$SystemDrive\Temp\LayoutModification.xml" -ForcePin

        # Example with Application JSON object
        $PackageConfigFile.Applications | New-LayoutmodificationXML -exportpath "$SystemDrive\Temp\LayoutModification.xml" -ForcePin


        ### Add/Remove Program entry ###

        # Example how to add a Add/Remove Programs entry
        Add-AddRemovePrograms -Name "My Custom Test App 1" -Version '1.0.0.0'
        Add-AddRemovePrograms -Name "My Custom Test App 2" -Version '2.0.0.0' -Publisher "Custom App Inc." -Target User -NoModify -NoRepair -NoRemove -Icon "C:\Windows\System32\WindowsUpdate.ico"

        # Example how to remove a Add/Remove Programs entry
        Remove-AddRemovePrograms -Name "My Custom Test App 1"
        Remove-AddRemovePrograms -Name "My Custom Test App 2"

        ### Check for DSM packages ###

        if (Test-DSMPackage -GUID "E5565EC5-6D27-4322-B26D-ED0F75BF86FC") {Show-DialogBox "Package found!" }
        if (Test-DSMPackage -GUID "E5565EC5-6D27-4322-B26D-ED0F75BF86FC","E5565EC5-6D27-4322-B26D-ED0F75BF86FX") {Show-DialogBox "Package found!" }
        if (Test-DSMPackage -Name "PackageNameA") {Show-DialogBox "Package found!" }
        if (Test-DSMPackage -Name "PackageNameA","PackageNameB") {Show-DialogBox "Package found!" }
        if (Test-DSMPackage -Name "PackageNameC") {Show-DialogBox "Package found!" }

    #endregion Misc
    
    #region PackagingTools


        ### New-Package ###
    
        # Create a new package with module files inside the package folder
        New-Package -Path $Systemdrive\Temp -Name 'Microsoft_Office_16.0_EN_01.00'

        # Create a new package without module files inside the package folder
        New-Package -Path $Systemdrive\Temp -Name 'Microsoft_Project_16.0_EN_01.00' -ExcludeModuleFiles


        ### Test-Package ###

        # Example Test-Package
        Test-Package -path "$Systemdrive\Test" | Sort Severity | Format-Table Package,Severity,Description


        ### Test-PackageName ###
        
        # Test-PackageName Example 1, test current package name (expected result=true)
        $result = Test-PackageName
        Write-Log "RESULT: $result"

        # Test-PackageName Example 2, test a specified package name (expected result=True)
        $result = Test-PackageName -name 'Microsoft_Notepad_1.0_DE_01.00'
        Write-Log "RESULT: $result"

        # Test-PackageName Example 3, test a specified package name with some errors like unknown language (expected result=false)
        $result = Test-PackageName -name 'Microsoft_Notepad_1.0_NL_01.00'
        Write-Log "RESULT: $result"
   
        # Test-PackageName Example 4, test a specified package name with some errors like v character in front of the version number (expected result=false)
        $Result = Test-PackageName -Name 'Microsoft_Office_v16.0_EN_01.00'
        Write-Log "RESULT: $Result"


        ### Update Framework in Packages ###

        # Update all pakcages regarding the included Framework
        Update-FrameworkInPackages -ModuleFolder "C:\Temp\Ceterion_Template_1.0_EN_01.00\" -PackagesFolder "C:\Temp\"


        ### NSIS wrapper ###

        # Warp PowerShell pacakge with NSIS (NSIS must be installed)
        Start-NSISWrapper -Path "C:\Temp\FileZillaProject_FileZilla_3.28.0_DE_01.00"

        # Find all packages in a folder structure and wrap all with NSIS
        Get-ChildItem -Path "C:\Temp" -Filter "*.ps1" -Recurse -Depth 2 | ForEach-Object {
            if ([io.path]::GetFileNameWithoutExtension(((Get-Item $_.FullName).Name)) -ieq (Split-Path -path (Get-Item $_.FullName).DirectoryName -Leaf) ){
                Start-NSISWrapper -Path (Get-Item $_.FullName).DirectoryName
            }
        }

        # Sign package script and module files
        $cert =  Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
        Start-SignPackageScript -Path "c:\temp\DonHo_NotepadPlusPlusX64_7.5.1_ML_01.00" -Certificate $cert -HashAlgorithm 'SHA256' -IncludeChain All -TimestampServer "http://time.certum.pl"

        # NSIS Wrapper incling signing
        $cert =  Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
        Start-NSISWrapper -Path "c:\temp\DonHo_NotepadPlusPlusX64_7.5.1_ML_01.00" -Sign  -Certificate $cert -HashAlgorithm 'SHA256' -IncludeChain All -TimestampServer "http://time.certum.pl"

        ### Intune wrapper ###
        Start-IntuneWrapper -Path "C:\Temp\FileZillaProject_FileZilla_3.28.0_DE_01.00"

        # Find all packages in a folder structure and wrap all for Intunes
        Get-ChildItem -Path "C:\Temp" -Filter "*.ps1" -Recurse -Depth 2 | ForEach-Object {
            if ([io.path]::GetFileNameWithoutExtension(((Get-Item $_.FullName).Name)) -ieq (Split-Path -path (Get-Item $_.FullName).DirectoryName -Leaf) ){
                Start-IntuneWrapper -Path (Get-Item $_.FullName).DirectoryName
            }
        }


        ### DSM, WISE and NSIS Converters (optional) ###
   
        # Convert Wise Package to PowerShell
        Convert-WISEPackage -WISEPackageFolder 'C:\Convert' -PSPackageFolder 'C:\Converted' -Depth 2

        # Convert NSIS Package to PowerShell
        Convert-NSISPackage -NSISPackageFolder 'C:\Convert' -PSPackageFolder 'C:\Converted' -Depth 2

        # Convert DSM Package (aka enteo NetInstall, Avanti, etc. ) to PowerShell
        Convert-DSMPackage -DSMPackageFolder 'C:\Convert' -PSPackageFolder 'C:\Converted' -Depth 2


        ### Other ###

        # Move all compiled packages from the package sub folder to a tagret folder (incl. folders)
        Get-ChildItem -Path "C:\Packages" -Filter "*.exe" -Recurse -Depth 2 | ForEach-Object {
        if ([io.path]::GetFileNameWithoutExtension(((Get-Item $_.FullName).Name)) -ieq (Split-Path -path (Get-Item $_.FullName).DirectoryName -Leaf) ){
            $DestinationRoot = "C:\Compiled"
            $CategorySubFolder = $_.FullName.Split("\")[-3]
            If (-not(Test-Path -path "$DestinationRoot\$CategorySubFolder")) {New-Folder "$DestinationRoot\$CategorySubFolder" }
            Move-Item -Path $_.FullName -Destination "$DestinationRoot\$CategorySubFolder" -Verbose -force
        }

        # Set correct EOL and Encoding for all package PS1, NSI and JSON files
        Get-ChildItem -Path "C:\Converted\*" -Include *.ps1,*.nsi,*.json -Recurse -Depth 2 | ForEach-Object {
            if ([io.path]::GetFileNameWithoutExtension(((Get-Item $_.FullName).Name)) -ieq (Split-Path -path (Get-Item $_.FullName).DirectoryName -Leaf) ) {
                if ($_.Name -ine "PackagingFramework.json") {
                    Set-EOL -File $_.FullName -LineEnding 'win' -Encoding 'iso-8859-1'
                }
            }
        }






}


    #endregion PackagingTools


    }


	# Call package end and exit script
	Invoke-PackageEnd ; Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}