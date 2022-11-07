[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter, [Parameter(Mandatory=$false)] [switch]$AllowRebootPassThru = $true)
Try {

    # Import Packaging Framework module
    $Global:DeploymentType=$Script:DeploymentType ; $Global:DeployMode=$Script:DeployMode ; $Global:CustomParameter=$Script:CustomParameter ; $Global:AllowRebootPassThru = $Script:AllowRebootPassThru ; Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; Remove-Module PackagingFrameworkExtension -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script} ; Invoke-PackageStart
	
    # Installation
    If ($deploymentType -ieq 'Install') {

	    # Installation
        Start-Program -Path "$Files\npp.7.5.1.Installer.x64.exe" -Parameters "/S"
		
        # Cleanup
        Remove-Folder -Path "$CommonStartMenuPrograms\Notepad++"

        # Install additional localization files
		If ((Get-Parameter 'InstallLocalization') -eq $true)
        {
            Copy-File -Path "$Files\localization\*" -Destination "$ProgramFiles\Notepad++\localization"

            # User configuration via ActiveSetup
            Set-ActiveSetup -StubExePath "$ProgramFiles\Notepad++\ActiveSetup.ps1"

        }

        # Disable auto update
		If ((Get-Parameter 'DisableAutoUpdate') -eq $true)
        {
            Remove-Folder -Path "$ProgramFiles\Notepad++\updater"
        }

        # Disable Shell Extension (removes the explorer "Edit with Notepad++" context menu)
		If ((Get-Parameter 'DisableShellExtension') -eq $true)
        {
            Invoke-RegisterOrUnregisterDLL -FilePath "$ProgramFiles\Notepad++\NppShell_06.dll" -DLLAction Unregister
        }        

	}	

    # Uninstall
    If ($deploymentType -ieq 'Uninstall') {
	
        Start-Program -Path "$ProgramFiles\Notepad++\uninstall.exe" -Parameters "/S"
        Remove-Folder "$ProgramFiles\Notepad++\localization"
        Set-ActiveSetup -PurgeActiveSetupKey
		
	}

    # Call package end and exit script
	Invoke-PackageEnd ; Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}