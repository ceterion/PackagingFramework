[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter)
Try {
    
    # Import Packaging Framework module
    $Global:DeploymentType=$Script:DeploymentType ; $Global:DeployMode=$Script:DeployMode ; $Global:CustomParameter=$Script:CustomParameter ; Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}

    # Install
	If ($deploymentType -ieq 'Install') {
        
        # Params
        Get-Parameter InstallDir -Default "$ProgramFiles\Sysinternals" -Expand
        		
        # Install files
        Write-Log "Installing files to [$InstallDir]" -Source "Expand-Archive"
        Expand-Archive -Path "$Files\SysinternalsSuite.zip" -DestinationPath $InstallDir -Force

	}

	# Uninstall
    If ($deploymentType -ieq 'Uninstall') {
        
        # Uninstall files
        Remove-Folder -path $InstallDir
    }

	# Call the exit-Script
	Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}