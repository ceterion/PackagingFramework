Pushd "%~dp0"
Set SEE_MASK_NOZONECHECKS=1
.\PackagingFrameworkSetup.exe /S
"%WinDir%\System32\WindowsPowerShell\v1.0\PowerShell.exe" -ExecutionPolicy Bypass -Command "& {Import-Module PackagingFramework ; Install-DeployPackageService -InstallService -ServiceCredential (Get-Credential -username serviceaccount@domain.local -message 'Enter password') -NetworkShare "\\Server\Share" -PackageFolder "Packages" -DeployScriptFolder "DeployScripts" -ReportingFolder "Reporting" -CsvFile "Install-DeployPackageService "}"
SchTasks /Run /TN "\DeployPackageService"
