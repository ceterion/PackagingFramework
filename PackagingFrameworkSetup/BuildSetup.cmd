REM Sign Scripts before compile
Powershell.exe -Command "&{ Set-AuthenticodeSignature -Certificate $(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert) -HashAlgorithm 'SHA256' -IncludeChain All -TimestampServer "http://time.certum.pl" -FilePath ".\..\PackagingFramework\*.ps?1" }"
Powershell.exe -Command "&{ Set-AuthenticodeSignature -Certificate $(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert) -HashAlgorithm 'SHA256' -IncludeChain All -TimestampServer "http://time.certum.pl" -FilePath ".\..\PackagingFrameworkExtension\*.ps?1" }"

REM Compile via NSIS (makensisw.exe)
"C:\Program Files (x86)\NSIS\makensis.exe" ".\PackagingFrameworkSetup.nsi" 

REM Sign compiled EXE
Powershell.exe -Command "&{ Set-AuthenticodeSignature -Certificate $(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert) -HashAlgorithm 'SHA256' -IncludeChain All -TimestampServer "http://time.certum.pl" -FilePath ".\PackagingFrameworkSetup.exe" }"

