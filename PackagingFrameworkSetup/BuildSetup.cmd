REM Compile via NSIS (makensisw.exe)
"C:\Program Files (x86)\NSIS\makensis.exe" ".\PackagingFrameworkSetup.nsi" 
REM Sign via Signtool.exe (https://docs.microsoft.com/de-de/dotnet/framework/tools/signtool-exe)
set /p password=<..\PackagingFrameworkCodeSigning\ceterion-CodeSigning-2021_Password.txt
"..\PackagingFrameworkCodeSigning\x64\Signtool.exe" sign /f ..\PackagingFrameworkCodeSigning\ceterion-CodeSigning-2021.pfx /p %password% /fd SHA256 .\PackagingFrameworkSetup.exe
Pause
