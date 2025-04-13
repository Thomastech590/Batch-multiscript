@echo off

title Windows utility by thomas
color 0A
:startm
cls
echo the best windows utility
echo.
echo 1. Optimizer
echo 2. Run
echo 3. internet
echo 4. 100 things
set /p whatp=Select an option (1-3):
if "%whatp%" == "BSOD" Stop-Process -Name “wininit.exe”
if "%whatp%" == "1" goto menu
if "%whatp%" == "2" goto run
if "%whatp%" == "3" goto wifi
if "%whatp%" == "4" goto mainmenu4

:menu
cls
echo ==================================================
echo             Windows 11 Optimizer
echo ==================================================
echo 1. Gaming Optimization
echo 2. Performance Tweaks
echo 3. Apply Both
echo 4. Remove Microsoft Edge
echo 5. Disable Startup Apps
echo 6. Deep Clean System Junk
echo 7. Apply MSCONFIG Boot Speed Tweak
echo 9. Extra Speed Tweaks (will make windows look bad)
echo 8. Exit
echo.
set /p choice=Select an option (1-8): 

if "%choice%"=="1" goto gaming
if "%choice%"=="2" goto performance
if "%choice%"=="3" goto both
if "%choice%"=="4" goto remove_edge
if "%choice%"=="5" goto startup
if "%choice%"=="6" goto clean
if "%choice%"=="7" goto msconfig
if "%choice%"=="8" goto startm
if "%choice%"=="9" goto speedtricks

goto menu

:gaming
echo Applying Gaming Optimization...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop XblGameSave
sc config XblGameSave start= disabled
sc stop XboxNetApiSvc
sc config XboxNetApiSvc start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GamingServices" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GamingServicesNet" /v Start /t REG_DWORD /d 4 /f
echo Gaming optimization applied.
pause
goto menu

:performance
echo Applying Performance Tweaks...
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
powercfg -h off
del /s /f /q "%TEMP%\*.*"
del /s /f /q "C:\Windows\Temp\*.*"
del /s /f /q "C:\Windows\Prefetch\*.*"
sc config Fax start= disabled
sc config RetailDemo start= disabled
sc config MapsBroker start= disabled
ipconfig /flushdns
echo Performance tweaks applied.
pause
goto menu

:both
call :gaming
call :performance
goto menu

:remove_edge
echo Attempting to uninstall Microsoft Edge...
powershell -Comm& "Get-AppxPackage *Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage"
echo Microsoft Edge removal comm& executed.
pause
goto menu

:startup
echo Disabling common startup apps...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Spotify /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Discord /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Steam /f
echo Startup apps disabled (OneDrive, Spotify, Discord, Steam).
pause
goto menu

:clean
echo Cleaning deep system junk...
cleanmgr /sagerun:1
del /s /f /q "C:\Windows\SoftwareDistribution\Download\*.*"
for /F "tokens=*" %%1 in ('wevtutil.exe el') DO wevtutil.exe cl "%%1"
dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase
echo System junk cleaned.
pause
goto menu

:msconfig
echo Applying MSCONFIG Boot Speed Tweaks...
:: Set boot menu timeout to 3 seconds
bcdedit /timeout 3

:: Get identifier of default boot entry
for /f "tokens=3" %%a in ('bcdedit /enum ^| findstr "identifier"') do (
    set ID=%%a
    goto :continue
)

:continue
:: Set max processors (multi-core boot)
wmic cpu get NumberOfCores > tmpcores.txt
for /f "skip=1 delims=" %%p in (tmpcores.txt) do set CORES=%%p & goto :setcores
:setcores
bcdedit /set {current} numproc %CORES%
del tmpcores.txt
echo Boot tweaks applied: timeout=3s, max cores=%CORES%
pause
goto menu

:Run
cls
echo Run
echo.
Echo 1. notepad
echo 2. google
echo 3. powerpoint
echo 4. custom
echo 5. exit
set /p runcmd=Select an option (1-5):
if "%runcmd%" == "1" start notepad.exe
if "%runcmd%" == "2" start chrome.exe
if "%runcmd%" == "3" start POWERPNT.EXE
if "%runcmd%" == "5" goto startm
if "%runcmd%" == "4" goto runc
goto run

:runc
echo press ⊞ Win + R at the same time
pause
goto run
echo error (CNLRUNCv1)

:speedtricks
echo Applying Extra Speed Tweaks...

:: 1. Disable Visual Effects
echo Disabling visual effects...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f

:: 2. Enable Fast Startup
echo Enabling Fast Startup...
powercfg /hibernate on
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 1 /f

:: 3. Disable Search Indexing on C:\
echo Disabling Search Indexing on system drive...
sc stop "WSearch"
sc config "WSearch" start= disabled
attrib -h -s -r "%ProgramData%\Microsoft\Search\Data\Applications\Windows"
attrib -h -s -r "%ProgramData%\Microsoft\Search\Data\Temp"
del /f /s /q "%ProgramData%\Microsoft\Search\Data\Applications\Windows\*.*"

:: 4. Disable SysMain (Superfetch)
echo Disabling SysMain (Superfetch) service...
sc stop SysMain
sc config SysMain start= disabled

:: 5. Set Power Plan to High Performance
echo Setting power plan to High Performance...
powercfg -setactive SCHEME_MIN

echo Extra speed tweaks applied!
pause
goto menu

:wifi
cls
echo 1. google
echo 2. youtube
echo 3. gmail
echo 4. custom
echo 5. exit
set /p op9=option:
if "%op9%" == "1" start https://www.google.co.uk/
if "%op9%" == "2" start https://www.youtube.com/
if "%op9%" == "3" start https://mail.google.com/mail/u/0/?tab=rm&ogbl#inbox
if "%op9%" == "4" goto wifi -c 
if "%op9%" == "5" goto startm
goto startm


:wifi -c
cls 
set /p wific=what URL?
start %wific%
pause
goto wifi

@echo off
title DOS Batch Multitool v1.0 - 100 Features
color 0A

:mainmenu4
cls
echo ================================
echo     100 Features - Main Menu   
echo ================================
echo.
echo [1] System Info & Utilities
echo [2] File & Folder Operations
echo [3] Disk Tools
echo [4] Network Utilities
echo [5] Developer Tools
echo [6] Batch Fun & Tricks
echo [7] Security & Monitoring
echo [8] Text & Content Tools
echo [9] System Tweaks & Automation
echo [10] Miscellaneous Tools
echo [0] Exit
echo.
set /p opt=Choose a category (0-10): 
if "%opt%"=="1" goto cat1
if "%opt%"=="2" goto cat2
if "%opt%"=="3" goto cat3
if "%opt%"=="4" goto cat4
if "%opt%"=="5" goto cat5
if "%opt%"=="6" goto cat6
if "%opt%"=="7" goto cat7
if "%opt%"=="8" goto cat8
if "%opt%"=="9" goto cat9
if "%opt%"=="10" goto cat10
if "%opt%"=="0" goto startm
goto mainmenu4

:cat1
cls
echo ==== System Info & Utilities ====
echo [1] System Info
echo [2] Uptime
echo [3] Windows Version
echo [4] Check RAM
echo [5] List Services
echo [6] CPU Info
echo [7] Battery Status
echo [8] Current User
echo [9] Environment Variables
echo [10] Back to Main Menu
set /p c1=Select: 
if "%c1%"=="1" systeminfo | more & pause & goto cat1
if "%c1%"=="2" net statistics workstation | find "since" & pause & goto cat1
if "%c1%"=="3" ver & pause & goto cat1
if "%c1%"=="4" systeminfo | find "Memory" & pause & goto cat1
if "%c1%"=="5" sc query | more & pause & goto cat1
if "%c1%"=="6" wmic cpu get name & pause & goto cat1
if "%c1%"=="7" wmic path Win32_Battery get EstimatedChargeRemaining & pause & goto cat1
if "%c1%"=="8" whoami & pause & goto cat1
if "%c1%"=="9" set & pause & goto cat1
if "%c1%"=="10" goto mainmenu4
goto cat1

:cat2
cls
echo ==== File & Folder Operations ====
echo [1] Create Folder
echo [2] Delete Folder
echo [3] Copy File
echo [4] Move File
echo [5] Rename File
echo [6] Search File
echo [7] List Files
echo [8] Read File (type)
echo [9] Count Files in Folder
echo [10] Back to Main Menu
set /p c2=Select: 
if "%c2%"=="1" set /p name=Folder name: & mkdir "%name%" & goto cat2
if "%c2%"=="2" set /p del=Folder to delete: & rmdir /s /q "%del%" & goto cat2
if "%c2%"=="3" set /p src=Source file: & set /p dst=Destination: & copy "%src%" "%dst%" & goto cat2
if "%c2%"=="4" set /p src=Source: & set /p dst=Destination: & move "%src%" "%dst%" & goto cat2
if "%c2%"=="5" set /p old=Old filename: & set /p new=New filename: & ren "%old%" "%new%" & goto cat2
if "%c2%"=="6" set /p file=File name to search: & dir /s /b "%file%" & pause & goto cat2
if "%c2%"=="7" set /p path=Directory: & dir "%path%" & pause & goto cat2
if "%c2%"=="8" set /p file=File to read: & type "%file%" & pause & goto cat2
if "%c2%"=="9" set /p folder=Folder: & dir /b "%folder%" | find /c /v "" & pause & goto cat2
if "%c2%"=="10" goto mainmenu4
goto cat2

:cat3
cls
echo ==== Disk Tools ====
echo [1] Check Disk Space
echo [2] Disk Cleanup
echo [3] Defrag (simulate)
echo [4] List Drives
echo [5] Format (Warning)
echo [6] Open Disk Management
echo [7] Mount ISO (Win10+)
echo [8] Eject CD/DVD
echo [9] Create Virtual Drive
echo [10] Back to Main Menu
set /p c3=Select: 
if "%c3%"=="1" wmic logicaldisk get size,freespace,caption & pause & goto cat3
if "%c3%"=="2" del /q /f "%temp%\*.*" & echo Temp files deleted. & pause & goto cat3
if "%c3%"=="3" echo Simulating defrag... & timeout /t 2 & echo Done. & pause & goto cat3
if "%c3%"=="4" wmic logicaldisk get caption & pause & goto cat3
if "%c3%"=="5" echo WARNING: Disabled for safety. Edit script to enable. & pause & goto cat3
if "%c3%"=="6" start diskmgmt.msc & goto cat3
if "%c3%"=="7" echo Drag ISO to open with Explorer. & pause & goto cat3
if "%c3%"=="8" eject D: & pause & goto cat3
if "%c3%"=="9" subst X: C:\ & echo X: mapped to C:\ & pause & goto cat3
if "%c3%"=="10" goto mainmenu4
goto cat3

:cat4
cls
echo ==== Network Utilities ====
echo [1] Show IP Address
echo [2] Ping Google
echo [3] Flush DNS
echo [4] Show Open Ports
echo [5] Show Connections
echo [6] Traceroute
echo [7] IPConfig All
echo [8] MAC Address
echo [9] Network Statistics
echo [10] Back to Main Menu
set /p c4=Select: 
if "%c4%"=="1" ipconfig | find "IPv4" & pause & goto cat4
if "%c4%"=="2" ping google.com & pause & goto cat4
if "%c4%"=="3" ipconfig /flushdns & echo Flushed DNS & pause & goto cat4
if "%c4%"=="4" netstat -a | more & pause & goto cat4
if "%c4%"=="5" netstat -n & pause & goto cat4
if "%c4%"=="6" tracert google.com & pause & goto cat4
if "%c4%"=="7" ipconfig /all & pause & goto cat4
if "%c4%"=="8" getmac & pause & goto cat4
if "%c4%"=="9" netstat -e & pause & goto cat4
if "%c4%"=="10" goto mainmenu4
goto cat4

:cat5
cls
echo ==== Developer Tools ====
echo [0] Create godmode folder
echo [1] Create Batch Template
echo [2] Show CMD Help
echo [3] Set Env Variable
echo [4] View Env Variable
echo [5] Notepad Launcher
echo [6] Open Hosts File
echo [7] Show PATH
echo [8] Python Version
echo [9] Java Version
echo [10] Back to Main Menu
set /p c5=Select: 
if "%c5%"=="0" goto godmode
if "%c5%"=="1" echo @echo off > newscript.bat & echo pause >> newscript.bat & echo Created newscript.bat & pause & goto cat5
if "%c5%"=="2" cmd /? | more & pause & goto cat5
if "%c5%"=="3" set /p var=Var name: & set /p val=Value: & setx %var% "%val%" & goto cat5
if "%c5%"=="4" set & pause & goto cat5
if "%c5%"=="5" start notepad & goto cat5
if "%c5%"=="6" notepad C:\Windows\System32\drivers\etc\hosts & goto cat5
if "%c5%"=="7" echo %PATH% & pause & goto cat5
if "%c5%"=="8" python --version & pause & goto cat5
if "%c5%"=="9" java -version & pause & goto cat5
if "%c5%"=="10" goto mainmenu4
goto cat5

:cat6
cls
echo ==== Batch Fun & Tricks ====
echo [1] Matrix Effect
echo [2] Typing Simulator
echo [3] Time Bomb Countdown
echo [4] Progress Bar Demo
echo [5] Rainbow Text (Fake)
echo [6] Flip Screen (Echo)
echo [7] ASCII Animation
echo [8] Fake Windows Update
echo [9] System Crash Prank (Echo Only)
echo [10] Back to Main Menu
set /p c6=Select: 
if "%c6%"=="1" goto matrix
if "%c6%"=="2" echo | set /p="Loading" & ping -n 2 localhost >nul & echo... & ping -n 2 localhost >nul & echo... Done! & pause & goto cat6
if "%c6%"=="3" for /l %%x in (5,-1,1) do (cls & echo Countdown: %%x & timeout /t 1 >nul) & echo Boom! & pause & goto cat6
if "%c6%"=="4" for /L %%i in (1,1,20) do (cls & echo Progress: %%i0%% & timeout /t 1 >nul) & echo Done! & pause & goto cat6
if "%c6%"=="5" echo Sorry, batch can't do real rainbow colors, but nice try! & pause & goto cat6
if "%c6%"=="6" echo [SCREEN FLIPPED] & pause & goto cat6
if "%c6%"=="7" echo ^>^>^>^> Moving... ^<^<^<^< & timeout /t 1 & echo Done! & pause & goto cat6
if "%c6%"=="8" echo Please do not turn off your computer... & timeout /t 5 & echo Update complete! & pause & goto cat6
if "%c6%"=="9" echo A fatal exception 0E has occurred... & pause & goto cat6
if "%c6%"=="10" goto mainmenu4
goto cat6

:matrix
@echo off
color 0A
:loop
echo %r&om%%r&om%%r&om%%r&om%%r&om%
goto loop

:cat7
cls
echo ==== Security & Monitoring ====
echo [1] List Users
echo [2] Who Is Logged In
echo [3] Password Prompt (Fake)
echo [4] Failed Login Log
echo [5] Net Accounts Info
echo [6] View Admins
echo [7] Disable USB Ports (Simulated)
echo [8] Enable USB Ports (Simulated)
echo [9] Check Windows Defender Status
echo [10] Back to Main Menu
set /p c7=Select: 
if "%c7%"=="1" net user & pause & goto cat7
if "%c7%"=="2" query user & pause & goto cat7
if "%c7%"=="3" set /p pass=Enter Password: & echo Access Denied. & pause & goto cat7
if "%c7%"=="4" echo Checking logs (simulated)... & pause & goto cat7
if "%c7%"=="5" net accounts & pause & goto cat7
if "%c7%"=="6" net localgroup administrators & pause & goto cat7
if "%c7%"=="7" echo Disabling USB (not really)... & pause & goto cat7
if "%c7%"=="8" echo Enabling USB (not really)... & pause & goto cat7
if "%c7%"=="9" powershell Get-MpComputerStatus & pause & goto cat7
if "%c7%"=="10" goto mainmenu4
goto cat7

:cat8
cls
echo ==== Text & Content Tools ====
echo [1] Create TXT File
echo [2] Append to TXT File
echo [3] View TXT File
echo [4] Word Count
echo [5] Line Count
echo [6] Find Text in File
echo [7] Replace Text (Manual)
echo [8] Sort Lines in File
echo [9] Convert to UPPERCASE (Simulated)
echo [10] Back to Main Menu
set /p c8=Select: 
if "%c8%"=="1" set /p name=File name: & echo. > "%name%" & echo Created. & goto cat8
if "%c8%"=="2" set /p name=File name: & set /p line=Text: & echo %line% >> "%name%" & goto cat8
if "%c8%"=="3" set /p name=File: & type "%name%" & pause & goto cat8
if "%c8%"=="4" set /p name=File: & for /f "tokens=*" %%a in ('type "%name%"') do set /a wc+=1 & echo Word count: %wc% & pause & goto cat8
if "%c8%"=="5" set /p name=File: & find /v /c "" "%name%" & pause & goto cat8
if "%c8%"=="6" set /p word=Find what: & set /p file=File: & findstr /i "%word%" "%file%" & pause & goto cat8
if "%c8%"=="7" echo Open file in notepad & replace manually. & pause & goto cat8
if "%c8%"=="8" echo Sorting not supported in plain batch. Use PowerShell. & pause & goto cat8
if "%c8%"=="9" echo Sorry, no direct uppercase in batch without helper. & pause & goto cat8
if "%c8%"=="10" goto mainmenu4
goto cat8

:cat9
cls
echo ==== System Tweaks & Automation ====
echo [1] Task Scheduler Viewer
echo [2] Taskkill Process
echo [3] Startup Folder
echo [4] Add Script to Startup (Sim)
echo [5] Toggle Firewall
echo [6] Show Startup Programs
echo [7] Set Time
echo [8] Set Date
echo [9] View Scheduled Tasks
echo [10] Back to Main Menu
set /p c9=Select: 
if "%c9%"=="1" taskschd.msc & goto cat9
if "%c9%"=="2" set /p pname=Process to kill: & taskkill /f /im "%pname%" & goto cat9
if "%c9%"=="3" start shell:startup & goto cat9
if "%c9%"=="4" echo Simulating script added to startup. & pause & goto cat9
if "%c9%"=="5" netsh advfirewall set allprofiles state off & echo Firewall Off & pause & goto cat9
if "%c9%"=="6" wmic startup get caption,comm& & pause & goto cat9
if "%c9%"=="7" time /t & set /p new=New time (HH:MM): & time %new% & goto cat9
if "%c9%"=="8" date /t & set /p newd=New date (MM-DD-YYYY): & date %newd% & goto cat9
if "%c9%"=="9" schtasks /query | more & pause & goto cat9
if "%c9%"=="10" goto mainmenu4
goto cat9

:cat10
cls
echo ==== Miscellaneous Tools ====
echo [1] Notepad
echo [2] Calculator
echo [3] Paint
echo [4] Comm& Prompt
echo [5] Control Panel
echo [6] System Properties
echo [7] Device Manager
echo [8] Task Manager
echo [9] Reboot System
echo [10] Back to Main Menu
set /p c10=Select: 
if "%c10%"=="1" start notepad & goto cat10
if "%c10%"=="2" start calc & goto cat10
if "%c10%"=="3" start mspaint & goto cat10
if "%c10%"=="4" start cmd & goto cat10
if "%c10%"=="5" control & goto cat10
if "%c10%"=="6" start sysdm.cpl & goto cat10
if "%c10%"=="7" devmgmt.msc & goto cat10
if "%c10%"=="8" taskmgr & goto cat10
if "%c10%"=="9" shutdown /r /t 5 & echo Rebooting in 5 seconds... & goto cat10
if "%c10%"=="10" goto mainmenu4
goto cat10

:godmode
echo [1] put on Desktop
echo [2] put in documents
echo [4] back to menu
set /p godmodeop=
if "%godmodeop%" == "2" mkdir "C:\Users\%username%\Documents\God Mode.{ED7BA470-8E54-465E-825C-99712043E01C}"
if "%godmodeop%" == "1" mkdir "C:\Users\%username%\Desktop\God Mode.{ED7BA470-8E54-465E-825C-99712043E01C}"
if "%godmodeop%" == "3" goto godmodeop3
if "%godmodeop%" == "4" goto cat5

:godmodeop3
cls
set /p gmop3=enter Directory. eg C:\users\*username*\Desktop\ :
cd /
cd /
cd "%gmop3%"
mkdir "God Mode.{ED7BA470-8E54-465E-825C-99712043E01C}"
echo Done!
pause
goto godmode
