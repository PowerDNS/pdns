; PowerDNS NSIS file
;------------------------------------------------------


; Defines.
;------------------------------------------------------

!define VERSION "2.9.13"


; Output settings.
;------------------------------------------------------

SetCompressor bzip2

!ifdef Debug
OutFile       "..\Debug\powerdns-${VERSION}-d.exe"
!define INDIR "..\Debug\"
!else
OutFile       "..\Release\powerdns-${VERSION}.exe"
!define INDIR "..\Release\"
!endif

BrandingText " "
XPStyle on

InstType "Full"
InstType "Minimal (no example zone)"

InstallDir $PROGRAMFILES\PowerDNS
InstallDirRegKey HKLM SOFTWARE\PowerDNS ""


;Include Modern UI
;------------------------------------------------------

!include "MUI.nsh"


; Names
;------------------------------------------------------
Name    "PowerDNS"
Caption "PowerDNS ${VERSION} for Windows Setup"


;Interface Settings
;------------------------------------------------------
!define MUI_ABORTWARNING

!define MUI_HEADERIMAGE
!insertmacro MUI_DEFAULT MUI_HEADERIMAGE_BITMAP "powerdns.bmp"

!define MUI_COMPONENTSPAGE_NODESC

!insertmacro MUI_DEFAULT MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\pixel-install.ico"
!insertmacro MUI_DEFAULT MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\pixel-uninstall.ico"

;Pages
;------------------------------------------------------
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of PowerDNS for Windows.\r\n\r\n\r\n$_CLICK"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_LINK "Visit the PowerDNS website for news and documentation."
!define MUI_FINISHPAGE_LINK_LOCATION "http://www.powerdns.com/"

!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

;Languages
;------------------------------------------------------
!insertmacro MUI_LANGUAGE "English"


;Sections
;------------------------------------------------------
Section "PowerDNS Nameserver (required)"

  SetDetailsPrint textonly
  DetailPrint "Installing PowerDNS..."
  SetDetailsPrint listonly

  SectionIn 1 2 RO
  SetOutPath $INSTDIR
  RMDir /r $SMPROGRAMS\PowerDNS

  SetOverwrite on
  File ${INDIR}\pdns.exe
  File ${INDIR}\pdns_control.exe
  File ${INDIR}\pdns_recursor.exe
  File ${INDIR}\pdnsmsg.dll
  File ${INDIR}\zone2sql.exe
  File ..\release-scripts\pdns.ico
  File ..\..\LICENSE

  WriteUninstaller $INSTDIR\uninst-pdns.exe

WriteRegStr HKLM SOFTWARE\PowerDNS "" $INSTDIR

WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerDNS" \
                   "DisplayName" "PowerDNS Nameserver (remove only)"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerDNS" \
                   "UninstallString" "$INSTDIR\uninst-pdns.exe"

  
  SetOverwrite ifnewer
  ; $SYSDIR doesn't work?
  File C:\WINNT\System32\pthreadVCE.dll
  File C:\WINNT\System32\msvcrt.dll


  ; Create default pdns configuration file.
IfFileExists "$INSTDIR\pdns.conf" NoConfWrite
  FileOpen $R1 "$INSTDIR\pdns.conf" "w"
  
    FileWrite $R1 "# PowerDNS configuration file.$\r$\n$\r$\n"

  FileWrite $R1 "# Use NT logging when running as a service:$\r$\n"
  FileWrite $R1 "use-ntlog=yes$\r$\n$\r$\n"

  FileWrite $R1 "# Backends to launch at startup:$\r$\n"
    FileWrite $R1 "launch=godbc$\r$\n$\r$\n"

    FileWrite $R1 "godbc-datasource=PowerDNS$\r$\n"
    FileWrite $R1 "godbc-username=PowerDNS$\r$\n"
    FileWrite $R1 "godbc-password=PowerDNS$\r$\n$\r$\n"

    FileWrite $R1 "# Point to the recursor:$\r$\n"
    FileWrite $R1 "recursor=127.0.0.1:5300$\r$\n$\r$\n"

  FileWrite $R1 "# Launch a statistical webserver:$\r$\n"
  FileWrite $R1 "webserver=yes$\r$\n"
  FileWrite $R1 "webserver-port=8081$\r$\n$\r$\n"

  FileWrite $R1 "# EOF$\r$\n"

  FileClose $R1

NoConfWrite:
  ; Create default pdns configuration file.
  IfFileExists "$INSTDIR\recursor.conf" NoConfRecWrite
    FileOpen $R2 "$INSTDIR\recursor.conf" "w"

    FileWrite $R2 "# PowerDNS Recursor configuration file.$\r$\n$\r$\n"

    FileWrite $R2 "# Use NT logging when running as a service:$\r$\n"
    FileWrite $R2 "use-ntlog=yes$\r$\n$\r$\n"

    FileWrite $R2 "# Port to run the recursor on:$\r$\n"
    FileWrite $R2 "local-port=5300$\r$\n$\r$\n"

    FileWrite $R2 "# EOF$\r$\n"

    FileClose $R2

NoConfRecWrite:

  Sleep 500

  MessageBox MB_YESNO "Do you want to register PowerDNS as a NT service?" IDNO NoReg
    Exec '"$INSTDIR\pdns.exe" --register-service'
    Exec '"$INSTDIR\pdns_recursor.exe" --register-service'

NoReg:

SectionEnd

Section "Start menu + shortcuts"
  SectionIn 1 2

  CreateDirectory "$SMPROGRAMS\PowerDNS"

  WriteINIStr "$SMPROGRAMS\PowerDNS\PowerDNS Homepage.url" \
              "InternetShortcut" "URL" "http://www.powerdns.com/"

  WriteINIStr "$SMPROGRAMS\PowerDNS\PowerDNS Documentation.url" \
              "InternetShortcut" "URL" "http://doc.powerdns.com/"

  CreateShortCut "$SMPROGRAMS\PowerDNS\PowerDNS.lnk" \
                 "$INSTDIR\pdns.exe" "" \
                 "$INSTDIR\pdns.ico"

  CreateShortCut "$SMPROGRAMS\PowerDNS\Uninstall PowerDNS.lnk" \
                 "$INSTDIR\uninst-pdns.exe"
  
SectionEnd

Section "Example zone"
  SectionIn 1

  IfFileExists $INSTDIR\powerdns.mdb Ask
    Goto OverwriteZone

Ask:
  MessageBox MB_YESNO "powerdns.mdb already exists, overwrite?" IDNO StatusEnd
    SetOverwrite on

OverwriteZone:
  File ..\..\modules\godbcbackend\powerdns.mdb

StatusEnd:
SectionEnd

# Uninstall section.
Section "Uninstall"
  MessageBox MB_YESNO "Are you sure you want to uninstall PowerDNS?" IDYES Proceed
    Quit
  
Proceed: 
  IfFileExists $INSTDIR\pdns.exe Skip
    MessageBox MB_YESNO "It does not appear that PowerDNS is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)" IDYES FSkip
      Quit

Skip:
  ExecWait '"$INSTDIR\pdns.exe" --unregister-service'
  ExecWait '"$INSTDIR\pdns_recursor.exe" --unregister-service'

FSkip:

  DeleteRegKey HKLM "System\CurrentControlSet\Services\PDNS"
  DeleteRegKey HKLM "System\CurrentControlSet\Services\Eventlog\Application\PDNS"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerDNS"
  DeleteRegKey HKLM "SOFTWARE\PowerDNS"

  RMDir /r $SMPROGRAMS\PowerDNS

  Delete $INSTDIR\LICENSE
  Delete $INSTDIR\pthreadVCE.dll
  Delete $INSTDIR\msvcrt.dll
  Delete $INSTDIR\pdnsmsg.dll
  Delete $INSTDIR\uninst-pdns.exe
  Delete $INSTDIR\pdns.ico
  Delete $INSTDIR\pdns.exe
  Delete $INSTDIR\zone2sql.exe
  Delete $INSTDIR\pdns_control.exe
  Delete $INSTDIR\pdns_recursor.exe

  RMDir $INSTDIR

SectionEnd


Function .onInstSuccess
  Sleep 500

  MessageBox MB_YESNO "Installation successful!$\r$\n$\r$\nTo use the ODBC functionality in PowerDNS you need to create a ODBC data source.$\r$\nFor more information about the ODBC backend please examine the documentation.$\r$\n$\r$\nDo you want to create a data source now?" IDNO NoODBC
    Exec '"rundll32.exe" shell32.dll,Control_RunDLL odbccp32.cpl'

NoODBC:

FunctionEnd