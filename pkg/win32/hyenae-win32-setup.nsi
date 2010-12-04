!include "MUI2.nsh"
!include ".\include\EnvVarUpdate.nsh"

Name "Hyenae 0.36-1"
OutFile "hyenae-0.36-1_fe_0.1-1-win32.exe"
InstallDir $PROGRAMFILES\Hyenae

; Required for Windows Vista
RequestExecutionLevel admin

!define MUI_ABORTWARNING

!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP ".\components\hyenae.bmp" ; optional

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE ".\components\License.rtf"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "WinPcap"
  SectionIn RO
  SetOutPath $INSTDIR

  File components\WinPcap_4_1_2.exe

  ExecShell "" "$INSTDIR\WinPcap_4_1_2.exe"
SectionEnd

Section "Hyenae"
  SectionIn RO

  SetOutPath $INSTDIR
  File ..\..\LICENSE
  File ..\..\README
  File ..\..\HOWTO
  File ..\..\ChangeLog
  File ..\..\src\hyenae.exe

  ${EnvVarUpdate} $0 "PATH" "A" "HKLM" "$INSTDIR"
SectionEnd

Section "Hyenae Daemon"
  SectionIn 2

  SetOutPath $INSTDIR
  File ..\..\src\hyenaed.exe
SectionEnd

Section "HyenaeFE"
  SectionIn 2

  SetOutPath $SYSDIR
  File components\libgcc_s_dw2-1.dll
  File components\libstdc++-6.dll
  File components\mingwm10.dll
  File components\QtCore4.dll
  File components\QtGui4.dll

  SetOutPath $INSTDIR
  File components\hyenaefe.exe

  createShortCut "$SMPROGRAMS\HyenaeFE.lnk" "$INSTDIR\HyenaeFE.exe"
SectionEnd
