!include "MUI2.nsh"
!include ".\include\EnvVarUpdate.nsh"

Name "Hyenae 0.32-1"
OutFile "hyenae-0.32-1-win32.exe"
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

Section "Base Components (Required)"
  SectionIn RO
  SetOutPath $INSTDIR

  File ..\..\HOWTO
  File ..\..\README
  File ..\..\LICENSE
  File ..\..\src\hyenae.exe

  ${EnvVarUpdate} $0 "PATH" "A" "HKLM" "$INSTDIR"
SectionEnd

Section "WinPcap 4.0.2 (Required)"
  SectionIn RO
  SetOutPath $INSTDIR

  File ..\..\src\hyenaed.exe
  File components\WinPcap_4_0_2.exe

  ExecShell "" "$INSTDIR\WinPcap_4_0_2.exe"
SectionEnd

Section "Hyenae Daemon"
  SectionIn 2
  SetOutPath $INSTDIR

  File ..\..\src\hyenaed.exe
SectionEnd
