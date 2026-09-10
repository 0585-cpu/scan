; NSIS overlays an upgrade onto the existing directory: it writes the files this
; build ships and leaves everything else in place. The bundled Playwright browser
; is versioned by directory name, so an upgrade that moves to a newer revision
; leaves the previous one behind - 270MB per superseded revision, carried forever
; by anyone who upgrades rather than reinstalls.
;
; A private SYN-enabled build stages the official Npcap installer beside this
; file. It is deliberately launched with its normal UI: the free installer has
; no redistributable silent-install contract, and the operator must leave
; "Restrict Npcap driver's access to Administrators only" unchecked.
!define NETROACH_NPCAP_INSTALLER "${__FILEDIR__}\resources\installers\npcap-installer.exe"

!macro NETROACH_CHECK_NPCAP_READY _RESULT
  StrCpy ${_RESULT} 0
  StrCpy $R5 0
  ClearErrors
  ReadRegDWORD $R0 HKLM "SYSTEM\CurrentControlSet\Services\npcap" "DriverMajorVersion"
  ${If} ${Errors}
    StrCpy $R5 1
  ${EndIf}
  ClearErrors
  ReadRegDWORD $R1 HKLM "SYSTEM\CurrentControlSet\Services\npcap" "DriverMinorVersion"
  ${If} ${Errors}
    StrCpy $R5 1
  ${EndIf}
  ClearErrors
  ReadRegDWORD $R2 HKLM "SYSTEM\CurrentControlSet\Services\npcap\Parameters" "AdminOnly"
  ${If} ${Errors}
    StrCpy $R5 1
  ${EndIf}
  ${If} $R5 = 0
    ${If} $R0 > 1
      ${If} $R2 = 0
        StrCpy ${_RESULT} 1
      ${EndIf}
    ${ElseIf} $R0 = 1
      ${If} $R1 >= 88
        ${If} $R2 = 0
          StrCpy ${_RESULT} 1
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend
;
; The whole browser directory is removed before the new files are written. It is
; pure build output with nothing user-owned in it, and the installer recreates it
; immediately.
!macro NSIS_HOOK_PREINSTALL
!if /FileExists "${NETROACH_NPCAP_INSTALLER}"
  !insertmacro NETROACH_CHECK_NPCAP_READY $R3

  ${If} $R3 != 1
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File /oname=npcap-installer.exe "${NETROACH_NPCAP_INSTALLER}"
    MessageBox MB_OK|MB_ICONINFORMATION "Netroach SYN 스캔에는 Npcap 1.88 이상이 필요합니다.$\r$\n$\r$\n다음 설치 화면에서 'Restrict Npcap driver's access to Administrators only' 옵션을 선택하지 마세요."
    ClearErrors
    ExecShellWait "runas" "$PLUGINSDIR\npcap-installer.exe"
    SetOutPath "$INSTDIR"
    ${If} ${Errors}
      MessageBox MB_OK|MB_ICONSTOP "Npcap 설치 프로그램을 시작하지 못했습니다. Netroach 설치를 중단합니다."
      Abort
    ${EndIf}
    !insertmacro NETROACH_CHECK_NPCAP_READY $R3
    ${If} $R3 != 1
      MessageBox MB_OK|MB_ICONSTOP "Npcap 1.88 이상과 일반 사용자 접근(AdminOnly=0)이 확인되지 않았습니다. 설정을 확인한 뒤 Netroach 설치를 다시 실행하세요."
      Abort
    ${EndIf}
  ${EndIf}
!endif

  DetailPrint "Removing bundled browser revisions from the previous install"
  RMDir /r "$INSTDIR\resources\playwright"
!macroend

!macro NSIS_HOOK_POSTINSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing bundled browsers"
  RMDir /r "$INSTDIR\resources\playwright"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
