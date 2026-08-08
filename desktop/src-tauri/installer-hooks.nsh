; NSIS overlays an upgrade onto the existing directory: it writes the files this
; build ships and leaves everything else in place. The bundled Playwright browser
; is versioned by directory name, so an upgrade that moves to a newer revision
; leaves the previous one behind - 270MB per superseded revision, carried forever
; by anyone who upgrades rather than reinstalls.
;
; The whole browser directory is removed before the new files are written. It is
; pure build output with nothing user-owned in it, and the installer recreates it
; immediately.
!macro NSIS_HOOK_PREINSTALL
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
