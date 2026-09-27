; NSIS installer hooks (tauri.conf.json bundle.windows.nsis.installerHooks).
;
; SecureText supports Windows 10 version 21H2 (build 19044) and newer,
; including Windows 11 (docs/platform-support.md). Older builds are refused
; before anything is installed.
!macro NSIS_HOOK_PREINSTALL
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  ${If} $0 == ""
  ${OrIf} $0 < 19044
    MessageBox MB_OK|MB_ICONSTOP "SecureText needs Windows 10 version 21H2 or newer, or Windows 11. This PC is running Windows build $0." /SD IDOK
    Abort "SecureText needs Windows 10 version 21H2 or newer."
  ${EndIf}
!macroend
