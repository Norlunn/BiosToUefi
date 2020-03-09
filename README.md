# Invoke-BiosToUefi.ps1
Convert a disk with BIOS (MBR) installation of Windows to UEFI (GPT)

# Requirements
- Source disk
  - VMDK or VHDX
  - Windows is installed
  - WinRE is disabled, but can be enabled again after conversion
- Admin workstation
  - Windows OS (need to have diskpart, bcdboot and dism available)
  - PowerShell 5.1 or 7 (Run as Administrator)
  - Hyper-V PowerShell module installed (for New-VHD command)
  - At least 6 free drive letters
  - Enough free space to host temporary files under the conversion. Temp files will be located in the script folder.
  - qemu-img folder is required to be in script folder if using VMDK format

# Command
```Powershell
.\Invoke-BiosToUefi.ps1 -SourceDisk D:\Hyper\convert\Win2019Bios.vhdx -Verbose
```

# Note
Use this script at your own risk. Source disk will be mounted as read-only.
