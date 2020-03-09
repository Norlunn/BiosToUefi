#Requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V
<#
    .SYNOPSIS
    Convert VHDX or VMDK disks from BIOS (MBR) to UEFI (GPT)

    .DESCRIPTION
    Convert VHDX or VMDK disks from BIOS (MBR) to UEFI (GPT).
    Only Windows installations are supported.
    Output format will be the same as input format.

    .PARAMETER SourceDisk
    Full path to the disk containing the BIOS installation of Windows

    .EXAMPLE
    .\Invoke-BiosToUefi.ps1 -SourceDisk D:\disks\Win2019Bios.vmdk -Verbose

    .EXAMPLE
    .\Invoke-BiosToUefi.ps1 -SourceDisk D:\disks\Win2019Bios.vhdx -Verbose

    .NOTES
    Author: Martin Norlunn
    Date: 09.03.2020
    Version: 1.0
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -Path $_ })]
    [string]$SourceDisk
)

#region settings

$script:Config = [PSCustomObject]@{
    DestinationDisk = [PSCustomObject]@{
        BootPartition = $null
        DataPartitions = @()
        Path = $null
        WindowsPartition = $null
    }
    SourceDisk = [PSCustomObject]@{
        DataPartitions = @()
        Path = $SourceDisk
        WindowsPartition = $null
    }
    TempDir = "$PSScriptRoot\Temp"
    FromToVmdk = $false
}

#endregion settings


#region functions

function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [String]$Message,
        [String]$Warning,
        [System.Management.Automation.ErrorRecord]$ErrorObj,
        [String]$LogFolderPath = "$($env:APPDATA)",
        [String]$LogFilePrefix = 'BiosToUefi'
    )

    $Date = Get-Date -Format "dd_MMMM_yyyy"
    $Time = Get-Date -Format "HH:mm:ss.f"
    $LogFile = "$LogFolderPath\$LogFilePrefix`_$Date.log"

    if (-Not (Test-Path -Path $LogFolderPath))
    {
        [Void](New-Item -ItemType Directory -Path $LogFolderPath -Force)
    }

    if (-Not (Test-Path -Path $LogFile))
    {
        [Void](New-Item -ItemType File -Path $LogFile -Force)
    }

    $LogMessage = "[$Time] "

    if ($PSBoundParameters.ContainsKey("ErrorObj"))
    {
        if ($PSBoundParameters.ContainsKey("Message"))
        {
            $LogMessage += "Error: $Message`: $ErrorObj $($ErrorObj.ScriptStackTrace.Split("`n") -join ' <-- ')"
        }
        else
        {
            $LogMessage += "Error: $ErrorObj $($ErrorObj.ScriptStackTrace.Split("`n") -join ' <-- ')"
        }

        Write-Error -Message $LogMessage
    }
    elseif ($PSBoundParameters.ContainsKey("Warning"))
    {
        $LogMessage += "Warning: $Warning"
        Write-Warning -Message $LogMessage
    }
    else
    {
        $LogMessage += "Info: $Message"
        Write-Verbose -Message $LogMessage
    }

    Add-Content -Path $LogFile -Value "$LogMessage"
}

function Get-DriveLetter
{
    [CmdletBinding()]Param
    (
        [Int]$Number = 1,
        [Switch]$Alphabetical
    )
    Try
    {
        $Letters = Get-ChildItem -Path function:[d-z]: -Name | Where-Object { -Not (Test-Path -Path $_ -ErrorAction SilentlyContinue) } | Select-Object -Last $Number
        If ($Alphabetical.IsPresent)
        {
            $Letters = $Letters | Select-Object -First $Number
        }
        Else
        {
            $Letters = $Letters | Select-Object -Last $Number
        }

        If (($Letters | Measure-Object).Count -lt $Number)
        {
            Throw "Ikke nok ledige Letters"
        }

        Write-Output -InputObject $Letters
    }
    Catch
    {
        Throw "Klarte ikke å hente ledige Letters: $_ $($_.ScriptStackTrace.Split("`n")[0])"
    }
}

function Get-PartitionLetter
{
    param
    (
        [PSObject]$Partition
    )

    try
    {
        $Counter = 0
        do
        {
            if ($Counter -gt 15)
            {
                throw "Failed to find drive letter for partition"
            }

            Start-Sleep -Seconds 2
            Get-PSDrive | Out-Null

            $Part = Get-Partition -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber
            $Counter++
        }
        until ([System.Convert]::ToString($Part.DriveLetter) -ne "")

        Write-Output ($Part.DriveLetter + ":")
    }
    catch
    {
        Write-Log -Message "Failed to find drive letter for partition"
    }
}

function Mount-Disk
{
    param
    (
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$DiskPath,
        [switch]$NoDriveLetter,
        [ValidateSet("ReadOnly", "ReadWrite")]
        [string]$Access = "ReadWrite"
    )

    try
    {
        Mount-DiskImage -ImagePath $DiskPath -NoDriveLetter:$NoDriveLetter -Access $Access | Out-Null

        $Image = Get-DiskImage -ImagePath $DiskPath

        # Ensure disk is online
        Set-Disk -Number $Image.Number -IsOffline $false | Out-Null

        # Update cache
        Update-Disk -Number $Image.Number | Out-Null
    }
    catch
    {
        Write-Log -Message "Failed to mount disk '$DiskPath'" -ErrorObj $_
    }
}

function Dismount-Disk
{
    param
    (
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$DiskPath
    )

    try
    {
        $DiskImage = Get-DiskImage -ImagePath $DiskPath

        if ($null -ne ($DiskImage | Select-Object -ExpandProperty Number))
        {
            Write-Log -Message "Dismounting disk $DiskPath"
            $Partitions = Get-Partition -DiskNumber $DiskImage.Number
            foreach ($Partition in $Partitions)
            {
                # Dismount partition
                $Drive = Get-PartitionLetter -Partition $Partition
                if (([System.Convert]::ToString($Drive) -ne ""))
                {
                    Write-Log -Message "Dismounting disk number $($Partition.DiskNumber), partition number $($Partition.PartitionNumber) on mount $Drive\"
                    Remove-PartitionAccessPath -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -AccessPath $Drive -ErrorAction SilentlyContinue
                }
                else
                {
                    Write-Log -Warning "Could not find drive letter to dismount disk number $($Partition.DiskNumber), partition number $($Partition.PartitionNumber)"
                }
            }

            Dismount-DiskImage -ImagePath $DiskPath | Out-Null
        }
        else
        {
            Write-Log -Message "Disk not mounted. Skipping dismounting disk $DiskPath"
        }
    }
    catch
    {
        Write-Log -ErrorObj $_
    }
}

function Find-Partitions
{
    param
    (
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$DiskPath
    )

    $DiskImage = Get-DiskImage -ImagePath $DiskPath

    # Get Windows OS partititon
    $Partitions = Get-Partition -DiskNumber $DiskImage.Number | Where-Object { $_.MbrType -eq 7 -and $_.IsActive -eq $false }
    foreach ($Partition in $Partitions)
    {
        # Mount partition
        Add-PartitionAccessPath -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -AssignDriveLetter

        $Drive = Get-PartitionLetter -Partition $Partition

        # Check if Windows or Data partition
        if (Test-Path -LiteralPath "$Drive\windows\system32\ntdll.dll")
        {
            $script:Config.SourceDisk.WindowsPartition = $Partition
        }
        else
        {
            $script:Config.SourceDisk.DataPartitions += $Partition
        }

        Remove-PartitionAccessPath -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -AccessPath $Drive
    }
}

function Get-WinRE
{
    try
    {
        $MountPath = $script:Config.SourceDisk.WindowsPartition.DriveLetter + ":"
        $IsPBRConfigured = $false
        if (Test-Path -Path "$MountPath\windows\system32\recovery\reagent.xml")
        {
            [System.Xml.XmlDocument]$XMLDoc = New-Object -TypeName System.Xml.XmlDocument
            $XMLDoc.Load("$MountPath\windows\system32\recovery\reagent.xml")
            $XMLNoder = $XMLDoc.SelectNodes("/WindowsRE/InstallState")

            if ($XMLNoder.Count -gt 0)
            {
                if ($XMLNoder.State -eq 1)
                {
                    Write-Log -Message "WinRE is configured"
                    throw "WinRE is configured. Deactive this in the guest OS with the command 'reagentc /disable' first"
                }
                else
                {
                    Write-Log -Message "WinRE is not configured"
                }
            }
            else
            {
                throw "Not able to determine state of WinRE"
            }

            $WinREVersjon = $XMLDoc.SelectNodes("/WindowsRE").version

            if ($WinREVersjon -eq "1.0")
            {
                $XMLNoder = $XMLDoc.SelectNodes("/WindowsRE/OSInstallLocation")
            }
            else
            {
                $XMLNoder = $XMLDoc.SelectNodes("/WindowsRE/PBRImageLocation")
            }

            if ($XMLNoder.Count -ne 0)
            {
                if ($XMLNoder.Path -ne "")
                {
                    $IsPBRConfigured = $true
                    Write-Log -Message "PBR is configured"
                }
                else
                {
                    Write-Log -Message "PBR is not configured"
                }
            }
        }
        else
        {
            Write-Log -Message "WinRE is not configured"
        }
    }
    catch
    {
        Write-Log -ErrorObj $_
    }

    if ($IsPBRConfigured)
    {
        Throw "WinRE PBR is configured"
    }
}

function Capture-Image
{
    param
    (
        [string]$MountPath,
        [string]$WimPath,
        [string]$Name
    )

    try
    {
        Write-Log -Message "Capturing partition $MountPath to WIM file: $WimPath"

        dism.exe /Capture-Image /ImageFile:`"$WimPath`" /CaptureDir:$MountPath /Name:`"$Name`" /Compress:Fast /CheckIntegrity
        if (-not $?)
        {
            Throw "Failed to capture image with Dism"
        }

        Write-Log -Message "Finished capturing $WimPath"
    }
    catch
    {
        Write-Log -ErrorObj $_
    }
}

function New-WinImage
{
    try
    {
        $MountPath = Get-PartitionLetter -Partition $script:Config.SourceDisk.WindowsPartition
        $WindowsWimPath = "$($script:Config.TempDir)\WindowsPartition.wim"

        Capture-Image -MountPath $MountPath -WimPath $WindowsWimPath -Name 'Windows'
    }
    catch
    {
        Write-Log -ErrorObj $_
    }
}

function New-DataImage
{
    param
    (
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$MountPath
    )

    try
    {
        $ImageId = (Get-ChildItem -Path $script:Config.TempDir -Filter "DataPartititon-*.wim" | Measure-Object).Count + 1
        $DataWimPath = "$($script:Config.TempDir)\DataPartition-$ImageId.wim"

        Capture-Image -MountPath $MountPath -WimPath $DataWimPath -Name 'Data'
    }
    catch
    {
        Write-Log -ErrorObj $_
    }
}

function New-Disk
{
    try
    {
        If ($null -eq $script:Config.SourceDisk.WindowsPartition)
        {
            $WindowsSize = 0
        }
        else
        {
            $WindowsSize = [Math]::Ceiling($script:Config.SourceDisk.WindowsPartition.Size / 1MB) * 1MB
        }

        if (($script:Config.SourceDisk.DataPartitions | Measure-Object).Count -gt 0)
        {
            $DataSize = [Math]::Ceiling(($script:Config.SourceDisk.DataPartitions | Select-Object -ExpandProperty Size | Measure-Object -Sum).Sum / 1MB) * 1MB
        }

        Write-Log -Message "Windows size: $WindowsSize"
        Write-Log -Message "Data size: $DataSize"

        $TargetSize = 450MB # Partition 1: Hidden recovery tools
        $TargetSize += 100MB # Partition 2: ESP
        $TargetSize += 128MB # Partition 3: MSR
        $TargetSize += $WindowsSize # Partition 4: Primary partition with Windows
        $TargetSize += $DataSize # Partition 5+: Data partitions
        $TargetSize += 3MB # GPT-tables

        Write-Log -Message "Size of new disk = $([Math]::Round(($TargetSize / 1GB), 2)) GB"

        $script:Config.DestinationDisk.Path = $script:Config.TempDir + '\' + (Split-Path -Path ($script:Config.SourceDisk.Path -replace ".vhdx", " (UEFI).vhdx") -Leaf)

        Write-Log -Message "Creating new disk at $($script:Config.DestinationDisk.Path)"
        New-VHD -Path $script:Config.DestinationDisk.Path -Dynamic -SizeBytes $TargetSize | Out-Null
    }
    catch
    {
        Write-Log -ErrorObj $_
    }
}

function Add-DiskPartition
{
    try
    {
        $DiskImage = Get-DiskImage -ImagePath $script:Config.DestinationDisk.Path -ErrorAction SilentlyContinue
        if (-not $?)
        {
            throw "Failed getting the disk image"
        }

        $DiskNumber = $DiskImage | Get-Disk -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Number
        if (-not $?)
        {
            throw "Failed getting disk"
        }

        $DiskPartConfig = $script:Config.TempDir + "\Diskpart.txt"
        New-Item -Path $DiskPartConfig -ItemType File -Force | Out-Null

        # Clean disk and set GPT layout
        Add-Content -Path $DiskPartConfig -Value "select disk $DiskNumber"
        Add-Content -Path $DiskPartConfig -Value "clean"
        Add-Content -Path $DiskPartConfig -Value "convert gpt"

        # Create recovery partition
        Add-Content -Path $DiskPartConfig -Value "create partition efi size=450"
        Add-Content -Path $DiskPartConfig -Value "format quick fs=ntfs label=`"Windows RE tools`""
        Add-Content -Path $DiskPartConfig -Value "set id=`"de94bba4-06d1-4d40-a16a-bfd50179d6ac`""
        Add-Content -Path $DiskPartConfig -Value "gpt attributes=0x8000000000000001"

        # Create EFI system partition
        Add-Content -Path $DiskPartConfig -Value "create partition efi size=100"
        Add-Content -Path $DiskPartConfig -Value "format quick fs=fat32 label=""System"""

        # Create Windows partition
        Add-Content -Path $DiskPartConfig -Value ("create partition primary size=" + [Math]::Ceiling($script:Config.SourceDisk.WindowsPartition.Size / 1MB))
        Add-Content -Path $DiskPartConfig -Value "format quick fs=ntfs label=`"Windows`""

        # Create data partitions
        $Counter = 0
        foreach ($Partition in $script:Config.SourceDisk.DataPartitions)
        {
            $Counter++
            Add-Content -Path $DiskPartConfig -Value ("create partition primary size=" + [Math]::Ceiling($Partition.Size / 1MB))
            Add-Content -Path $DiskPartConfig -Value "format quick fs=ntfs label=`"Data $Counter`""
        }

        Add-Content -Path $DiskPartConfig -Value "exit"

        $Formated = $false
        $Attempts = 10
        $Counter = 0
        do
        {
            Write-Log -Message "Running  Diskpart with config file $DiskPartConfig"
            $Result = diskpart /s $DiskPartConfig
            if ($?)
            {
                $Formated = $true
            }
            else
            {
                $Counter++
                Start-Sleep -Seconds 1
            }
        }
        until ($Formated -or $Counter -gt $Attempts)

        if (-not $Formated)
        {
            throw "Diskpart failed: $Result"
        }
    }
    catch
    {
        Write-Log -Message "Failed in partitioning the disk" -ErrorObj $_
    }
}

function Mount-DiskPartition
{
    try
    {
        $DiskImage = Get-DiskImage -ImagePath $script:Config.DestinationDisk.Path -ErrorAction SilentlyContinue
        if (-not $?)
        {
            throw "Failed getting the disk image"
        }

        $DiskNumber = $DiskImage | Get-Disk -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Number
        if (-not $?)
        {
            throw "Failed getting disk"
        }

        $script:Config.DestinationDisk.BootPartition = Get-Partition -DiskNumber $DiskNumber -PartitionNumber 3
        $script:Config.DestinationDisk.WindowsPartition = Get-Partition -DiskNumber $DiskNumber -PartitionNumber 4

        $Params = @{
            DiskNumber = $script:Config.DestinationDisk.BootPartition.DiskNumber
            PartitionNumber = $script:Config.DestinationDisk.BootPartition.PartitionNumber
            AssignDriveLetter = $true
        }
        Add-PartitionAccessPath @Params

        $Params = @{
            DiskNumber = $script:Config.DestinationDisk.WindowsPartition.DiskNumber
            PartitionNumber = $script:Config.DestinationDisk.WindowsPartition.PartitionNumber
            AssignDriveLetter = $true
        }
        Add-PartitionAccessPath @Params

        $null = Get-PartitionLetter -Partition $script:Config.DestinationDisk.BootPartition
        $null = Get-PartitionLetter -Partition $script:Config.DestinationDisk.WindowsPartition

        $NumberOfPartitions = (Get-Partition -DiskNumber $DiskNumber | Measure-Object).Count
        if ($NumberOfPartitions -gt 4)
        {
            for ($PartitionNumber = 5; $PartitionNumber -le $NumberOfPartitions; $PartitionNumber++)
            {
                Add-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -AssignDriveLetter
                $script:Config.DestinationDisk.DataPartitions += Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
            }
        }
    }
    catch
    {
        Write-Log -Message "Failed in partitioning the disk" -ErrorObj $_
    }
}

function Apply-WindowsImage
{
    try
    {
        $WinDrive = Get-PartitionLetter -Partition $script:Config.DestinationDisk.WindowsPartition
        if ($null -eq $WinDrive)
        {
            throw "Failed to find mounted Windows partition"
        }

        Write-Log -Message "Applying windows image"
        $WinImage = "$($script:Config.TempDir)\WindowsPartition.wim"
        dism.exe /Apply-Image /ImageFile:$WinImage /Index:1 /ApplyDir:$WinDrive
        if (-not $?)
        {
            throw "Failed applying Windows image $WinImage to partition $($script:Config.DestinationDisk.WindowsPartition.PartitionNumber) on disk $($script:Config.DestinationDisk.WindowsPartition.DiskNumber)"
        }

        $EfiDrive = Get-PartitionLetter -Partition $script:Config.DestinationDisk.BootPartition
        if ($null -eq $EfiDrive)
        {
            throw "Failed to find mounted EFI system partition"
        }

        Write-Log -Message "Configuring EFI system partition"
        bcdboot.exe "$Drive\windows" /s $EfiDrive /f UEFI
    }
    catch
    {
        Write-Log -Message "Failed applying Windows image" -ErrorObj $_
    }
}

function Apply-DataImage
{
    try
    {
        $Counter = 1
        foreach ($DataPart in $script:Config.DestinationDisk.DataPartitions)
        {
            $DataDrive = Get-PartitionLetter -Partition $DataPart
            $DataImage = "$($script:Config.TempDir)\DataPartition-$Counter.wim"
            dism.exe /Apply-Image /ImageFile:$DataImage /Index:1 /ApplyDir:$DataDrive
            if (-not $?)
            {
                throw "Failed applying data image $DataImage to partition $($DataPart.PartitionNumber) on disk $($DataPart.DiskNumber)"
            }
        }
    }
    catch
    {
        Write-Log -Message "Failed applying data image" -ErrorObj $_
    }
}

function ConvertTo-Vmdk
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$DiskPath
    )

    try
    {
        & "$PSScriptRoot\qemu-img\qemu-img.exe" convert $DiskPath -O vmdk ($DiskPath -replace "vhdx", "vmdk") -p
    }
    Catch
    {
        Write-Log -Message "Failed converting VHDX to VMDK" -ErrorObj $_
    }
}

function ConvertTo-Vhdx
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$DiskPath
    )

    try
    {
        & "$PSScriptRoot\qemu-img\qemu-img.exe" convert $DiskPath -O vhdx ($DiskPath -replace "vmdk", "vhdx") -p
    }
    Catch
    {
        Write-Log -Message "Failed converting VMDK to VHDX" -ErrorObj $_
    }
}

#endregion functions


#region logic

try
{
    if ((Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled))
    {
        Write-Log -Warning "Windows Defender is enabled and may severly impact performance of the script. It's recommended to temporarily disable real-time protection."
        Read-Host -Prompt "Press Enter to continue" | Out-Null
    }

    if (-not (Test-Path -Path $script:Config.TempDir))
    {
        New-Item -ItemType Directory -Path $script:Config.TempDir | Out-Null
    }

    if (-not (Test-Path -Path "$env:windir\System32\dism.exe"))
    {
        throw "Failed to find dism.exe in System32"
    }

    if (-not (Test-Path -Path "$env:windir\System32\diskpart.exe"))
    {
        throw "Failed to find diskpart.exe in System32"
    }

    if (-not (Test-Path -Path "$env:windir\System32\bcdboot.exe"))
    {
        throw "Failed to find bcdboot.exe in System32"
    }

    if ($script:Config.SourceDisk.Path -like "*.vmdk")
    {
        Write-Log -Message "Input format VMDK detected. Converting temporarily to VMDX.."
        $script:Config.FromToVmdk = $true
        ConvertTo-Vhdx -DiskPath $script:Config.SourceDisk.Path
        $script:Config.SourceDisk.Path = $script:Config.SourceDisk.Path -replace "vmdk", "vhdx"

        if (-not (Test-Path -Path "$PSScriptRoot\qemu-img\qemu-img.exe"))
        {
            throw "Failed to find $PSScriptRoot\qemu-img\qemu-img.exe. Qemy-img is necessary to convert from and to Vmdk format"
        }
    }

    Write-Log -Message "Mount source disk"
    Mount-Disk -DiskPath $script:Config.SourceDisk.Path -NoDriveLetter -Access ReadOnly

    # Find what partition have Windows installed, and which are pure data partitions (not boot)
    Find-Partitions -DiskPath $script:Config.SourceDisk.Path

    Write-Log -Message "Mount Windows partition"
    $Params = @{
        DiskNumber = $script:Config.SourceDisk.WindowsPartition.DiskNumber
        PartitionNumber = $script:Config.SourceDisk.WindowsPartition.PartitionNumber
        AssignDriveLetter = $true
    }
    Add-PartitionAccessPath @Params

    # Need to wait until a drive letter is assigned
    $null = Get-PartitionLetter -Partition $script:Config.DestinationDisk.WindowsPartition

    $Params.Remove('AssignDriveLetter')
    $script:Config.DestinationDisk.WindowsPartition += Get-Partition @Params

    Write-Log -Message "Check Windows Recovery Environment (WinRE)"
    Get-WinRE

    Write-Log -Message "Capture Windows partition to WIM file"
    New-WinImage

    Write-Log -Message "Capture data partitions to WIM files"
    foreach ($DataPart in $script:Config.SourceDisk.DataPartitions)
    {
        Add-PartitionAccessPath -DiskNumber $DataPart.DiskNumber -PartitionNumber $DataPart.PartitionNumber -AssignDriveLetter
        $Drive = Get-PartitionLetter -Partition $DataPart
        New-DataImage -MountPath $Drive
        Remove-PartitionAccessPath -DiskNumber $DataPart.DiskNumber -PartitionNumber $DataPart.PartitionNumber -AccessPath $Drive
    }

    Write-Log -Message "Creating a new disk"
    New-Disk

    Write-Log -Message "Mount new vhdx disk"
    Mount-Disk -DiskPath $script:Config.DestinationDisk.Path

    Write-Log -Message "Partition the new disk"
    Add-DiskPartition

    Write-Log -Message "Dismount source disk image"
    Dismount-DiskImage -ImagePath $script:Config.SourceDisk.Path

    Write-Log -Message "Mount boot and windows partitions of new disk"
    Mount-DiskPartition

    Write-Log -Message "Apply Windows image and configure EFI system partition"
    Apply-WindowsImage

    Write-Log -Message "Apply data partition images"
    Apply-DataImage

    Write-Log -Message "Dismounting disks"
    Dismount-Disk -DiskPath $script:Config.SourceDisk.Path
    Dismount-Disk -DiskPath $script:Config.DestinationDisk.Path

    if ($script:Config.FromToVmdk)
    {
        Write-Log -Message "Converting final VHDX back to VMDK format"
        ConvertTo-Vmdk -DiskPath $script:Config.DestinationDisk.Path
        if (-not $?)
        {
            Throw "Unable to convert final VHDX to VMDK"
        }
        $script:Config.DestinationDisk.Path = $script:Config.DestinationDisk.Path -replace "vhdx", "vmdk"
    }

    Write-Log -Message "Conversion is finished. Remember to enable Windows Recovery Environment in the guest OS again. Run 'reagentc /enable' and verify with 'reagentc /info'"
}
catch
{
    Write-Log -ErrorObj $_
}
finally
{
    Write-Log -Message "Finishing up script. Doing cleanup.."
    Dismount-Disk -DiskPath $script:Config.SourceDisk.Path
    Dismount-Disk -DiskPath $script:Config.DestinationDisk.Path
    Move-Item -Path $script:Config.DestinationDisk.Path -Destination (Split-Path -Path $script:Config.SourceDisk.Path -Parent)
    Remove-Item -Path $script:Config.TempDir -Recurse -Force
    Write-Log -Message "Saved UEFI disk to $((Split-Path -Path $script:Config.SourceDisk.Path -Parent))"
}

#endregion logic