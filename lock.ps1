function Protect-Directory {
    param (
        [string]$path
    )
    try {
        $dirInfo = New-Object System.IO.DirectoryInfo $path
        $dirSecurity = $dirInfo.GetAccessControl()

        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null),
            [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )

        $dirSecurity.AddAccessRule($denyRule)
        $dirInfo.SetAccessControl($dirSecurity)

        Write-Output "Successfully updated permissions for: $path"
    }
    catch [System.UnauthorizedAccessException] {
        Write-Output "Access denied to directory: $path"
    }
    catch {
        Write-Output "Failed to update permissions for: $path"
    }
}

# Ensure the script runs with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Script is not running as Administrator. Please run the script with elevated privileges."
    exit
}

# Define the important directories
$importantDirectories = @(
    [Environment]::GetFolderPath("MyDocuments"),
    [Environment]::GetFolderPath("MyPictures"),
    [Environment]::GetFolderPath("MyMusic"),
    [Environment]::GetFolderPath("MyVideos"),
    [Environment]::GetFolderPath("Desktop"),
    "C:\path\to\other\important\directory" # Add other important directories as needed
)

foreach ($path in $importantDirectories) {
    Protect-Directory -path $path
}

Exit
