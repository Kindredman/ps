function Protect-Directory {
    param (
        [string]$path
    )

    try {
        # Get the current access control settings for the directory
        $dirInfo = Get-Item -Path $path
        $dirSecurity = $dirInfo.GetAccessControl()

        # Create a new rule to deny delete and write permissions to all users
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null),
            [System.Security.AccessControl.FileSystemRights]"Delete, Write, Modify",
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )

        # Add the rule to the directory's security settings
        $dirSecurity.AddAccessRule($denyRule)

        # Apply the updated access control settings to the directory
        Set-Acl -Path $path -AclObject $dirSecurity

        Write-Output "Permissions updated successfully for $path"
    }
    catch [System.UnauthorizedAccessException] {
        Write-Error "UnauthorizedAccessException: You do not have permission to modify access control settings for this directory."
    }
    catch {
        Write-Error "Exception: $_"
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
    [Environment]::GetFolderPath("Desktop")
    # "C:\path\to\other\important\directory" # Add other important directories as needed
)

foreach ($path in $importantDirectories) {
    if (Test-Path $path) {
        Protect-Directory -path $path
    } else {
        Write-Output "Directory does not exist: $path"
    }
}

Exit
