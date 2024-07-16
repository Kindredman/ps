
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
    }
    catch [System.UnauthorizedAccessException] {
        # Handle access denied silently
    }
    catch {
        # Handle other exceptions silently
    }
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
