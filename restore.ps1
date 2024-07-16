function Restore-DirectoryPermissions {
    param (
        [string]$path
    )

    try {
        # Get the current access control settings for the directory
        $dirInfo = Get-Item -Path $path
        $dirSecurity = $dirInfo.GetAccessControl()

        # Create a new rule to match the deny rule we want to remove
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null),
            [System.Security.AccessControl.FileSystemRights]"Delete, Write, Modify",
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )

        # Remove the rule from the directory's security settings
        $dirSecurity.RemoveAccessRule($denyRule)

        # Apply the updated access control settings to the directory
        Set-Acl -Path $path -AclObject $dirSecurity

        Write-Output "Permissions restored successfully for $path"
    }
    catch [System.UnauthorizedAccessException] {
        Write-Error "UnauthorizedAccessException: You do not have permission to modify access control settings for this directory."
    }
    catch {
        Write-Error "Exception: $_"
    }
}

# Define the important directories
$importantDirectories = @(
    [Environment]::GetFolderPath("MyDocuments"),
    [Environment]::GetFolderPath("MyPictures"),
    [Environment]::GetFolderPath("MyMusic"),
    [Environment]::GetFolderPath("MyVideos"),
    [Environment]::GetFolderPath("Desktop"),
    # "C:\path\to\other\important\directory" # Add other important directories as needed
)

foreach ($path in $importantDirectories) {
    Restore-DirectoryPermissions -path $path
    # Uncomment the next line if you need to use the Protect-Directory function
    # Protect-Directory -path $path
}

Exit
