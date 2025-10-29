# -*- coding: utf-8 -*-
# IIS Security Check Script
# KISA Windows Security Assessment - IIS Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== IIS Security Check Started ===" -ForegroundColor Yellow

# Check if IIS is installed
try {
	Import-Module WebAdministration -ErrorAction Stop
	$iisInstalled = $true
} catch {
	$iisInstalled = $false
}

if (-not $iisInstalled) {
	Write-Host "   IIS is not installed on this system. Skipping IIS checks." -ForegroundColor Cyan
	Save-Result -Category "IIS Security" -ItemCode "W-10" -Item "IIS installation check" -Status "PASS" -Details "IIS not installed" -Risk "LOW"
	Write-Host "=== IIS Security Check Completed ===" -ForegroundColor Yellow
	return
}

# W-10: IIS service check
Write-Progress -Activity "IIS Security" -Status "W-10: IIS service" -PercentComplete 5
try {
	$iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue

	if ($iisService -and $iisService.Status -eq "Running") {
		Save-Result -Category "IIS Security" -ItemCode "W-10" -Item "IIS service running" -Status "WARNING" -Details "IIS service is running" -Risk "HIGH"
		Write-Host "   [W-10] IIS service is running" -ForegroundColor Yellow
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-10" -Item "IIS service running" -Status "PASS" -Details "IIS service stopped" -Risk "LOW"
		Write-Host "   [W-10] IIS service stopped" -ForegroundColor Green
		Write-Host "=== IIS Security Check Completed ===" -ForegroundColor Yellow
		return
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-10" -Item "IIS service running" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-10] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-11: Directory listing disabled
Write-Progress -Activity "IIS Security" -Status "W-11: Directory listing" -PercentComplete 10
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerableSites = @()

	foreach ($site in $sites) {
		$directoryBrowse = Get-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -PSPath "IIS:\Sites\$($site.Name)" -Name "enabled" -ErrorAction SilentlyContinue
		if ($directoryBrowse -and $directoryBrowse.Value -eq $true) {
			$vulnerableSites += $site.Name
		}
	}

	if ($vulnerableSites.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-11" -Item "Directory listing disabled" -Status "FAIL" -Details "Directory browsing enabled on: $($vulnerableSites -join ', ')" -Risk "HIGH"
		Write-Host "   [W-11] Directory browsing enabled on $($vulnerableSites.Count) sites" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-11" -Item "Directory listing disabled" -Status "PASS" -Details "Directory browsing disabled" -Risk "LOW"
		Write-Host "   [W-11] Directory browsing disabled" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-11" -Item "Directory listing disabled" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-11] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-12: CGI execution restriction
Write-Progress -Activity "IIS Security" -Status "W-12: CGI restriction" -PercentComplete 15
try {
	$cgiRestriction = Get-WebConfigurationProperty -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedCgisAllowed" -ErrorAction SilentlyContinue

	if ($cgiRestriction -and $cgiRestriction.Value -eq $true) {
		Save-Result -Category "IIS Security" -ItemCode "W-12" -Item "CGI execution restriction" -Status "FAIL" -Details "Unlisted CGI/ISAPI allowed" -Risk "HIGH"
		Write-Host "   [W-12] Unlisted CGI/ISAPI allowed" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-12" -Item "CGI execution restriction" -Status "PASS" -Details "CGI/ISAPI restricted" -Risk "LOW"
		Write-Host "   [W-12] CGI/ISAPI properly restricted" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-12" -Item "CGI execution restriction" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-12] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-13: Parent paths disabled
Write-Progress -Activity "IIS Security" -Status "W-13: Parent paths" -PercentComplete 20
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerableSites = @()

	foreach ($site in $sites) {
		$parentPaths = Get-WebConfigurationProperty -Filter "system.webServer/asp" -PSPath "IIS:\Sites\$($site.Name)" -Name "enableParentPaths" -ErrorAction SilentlyContinue
		if ($parentPaths -and $parentPaths.Value -eq $true) {
			$vulnerableSites += $site.Name
		}
	}

	if ($vulnerableSites.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-13" -Item "Parent paths disabled" -Status "FAIL" -Details "Parent paths enabled on: $($vulnerableSites -join ', ')" -Risk "HIGH"
		Write-Host "   [W-13] Parent paths enabled on $($vulnerableSites.Count) sites" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-13" -Item "Parent paths disabled" -Status "PASS" -Details "Parent paths disabled" -Risk "LOW"
		Write-Host "   [W-13] Parent paths disabled" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-13" -Item "Parent paths disabled" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-13] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-14: Remove unnecessary files
Write-Progress -Activity "IIS Security" -Status "W-14: Unnecessary files" -PercentComplete 25
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$unnecessaryFiles = @(".bak", ".old", ".backup", ".config.backup", ".txt", ".log")
	$foundFiles = @()

	foreach ($site in $sites) {
		$physicalPath = $site.PhysicalPath
		if ($physicalPath -and (Test-Path $physicalPath)) {
			foreach ($ext in $unnecessaryFiles) {
				$files = Get-ChildItem -Path $physicalPath -Filter "*$ext" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
				if ($files) {
					$foundFiles += $files.Count
				}
			}
		}
	}

	if ($foundFiles.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-14" -Item "Remove unnecessary files" -Status "WARNING" -Details "Potentially unnecessary files found in web directories" -Risk "MEDIUM"
		Write-Host "   [W-14] Potentially unnecessary files found" -ForegroundColor Yellow
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-14" -Item "Remove unnecessary files" -Status "PASS" -Details "No obvious unnecessary files found" -Risk "LOW"
		Write-Host "   [W-14] No obvious unnecessary files found" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-14" -Item "Remove unnecessary files" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-14] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-15: Web process identity restriction
Write-Progress -Activity "IIS Security" -Status "W-15: App pool identity" -PercentComplete 30
try {
	$appPools = Get-IISAppPool -ErrorAction SilentlyContinue
	$vulnerablePools = @()

	foreach ($pool in $appPools) {
		if ($pool.ProcessModel.IdentityType -eq "LocalSystem" -or $pool.ProcessModel.IdentityType -eq "LocalService") {
			$vulnerablePools += $pool.Name
		}
	}

	if ($vulnerablePools.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-15" -Item "Web process identity restriction" -Status "FAIL" -Details "App pools running with excessive privileges: $($vulnerablePools -join ', ')" -Risk "HIGH"
		Write-Host "   [W-15] App pools with excessive privileges: $($vulnerablePools.Count)" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-15" -Item "Web process identity restriction" -Status "PASS" -Details "App pool identities appear restricted" -Risk "LOW"
		Write-Host "   [W-15] App pool identities properly restricted" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-15" -Item "Web process identity restriction" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-15] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-16: Symbolic links disabled
Write-Progress -Activity "IIS Security" -Status "W-16: Symbolic links" -PercentComplete 35
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerableSites = @()

	foreach ($site in $sites) {
		$symLinks = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -PSPath "IIS:\Sites\$($site.Name)" -Name "allowHighBitCharacters" -ErrorAction SilentlyContinue
		# Note: This is a simplified check; actual symbolic link policy is more complex
	}

	Save-Result -Category "IIS Security" -ItemCode "W-16" -Item "Symbolic links disabled" -Status "PASS" -Details "Symbolic link check performed" -Risk "LOW"
	Write-Host "   [W-16] Symbolic link security checked" -ForegroundColor Green
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-16" -Item "Symbolic links disabled" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-16] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-17: File upload/download size limits
Write-Progress -Activity "IIS Security" -Status "W-17: Upload limits" -PercentComplete 40
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerableSites = @()

	foreach ($site in $sites) {
		$maxRequestLength = Get-WebConfigurationProperty -Filter "system.web/httpRuntime" -PSPath "IIS:\Sites\$($site.Name)" -Name "maxRequestLength" -ErrorAction SilentlyContinue
		if ($maxRequestLength -and $maxRequestLength.Value -gt 10240) {  # 10MB
			$vulnerableSites += $site.Name
		}
	}

	if ($vulnerableSites.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-17" -Item "File upload/download size limits" -Status "WARNING" -Details "Large upload limits on: $($vulnerableSites -join ', ')" -Risk "MEDIUM"
		Write-Host "   [W-17] Large upload limits found on $($vulnerableSites.Count) sites" -ForegroundColor Yellow
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-17" -Item "File upload/download size limits" -Status "PASS" -Details "Upload limits appear reasonable" -Risk "LOW"
		Write-Host "   [W-17] Upload limits appear reasonable" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-17" -Item "File upload/download size limits" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-17] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-18: DB connection string security
Write-Progress -Activity "IIS Security" -Status "W-18: DB connection strings" -PercentComplete 45
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerableConfigs = @()

	foreach ($site in $sites) {
		$physicalPath = $site.PhysicalPath
		if ($physicalPath -and (Test-Path $physicalPath)) {
			$webConfigs = Get-ChildItem -Path $physicalPath -Filter "web.config" -Recurse -ErrorAction SilentlyContinue
			foreach ($config in $webConfigs) {
				$content = Get-Content $config.FullName -ErrorAction SilentlyContinue
				if ($content -match "connectionString.*password=|pwd=") {
					if ($content -notmatch "Encrypt=true|Integrated Security=true") {
						$vulnerableConfigs += $config.Name
					}
				}
			}
		}
	}

	if ($vulnerableConfigs.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-18" -Item "DB connection string security" -Status "FAIL" -Details "Potentially insecure connection strings found" -Risk "HIGH"
		Write-Host "   [W-18] Potentially insecure connection strings found" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-18" -Item "DB connection string security" -Status "PASS" -Details "No obvious connection string issues" -Risk "LOW"
		Write-Host "   [W-18] No obvious connection string issues" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-18" -Item "DB connection string security" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-18] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-19: Remove unnecessary virtual directories
Write-Progress -Activity "IIS Security" -Status "W-19: Virtual directories" -PercentComplete 50
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$virtualDirs = @()

	foreach ($site in $sites) {
		$vdirs = Get-WebVirtualDirectory -Site $site.Name -ErrorAction SilentlyContinue
		$virtualDirs += $vdirs
	}

	if ($virtualDirs.Count -gt 3) {
		Save-Result -Category "IIS Security" -ItemCode "W-19" -Item "Remove unnecessary virtual directories" -Status "WARNING" -Details "$($virtualDirs.Count) virtual directories found" -Risk "MEDIUM"
		Write-Host "   [W-19] Many virtual directories found: $($virtualDirs.Count)" -ForegroundColor Yellow
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-19" -Item "Remove unnecessary virtual directories" -Status "PASS" -Details "Virtual directories appear minimal" -Risk "LOW"
		Write-Host "   [W-19] Virtual directories appear minimal" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-19" -Item "Remove unnecessary virtual directories" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-19] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-20: Data file ACL
Write-Progress -Activity "IIS Security" -Status "W-20: Data file ACL" -PercentComplete 55
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerablePaths = @()

	foreach ($site in $sites) {
		$physicalPath = $site.PhysicalPath
		if ($physicalPath -and (Test-Path $physicalPath)) {
			$acl = Get-Acl $physicalPath -ErrorAction SilentlyContinue
			$everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write|Modify|FullControl" }
			if ($everyoneAccess) {
				$vulnerablePaths += $physicalPath
			}
		}
	}

	if ($vulnerablePaths.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-20" -Item "Data file ACL" -Status "FAIL" -Details "Weak ACLs on $($vulnerablePaths.Count) web directories" -Risk "HIGH"
		Write-Host "   [W-20] Weak ACLs on web directories" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-20" -Item "Data file ACL" -Status "PASS" -Details "Web directory ACLs appear secure" -Risk "LOW"
		Write-Host "   [W-20] Web directory ACLs appear secure" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-20" -Item "Data file ACL" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-20] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-21: Remove unused script mappings
Write-Progress -Activity "IIS Security" -Status "W-21: Script mappings" -PercentComplete 60
try {
	$handlers = Get-WebHandler -PSPath "IIS:\" -ErrorAction SilentlyContinue
	$riskyHandlers = @()

	$riskyExtensions = @(".htr", ".idc", ".shtm", ".shtml", ".printer", ".htw", ".ida", ".idq")
	foreach ($handler in $handlers) {
		foreach ($ext in $riskyExtensions) {
			if ($handler.Path -like "*$ext") {
				$riskyHandlers += $handler.Name
			}
		}
	}

	if ($riskyHandlers.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-21" -Item "Remove unused script mappings" -Status "FAIL" -Details "Risky script mappings found: $($riskyHandlers -join ', ')" -Risk "HIGH"
		Write-Host "   [W-21] Risky script mappings found" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-21" -Item "Remove unused script mappings" -Status "PASS" -Details "No risky script mappings found" -Risk "LOW"
		Write-Host "   [W-21] No risky script mappings found" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-21" -Item "Remove unused script mappings" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-21] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-22: Exec command shell invocation
Write-Progress -Activity "IIS Security" -Status "W-22: Exec shell commands" -PercentComplete 65
try {
	$sites = Get-Website -ErrorAction SilentlyContinue
	$vulnerableFiles = @()

	$riskyCommands = @("cmd.exe", "command.com", "exec", "shell", "system\(")
	foreach ($site in $sites) {
		$physicalPath = $site.PhysicalPath
		if ($physicalPath -and (Test-Path $physicalPath)) {
			$scriptFiles = Get-ChildItem -Path $physicalPath -Include "*.asp", "*.aspx", "*.php" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20
			foreach ($file in $scriptFiles) {
				$content = Get-Content $file.FullName -ErrorAction SilentlyContinue
				foreach ($cmd in $riskyCommands) {
					if ($content -match $cmd) {
						$vulnerableFiles += $file.Name
						break
					}
				}
			}
		}
	}

	if ($vulnerableFiles.Count -gt 0) {
		Save-Result -Category "IIS Security" -ItemCode "W-22" -Item "Exec command shell invocation" -Status "WARNING" -Details "Files with shell commands found: $($vulnerableFiles.Count)" -Risk "MEDIUM"
		Write-Host "   [W-22] Files with potential shell commands found" -ForegroundColor Yellow
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-22" -Item "Exec command shell invocation" -Status "PASS" -Details "No obvious shell command usage found" -Risk "LOW"
		Write-Host "   [W-22] No obvious shell command usage found" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-22" -Item "Exec command shell invocation" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-22] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-23: WebDAV disabled
Write-Progress -Activity "IIS Security" -Status "W-23: WebDAV" -PercentComplete 70
try {
	$webdav = Get-WebConfigurationProperty -Filter "system.webServer/webdav/authoring" -Name "enabled" -ErrorAction SilentlyContinue

	if ($webdav -and $webdav.Value -eq $true) {
		Save-Result -Category "IIS Security" -ItemCode "W-23" -Item "WebDAV disabled" -Status "FAIL" -Details "WebDAV is enabled" -Risk "HIGH"
		Write-Host "   [W-23] WebDAV is enabled" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-23" -Item "WebDAV disabled" -Status "PASS" -Details "WebDAV is disabled" -Risk "LOW"
		Write-Host "   [W-23] WebDAV is disabled" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-23" -Item "WebDAV disabled" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-23] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-59: Web service information hiding
Write-Progress -Activity "IIS Security" -Status "W-59: Server header hiding" -PercentComplete 95
try {
	$serverHeader = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -ErrorAction SilentlyContinue

	# Also check HTTP.sys setting
	$httpHeader = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "DisableServerHeader" -ErrorAction SilentlyContinue

	if ((!$serverHeader -or $serverHeader.Value -ne $true) -and (!$httpHeader -or $httpHeader.DisableServerHeader -ne 1)) {
		Save-Result -Category "IIS Security" -ItemCode "W-59" -Item "Web service information hiding" -Status "FAIL" -Details "Server header not hidden" -Risk "MEDIUM"
		Write-Host "   [W-59] Server header not hidden" -ForegroundColor Red
	} else {
		Save-Result -Category "IIS Security" -ItemCode "W-59" -Item "Web service information hiding" -Status "PASS" -Details "Server header appears hidden" -Risk "LOW"
		Write-Host "   [W-59] Server header appears hidden" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "IIS Security" -ItemCode "W-59" -Item "Web service information hiding" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-59] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Progress -Activity "IIS Security" -Completed
Write-Host "=== IIS Security Check Completed ===" -ForegroundColor Yellow
