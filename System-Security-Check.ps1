# System Security Check Script (English)
# - Detailed checks, no emojis, Save-Result guard

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== System Security Check Started ===" -ForegroundColor Yellow

Write-Progress -Activity "System Security" -Status "Checking Windows Update" -PercentComplete 10
# 1) Windows Update status
try {
	$session = $null
	try { $session = New-Object -ComObject Microsoft.Update.Session } catch {}
	if ($null -eq $session) {
		Save-Result -Category "System Security" -Item "Windows Update" -Status "WARNING" -Details "COM Microsoft.Update.Session unavailable" -Risk "MEDIUM"
		Write-Host "   Microsoft.Update.Session COM unavailable" -ForegroundColor Yellow
	} else {
		$searcher = $session.CreateUpdateSearcher()
		$result = $searcher.Search("IsInstalled=0")
		$cnt = @($result.Updates).Count
		if ($cnt -gt 0) {
			Save-Result -Category "System Security" -Item "Windows Update" -Status "WARNING" -Details "$cnt updates pending" -Risk "MEDIUM"
			Write-Host "   Pending updates: $cnt" -ForegroundColor Yellow
		} else {
			Save-Result -Category "System Security" -Item "Windows Update" -Status "PASS" -Details "Up to date" -Risk "LOW"
			Write-Host "   System is up to date" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "System Security" -Item "Windows Update" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check updates: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "System Security" -Status "Checking Firewall" -PercentComplete 35
# 2) Firewall profiles
try {
	$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
	if ($null -eq $profiles) {
		Save-Result -Category "System Security" -Item "Firewall" -Status "WARNING" -Details "Unable to retrieve firewall profiles" -Risk "MEDIUM"
		Write-Host "   Unable to retrieve firewall profiles" -ForegroundColor Yellow
	} else {
		$disabled = $profiles | Where-Object { -not $_.Enabled }
		if ((@($disabled).Count) -gt 0) {
			Save-Result -Category "System Security" -Item "Firewall" -Status "FAIL" -Details "Disabled profiles present" -Risk "HIGH"
			Write-Host "   Disabled firewall profiles detected" -ForegroundColor Red
		} else {
			Save-Result -Category "System Security" -Item "Firewall" -Status "PASS" -Details "All profiles enabled" -Risk "LOW"
			Write-Host "   Firewall OK" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "System Security" -Item "Firewall" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check firewall: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "System Security" -Status "Checking Antivirus" -PercentComplete 60
# 3) Antivirus status
try {
	$av = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
	if ($null -eq $av) {
		Save-Result -Category "System Security" -Item "Antivirus" -Status "WARNING" -Details "Unable to retrieve info" -Risk "MEDIUM"
		Write-Host "   Unable to retrieve antivirus info" -ForegroundColor Yellow
	} else {
		$active = $av | Where-Object { $_.productState -ne 0 }
		if ((@($active).Count) -gt 0) {
			Save-Result -Category "System Security" -Item "Antivirus" -Status "PASS" -Details "Active product detected" -Risk "LOW"
			Write-Host "   Antivirus active" -ForegroundColor Green
		} else {
			Save-Result -Category "System Security" -Item "Antivirus" -Status "FAIL" -Details "No active product" -Risk "HIGH"
			Write-Host "   Antivirus inactive" -ForegroundColor Red
		}
	}
} catch {
	Save-Result -Category "System Security" -Item "Antivirus" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check antivirus: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "System Security" -Status "Checking Remote Registry" -PercentComplete 80
# 4) Remote Registry service
try {
	$svc = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
	if ($svc -and $svc.Status -eq "Running") {
		Save-Result -Category "System Security" -Item "Remote Registry" -Status "WARNING" -Details "Service is running" -Risk "MEDIUM"
		Write-Host "   Remote Registry is running" -ForegroundColor Yellow
	} elseif ($svc) {
		Save-Result -Category "System Security" -Item "Remote Registry" -Status "PASS" -Details "Disabled" -Risk "LOW"
		Write-Host "   Remote Registry disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "System Security" -Item "Remote Registry" -Status "WARNING" -Details "Service not found" -Risk "MEDIUM"
		Write-Host "   Remote Registry service not found" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "System Security" -Item "Remote Registry" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check Remote Registry: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "System Security" -Status "Checking Auto logon & UAC" -PercentComplete 90
# 5) Auto logon
try {
	$autoProp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
	$auto = if ($autoProp) { $autoProp.AutoAdminLogon } else { $null }
	if ($auto -eq 1) {
		Save-Result -Category "System Security" -Item "Auto logon" -Status "FAIL" -Details "Enabled" -Risk "HIGH"
		Write-Host "   Auto logon enabled" -ForegroundColor Red
	} elseif ($null -eq $auto) {
		Save-Result -Category "System Security" -Item "Auto logon" -Status "WARNING" -Details "Unable to read setting" -Risk "MEDIUM"
		Write-Host "   Unable to read auto logon setting" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -Item "Auto logon" -Status "PASS" -Details "Disabled" -Risk "LOW"
		Write-Host "   Auto logon disabled" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -Item "Auto logon" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check auto logon: $($_.Exception.Message)" -ForegroundColor Red
}

# 6) UAC
try {
	$uacProp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
	$uac = if ($uacProp) { $uacProp.EnableLUA } else { $null }
	if ($uac -eq 1) {
		Save-Result -Category "System Security" -Item "UAC" -Status "PASS" -Details "Enabled" -Risk "LOW"
		Write-Host "   UAC enabled" -ForegroundColor Green
	} elseif ($null -eq $uac) {
		Save-Result -Category "System Security" -Item "UAC" -Status "WARNING" -Details "Unable to read setting" -Risk "MEDIUM"
		Write-Host "   Unable to read UAC setting" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -Item "UAC" -Status "FAIL" -Details "Disabled" -Risk "HIGH"
		Write-Host "   UAC disabled" -ForegroundColor Red
	}
} catch {
	Save-Result -Category "System Security" -Item "UAC" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check UAC: $($_.Exception.Message)" -ForegroundColor Red
}

# 7) FTP service check
try {
	$ftpService = Get-Service -Name "*ftp*" -ErrorAction SilentlyContinue
	$ftpRunning = $false

	foreach ($service in $ftpService) {
		if ($service.Status -eq "Running") {
			$ftpRunning = $true
			Write-Host "   FTP service running: $($service.Name)" -ForegroundColor Red
		}
	}

	if ($ftpRunning) {
		Save-Result -Category "System Security" -Item "FTP service" -Status "FAIL" -Details "FTP service running" -Risk "HIGH"
		Write-Host "   FTP service is running" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -Item "FTP service" -Status "PASS" -Details "FTP service stopped" -Risk "LOW"
		Write-Host "   FTP service stopped or not installed" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -Item "FTP service" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check FTP service: $($_.Exception.Message)" -ForegroundColor Red
}

# 8) Risky services check
try {
	$riskyServices = @{
		"Telnet" = "Remote access risk"
		"SNMP" = "Network information exposure"
		"TlntSvr" = "Telnet server"
		"MSFTPSVC" = "Microsoft FTP service"
	}

	$foundRiskyServices = @()

	foreach ($serviceName in $riskyServices.Keys) {
		$svc = Get-Service -Name "*$serviceName*" -ErrorAction SilentlyContinue
		if ($svc) {
			foreach ($service in $svc) {
				if ($service.Status -eq "Running") {
					$foundRiskyServices += $service.Name
					Save-Result -Category "System Security" -Item "Risky service: $($service.Name)" -Status "FAIL" -Details $riskyServices[$serviceName] -Risk "HIGH"
					Write-Host "   Risky service running: $($service.Name)" -ForegroundColor Red
				}
			}
		}
	}

	if ($foundRiskyServices.Count -eq 0) {
		Write-Host "   No risky services running" -ForegroundColor Green
	}
} catch {
	Write-Host "   Failed to check risky services: $($_.Exception.Message)" -ForegroundColor Red
}

# 9) User home directory permissions
try {
	$usersPath = "C:\Users"
	$vulnerableDirs = @()

	if (Test-Path $usersPath) {
		$userDirs = Get-ChildItem $usersPath -Directory -ErrorAction SilentlyContinue
		foreach ($dir in $userDirs) {
			try {
				$acl = Get-Acl $dir.FullName -ErrorAction SilentlyContinue
				$everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }
				if ($everyoneAccess) {
					$vulnerableDirs += $dir.Name
				}
			} catch {
				# Skip directories that can't be accessed
			}
		}

		if ($vulnerableDirs.Count -gt 0) {
			Save-Result -Category "System Security" -Item "Home directory permissions" -Status "FAIL" -Details "$($vulnerableDirs.Count) directories with Everyone permission" -Risk "HIGH"
			Write-Host "   Home directories with Everyone permission: $($vulnerableDirs.Count)" -ForegroundColor Red
		} else {
			Save-Result -Category "System Security" -Item "Home directory permissions" -Status "PASS" -Details "No Everyone permission found" -Risk "LOW"
			Write-Host "   Home directory permissions OK" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "System Security" -Item "Home directory permissions" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check home directory permissions: $($_.Exception.Message)" -ForegroundColor Red
}

# 10) Critical security patches check
try {
	$updates = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending

	if ($updates) {
		$latestUpdate = $updates | Select-Object -First 1
		$daysSinceUpdate = (Get-Date) - $latestUpdate.InstalledOn

		if ($daysSinceUpdate.TotalDays -gt 30) {
			Save-Result -Category "System Security" -Item "Update freshness" -Status "WARNING" -Details "$([math]::Round($daysSinceUpdate.TotalDays)) days since last update" -Risk "MEDIUM"
			Write-Host "   System not updated in $([math]::Round($daysSinceUpdate.TotalDays)) days" -ForegroundColor Yellow
		} else {
			Save-Result -Category "System Security" -Item "Update freshness" -Status "PASS" -Details "Updated $([math]::Round($daysSinceUpdate.TotalDays)) days ago" -Risk "LOW"
			Write-Host "   System recently updated" -ForegroundColor Green
		}

		# Check critical patches
		$criticalPatches = @{
			"RDP CVE-2019-0708 BlueKeep" = @("KB4499149", "KB4499164", "KB4499175")
			"PrintNightmare CVE-2021-34527" = @("KB5004945", "KB5004953", "KB5004960")
		}

		$installedKBs = $updates | ForEach-Object { $_.HotFixID }

		foreach ($patchCategory in $criticalPatches.Keys) {
			$requiredKBs = $criticalPatches[$patchCategory]
			$hasRequiredPatch = $false

			foreach ($kb in $requiredKBs) {
				if ($installedKBs -contains $kb) {
					$hasRequiredPatch = $true
					break
				}
			}

			if (!$hasRequiredPatch) {
				Save-Result -Category "System Security" -Item "Critical patch: $patchCategory" -Status "WARNING" -Details "Not installed" -Risk "MEDIUM"
				Write-Host "   $patchCategory patch not found" -ForegroundColor Yellow
			}
		}
	}
} catch {
	Write-Host "   Failed to check security patches: $($_.Exception.Message)" -ForegroundColor Red
}

# 11) Visual Studio security version check
try {
	$vsRegPaths = @(
		"HKLM:\SOFTWARE\Microsoft\VisualStudio\*\Setup\VS",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\*\Setup\VS"
	)

	$vsFound = $false

	foreach ($regPath in $vsRegPaths) {
		$vsInstalls = Get-ChildItem $regPath -ErrorAction SilentlyContinue
		foreach ($install in $vsInstalls) {
			$vsFound = $true
			$version = Get-ItemProperty -Path $install.PSPath -Name "ProductVersion" -ErrorAction SilentlyContinue
			if ($version) {
				$versionNumber = $version.ProductVersion
				$isVulnerable = $true

				# Version-specific security version check
				if ($versionNumber -like "15.*") {  # VS 2017
					if ([version]$versionNumber -ge [version]"15.9.57") { $isVulnerable = $false }
				} elseif ($versionNumber -like "16.*") {  # VS 2019
					if ([version]$versionNumber -ge [version]"16.11.30") { $isVulnerable = $false }
				} elseif ($versionNumber -like "17.*") {  # VS 2022
					if ([version]$versionNumber -ge [version]"17.7.6") { $isVulnerable = $false }
				}

				if ($isVulnerable) {
					Save-Result -Category "System Security" -Item "Visual Studio security" -Status "WARNING" -Details "Version $versionNumber needs update" -Risk "MEDIUM"
					Write-Host "   Visual Studio $versionNumber needs security update" -ForegroundColor Yellow
				} else {
					Save-Result -Category "System Security" -Item "Visual Studio security" -Status "PASS" -Details "Version $versionNumber is secure" -Risk "LOW"
					Write-Host "   Visual Studio $versionNumber is up to date" -ForegroundColor Green
				}
			}
		}
	}

	if (!$vsFound) {
		Write-Host "   Visual Studio not installed" -ForegroundColor Cyan
	}
} catch {
	Write-Host "   Failed to check Visual Studio: $($_.Exception.Message)" -ForegroundColor Red
}

# 12) System backup policy check
try {
	$wbadminStatus = & wbadmin get versions -quiet 2>$null

	if ($wbadminStatus -and $wbadminStatus -notmatch "No backup") {
		Save-Result -Category "System Security" -Item "System backup" -Status "PASS" -Details "Backup policy configured" -Risk "LOW"
		Write-Host "   System backup configured" -ForegroundColor Green
	} else {
		Save-Result -Category "System Security" -Item "System backup" -Status "WARNING" -Details "No backup configured" -Risk "MEDIUM"
		Write-Host "   System backup not configured" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "System Security" -Item "System backup" -Status "WARNING" -Details "Unable to check backup status" -Risk "MEDIUM"
	Write-Host "   Unable to check backup status" -ForegroundColor Yellow
}

Write-Progress -Activity "System Security" -Completed
Write-Host "=== System Security Check Completed ===" -ForegroundColor Yellow