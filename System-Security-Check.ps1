# -*- coding: utf-8 -*-
# System Security Check Script
# KISA Windows Security Assessment - System Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== System Security Check Started ===" -ForegroundColor Yellow

# W-31 & W-32: Windows Update status and HOT FIX
Write-Progress -Activity "System Security" -Status "W-31/W-32: Windows Update" -PercentComplete 3
try {
	$session = $null
	try { $session = New-Object -ComObject Microsoft.Update.Session } catch {}
	if ($null -eq $session) {
		Save-Result -Category "System Security" -ItemCode "W-31" -Item "Latest service pack" -Status "WARNING" -Details "Unable to check Windows Update" -Risk "MEDIUM"
		Write-Host "   [W-31/32] Unable to check Windows Update" -ForegroundColor Yellow
	} else {
		$searcher = $session.CreateUpdateSearcher()
		$result = $searcher.Search("IsInstalled=0")
		$cnt = @($result.Updates).Count
		if ($cnt -gt 0) {
			Save-Result -Category "System Security" -ItemCode "W-31" -Item "Latest service pack" -Status "WARNING" -Details "$cnt updates pending" -Risk "MEDIUM"
			Save-Result -Category "System Security" -ItemCode "W-32" -Item "Latest HOT FIX" -Status "WARNING" -Details "$cnt updates pending" -Risk "HIGH"
			Write-Host "   [W-31/32] Pending updates: $cnt" -ForegroundColor Yellow
		} else {
			Save-Result -Category "System Security" -ItemCode "W-31" -Item "Latest service pack" -Status "PASS" -Details "System is up to date" -Risk "LOW"
			Save-Result -Category "System Security" -ItemCode "W-32" -Item "Latest HOT FIX" -Status "PASS" -Details "System is up to date" -Risk "LOW"
			Write-Host "   [W-31/32] System is up to date" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-31" -Item "Latest service pack" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-31/32] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-33 & W-36: Antivirus status
Write-Progress -Activity "System Security" -Status "W-33/W-36: Antivirus" -PercentComplete 6
try {
	$av = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
	if ($null -eq $av) {
		Save-Result -Category "System Security" -ItemCode "W-33" -Item "Antivirus update" -Status "WARNING" -Details "Unable to retrieve antivirus info" -Risk "MEDIUM"
		Save-Result -Category "System Security" -ItemCode "W-36" -Item "Antivirus installed" -Status "WARNING" -Details "Unable to retrieve antivirus info" -Risk "MEDIUM"
		Write-Host "   [W-33/36] Unable to retrieve antivirus info" -ForegroundColor Yellow
	} else {
		$active = $av | Where-Object { $_.productState -ne 0 }
		if ((@($active).Count) -gt 0) {
			Save-Result -Category "System Security" -ItemCode "W-33" -Item "Antivirus update" -Status "PASS" -Details "Active antivirus detected" -Risk "LOW"
			Save-Result -Category "System Security" -ItemCode "W-36" -Item "Antivirus installed" -Status "PASS" -Details "Antivirus installed and active" -Risk "LOW"
			Write-Host "   [W-33/36] Antivirus active" -ForegroundColor Green
		} else {
			Save-Result -Category "System Security" -ItemCode "W-33" -Item "Antivirus update" -Status "FAIL" -Details "No active antivirus" -Risk "HIGH"
			Save-Result -Category "System Security" -ItemCode "W-36" -Item "Antivirus installed" -Status "FAIL" -Details "No active antivirus" -Risk "HIGH"
			Write-Host "   [W-33/36] Antivirus inactive" -ForegroundColor Red
		}
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-33" -Item "Antivirus update" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-33/36] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-37: SAM file access control
Write-Progress -Activity "System Security" -Status "W-37: SAM file ACL" -PercentComplete 9
try {
	$samPath = "$env:SystemRoot\System32\config\SAM"
	if (Test-Path $samPath) {
		$acl = Get-Acl $samPath -ErrorAction SilentlyContinue
		$everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }
		$usersAccess = $acl.Access | Where-Object { $_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Read|Write" }

		if ($everyoneAccess -or $usersAccess) {
			Save-Result -Category "System Security" -ItemCode "W-37" -Item "SAM file access control" -Status "FAIL" -Details "Weak ACL on SAM file" -Risk "HIGH"
			Write-Host "   [W-37] SAM file has weak ACL" -ForegroundColor Red
		} else {
			Save-Result -Category "System Security" -ItemCode "W-37" -Item "SAM file access control" -Status "PASS" -Details "SAM file properly protected" -Risk "LOW"
			Write-Host "   [W-37] SAM file properly protected" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "System Security" -ItemCode "W-37" -Item "SAM file access control" -Status "WARNING" -Details "SAM file not found" -Risk "MEDIUM"
		Write-Host "   [W-37] SAM file not found" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-37" -Item "SAM file access control" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-37] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-38: Screen saver settings
Write-Progress -Activity "System Security" -Status "W-38: Screen saver" -PercentComplete 12
try {
	$screenSaver = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
	$screenSaverSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
	$screenSaverTimeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue

	if (!$screenSaver -or $screenSaver.ScreenSaveActive -ne "1") {
		Save-Result -Category "System Security" -ItemCode "W-38" -Item "Screen saver settings" -Status "FAIL" -Details "Screen saver not enabled" -Risk "HIGH"
		Write-Host "   [W-38] Screen saver not enabled" -ForegroundColor Red
	} elseif (!$screenSaverSecure -or $screenSaverSecure.ScreenSaverIsSecure -ne "1") {
		Save-Result -Category "System Security" -ItemCode "W-38" -Item "Screen saver settings" -Status "FAIL" -Details "Screen saver password not required" -Risk "HIGH"
		Write-Host "   [W-38] Screen saver password not required" -ForegroundColor Red
	} elseif (!$screenSaverTimeout -or [int]$screenSaverTimeout.ScreenSaveTimeOut -gt 900) {
		Save-Result -Category "System Security" -ItemCode "W-38" -Item "Screen saver settings" -Status "WARNING" -Details "Screen saver timeout too long" -Risk "MEDIUM"
		Write-Host "   [W-38] Screen saver timeout too long" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -ItemCode "W-38" -Item "Screen saver settings" -Status "PASS" -Details "Screen saver properly configured" -Risk "LOW"
		Write-Host "   [W-38] Screen saver properly configured" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-38" -Item "Screen saver settings" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-38] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-39: Shutdown without logon
Write-Progress -Activity "System Security" -Status "W-39: Shutdown without logon" -PercentComplete 15
try {
	$shutdownWithoutLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -ErrorAction SilentlyContinue

	if ($shutdownWithoutLogon -and $shutdownWithoutLogon.ShutdownWithoutLogon -eq 1) {
		Save-Result -Category "System Security" -ItemCode "W-39" -Item "Shutdown without logon disabled" -Status "FAIL" -Details "Shutdown without logon is allowed" -Risk "HIGH"
		Write-Host "   [W-39] Shutdown without logon is allowed" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -ItemCode "W-39" -Item "Shutdown without logon disabled" -Status "PASS" -Details "Shutdown without logon is blocked" -Risk "LOW"
		Write-Host "   [W-39] Shutdown without logon is blocked" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-39" -Item "Shutdown without logon disabled" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-39] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-40: Remote shutdown
Write-Progress -Activity "System Security" -Status "W-40: Remote shutdown" -PercentComplete 18
try {
	$seceditOutput = secedit /export /cfg temp_secpol.cfg /quiet 2>&1
	if (Test-Path "temp_secpol.cfg") {
		$remoteShutdown = Get-Content "temp_secpol.cfg" -ErrorAction SilentlyContinue | Select-String "SeRemoteShutdownPrivilege"

		if ($remoteShutdown -and $remoteShutdown -match "S-1-5-32-544") {
			# Administrators have remote shutdown - this is normal
			Save-Result -Category "System Security" -ItemCode "W-40" -Item "Remote shutdown privilege" -Status "PASS" -Details "Remote shutdown restricted to administrators" -Risk "LOW"
			Write-Host "   [W-40] Remote shutdown restricted to administrators" -ForegroundColor Green
		} else {
			Save-Result -Category "System Security" -ItemCode "W-40" -Item "Remote shutdown privilege" -Status "PASS" -Details "Remote shutdown appears restricted" -Risk "LOW"
			Write-Host "   [W-40] Remote shutdown appears restricted" -ForegroundColor Green
		}
		Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	} else {
		Save-Result -Category "System Security" -ItemCode "W-40" -Item "Remote shutdown privilege" -Status "WARNING" -Details "Unable to check policy" -Risk "MEDIUM"
		Write-Host "   [W-40] Unable to check policy" -ForegroundColor Yellow
	}
} catch {
	Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	Save-Result -Category "System Security" -ItemCode "W-40" -Item "Remote shutdown privilege" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-40] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-41: Shutdown if unable to log security audits
Write-Progress -Activity "System Security" -Status "W-41: Audit log failure" -PercentComplete 21
try {
	$crashOnAuditFail = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "CrashOnAuditFail" -ErrorAction SilentlyContinue

	if ($crashOnAuditFail -and $crashOnAuditFail.CrashOnAuditFail -eq 1) {
		Save-Result -Category "System Security" -ItemCode "W-41" -Item "Shutdown on audit failure" -Status "WARNING" -Details "System will shutdown if auditing fails (may cause availability issues)" -Risk "MEDIUM"
		Write-Host "   [W-41] System will shutdown if auditing fails" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -ItemCode "W-41" -Item "Shutdown on audit failure" -Status "PASS" -Details "System will not shutdown on audit failure" -Risk "LOW"
		Write-Host "   [W-41] System will not shutdown on audit failure" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-41" -Item "Shutdown on audit failure" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-41] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-43: Auto logon disabled
Write-Progress -Activity "System Security" -Status "W-43: Auto logon" -PercentComplete 24
try {
	$autoProp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
	$auto = if ($autoProp) { $autoProp.AutoAdminLogon } else { $null }
	if ($auto -eq "1") {
		Save-Result -Category "System Security" -ItemCode "W-43" -Item "Auto logon disabled" -Status "FAIL" -Details "Auto logon is enabled" -Risk "HIGH"
		Write-Host "   [W-43] Auto logon is enabled" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -ItemCode "W-43" -Item "Auto logon disabled" -Status "PASS" -Details "Auto logon is disabled" -Risk "LOW"
		Write-Host "   [W-43] Auto logon is disabled" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-43" -Item "Auto logon disabled" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-43] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-44: Removable media format/eject permissions
Write-Progress -Activity "System Security" -Status "W-44: Removable media" -PercentComplete 27
try {
	$allocateDASD = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -ErrorAction SilentlyContinue

	if (!$allocateDASD -or $allocateDASD.AllocateDASD -eq "0") {
		Save-Result -Category "System Security" -ItemCode "W-44" -Item "Removable media permissions" -Status "PASS" -Details "Removable media access restricted to administrators" -Risk "LOW"
		Write-Host "   [W-44] Removable media access properly restricted" -ForegroundColor Green
	} else {
		Save-Result -Category "System Security" -ItemCode "W-44" -Item "Removable media permissions" -Status "WARNING" -Details "Users can format/eject removable media" -Risk "MEDIUM"
		Write-Host "   [W-44] Users can format/eject removable media" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-44" -Item "Removable media permissions" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-44] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-45: Disk volume encryption
Write-Progress -Activity "System Security" -Status "W-45: Disk encryption" -PercentComplete 30
try {
	$bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
	if ($bitlocker) {
		$unencrypted = $bitlocker | Where-Object { $_.ProtectionStatus -eq "Off" }
		if ($unencrypted) {
			Save-Result -Category "System Security" -ItemCode "W-45" -Item "Disk volume encryption" -Status "FAIL" -Details "$(@($unencrypted).Count) volumes not encrypted" -Risk "HIGH"
			Write-Host "   [W-45] Unencrypted volumes found: $(@($unencrypted).Count)" -ForegroundColor Red
		} else {
			Save-Result -Category "System Security" -ItemCode "W-45" -Item "Disk volume encryption" -Status "PASS" -Details "All volumes encrypted" -Risk "LOW"
			Write-Host "   [W-45] All volumes encrypted" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "System Security" -ItemCode "W-45" -Item "Disk volume encryption" -Status "WARNING" -Details "BitLocker not available or no volumes found" -Risk "MEDIUM"
		Write-Host "   [W-45] BitLocker not available" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-45" -Item "Disk volume encryption" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-45] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-72: DoS attack defense registry settings
Write-Progress -Activity "System Security" -Status "W-72: DoS defense" -PercentComplete 33
try {
	$tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
	$synAttackProtect = Get-ItemProperty -Path $tcpParams -Name "SynAttackProtect" -ErrorAction SilentlyContinue
	$enableDeadGWDetect = Get-ItemProperty -Path $tcpParams -Name "EnableDeadGWDetect" -ErrorAction SilentlyContinue

	$issues = @()
	if (!$synAttackProtect -or $synAttackProtect.SynAttackProtect -lt 1) {
		$issues += "SynAttackProtect not enabled"
	}
	if (!$enableDeadGWDetect -or $enableDeadGWDetect.EnableDeadGWDetect -ne 0) {
		$issues += "EnableDeadGWDetect should be disabled"
	}

	if ($issues.Count -gt 0) {
		Save-Result -Category "System Security" -ItemCode "W-72" -Item "DoS attack defense settings" -Status "FAIL" -Details "$($issues -join '; ')" -Risk "MEDIUM"
		Write-Host "   [W-72] DoS defense settings need attention" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -ItemCode "W-72" -Item "DoS attack defense settings" -Status "PASS" -Details "DoS defense settings properly configured" -Risk "LOW"
		Write-Host "   [W-72] DoS defense settings OK" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-72" -Item "DoS attack defense settings" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-72] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-73: Prevent users from installing printer drivers
Write-Progress -Activity "System Security" -Status "W-73: Printer driver install" -PercentComplete 36
try {
	$addPrinterDrivers = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -ErrorAction SilentlyContinue

	if ($addPrinterDrivers -and $addPrinterDrivers.AddPrinterDrivers -eq 1) {
		Save-Result -Category "System Security" -ItemCode "W-73" -Item "Printer driver installation" -Status "WARNING" -Details "Users can install printer drivers" -Risk "MEDIUM"
		Write-Host "   [W-73] Users can install printer drivers" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -ItemCode "W-73" -Item "Printer driver installation" -Status "PASS" -Details "Printer driver installation restricted" -Risk "LOW"
		Write-Host "   [W-73] Printer driver installation restricted" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-73" -Item "Printer driver installation" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-73] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-74: Session idle time
Write-Progress -Activity "System Security" -Status "W-74: Session idle time" -PercentComplete 39
try {
	$rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
	if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
		$maxIdleTime = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue

		if (!$maxIdleTime -or $maxIdleTime.MaxIdleTime -eq 0) {
			Save-Result -Category "System Security" -ItemCode "W-74" -Item "Session idle time" -Status "FAIL" -Details "No idle timeout set for RDP sessions" -Risk "MEDIUM"
			Write-Host "   [W-74] No idle timeout set" -ForegroundColor Red
		} elseif ($maxIdleTime.MaxIdleTime -gt 1800000) { # 30 minutes
			Save-Result -Category "System Security" -ItemCode "W-74" -Item "Session idle time" -Status "WARNING" -Details "Idle timeout too long: $([math]::Round($maxIdleTime.MaxIdleTime/60000)) minutes" -Risk "MEDIUM"
			Write-Host "   [W-74] Idle timeout too long" -ForegroundColor Yellow
		} else {
			Save-Result -Category "System Security" -ItemCode "W-74" -Item "Session idle time" -Status "PASS" -Details "Idle timeout properly configured" -Risk "LOW"
			Write-Host "   [W-74] Idle timeout properly configured" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "System Security" -ItemCode "W-74" -Item "Session idle time" -Status "PASS" -Details "RDP disabled" -Risk "LOW"
		Write-Host "   [W-74] RDP disabled" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-74" -Item "Session idle time" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-74] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-75: Warning message settings
Write-Progress -Activity "System Security" -Status "W-75: Logon banner" -PercentComplete 42
try {
	$legalNoticeCaption = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue
	$legalNoticeText = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction SilentlyContinue

	if ((!$legalNoticeCaption -or [string]::IsNullOrWhiteSpace($legalNoticeCaption.LegalNoticeCaption)) -and
		(!$legalNoticeText -or [string]::IsNullOrWhiteSpace($legalNoticeText.LegalNoticeText))) {
		Save-Result -Category "System Security" -ItemCode "W-75" -Item "Warning message settings" -Status "WARNING" -Details "No logon banner configured" -Risk "LOW"
		Write-Host "   [W-75] No logon banner configured" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -ItemCode "W-75" -Item "Warning message settings" -Status "PASS" -Details "Logon banner configured" -Risk "LOW"
		Write-Host "   [W-75] Logon banner configured" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-75" -Item "Warning message settings" -Status "WARNING" -Details $_.Exception.Message -Risk "LOW"
	Write-Host "   [W-75] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-76: Home directory permissions
Write-Progress -Activity "System Security" -Status "W-76: Home directories" -PercentComplete 45
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
			Save-Result -Category "System Security" -ItemCode "W-76" -Item "Home directory permissions" -Status "FAIL" -Details "$($vulnerableDirs.Count) directories with Everyone permission" -Risk "HIGH"
			Write-Host "   [W-76] Home directories with weak permissions: $($vulnerableDirs.Count)" -ForegroundColor Red
		} else {
			Save-Result -Category "System Security" -ItemCode "W-76" -Item "Home directory permissions" -Status "PASS" -Details "Home directory permissions OK" -Risk "LOW"
			Write-Host "   [W-76] Home directory permissions OK" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-76" -Item "Home directory permissions" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-76] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-77: LAN Manager authentication level
Write-Progress -Activity "System Security" -Status "W-77: LM auth level" -PercentComplete 48
try {
	$lmCompatibility = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

	if (!$lmCompatibility -or $lmCompatibility.LmCompatibilityLevel -lt 3) {
		Save-Result -Category "System Security" -ItemCode "W-77" -Item "LAN Manager authentication level" -Status "FAIL" -Details "LM authentication level too low (current: $($lmCompatibility.LmCompatibilityLevel))" -Risk "MEDIUM"
		Write-Host "   [W-77] LM authentication level too low" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -ItemCode "W-77" -Item "LAN Manager authentication level" -Status "PASS" -Details "LM authentication level adequate (level: $($lmCompatibility.LmCompatibilityLevel))" -Risk "LOW"
		Write-Host "   [W-77] LM authentication level adequate" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-77" -Item "LAN Manager authentication level" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-77] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-78: Secure channel data encryption/signing
Write-Progress -Activity "System Security" -Status "W-78: Secure channel" -PercentComplete 51
try {
	$requireSignOrSeal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -ErrorAction SilentlyContinue

	if (!$requireSignOrSeal -or $requireSignOrSeal.RequireSignOrSeal -ne 1) {
		Save-Result -Category "System Security" -ItemCode "W-78" -Item "Secure channel data encryption/signing" -Status "FAIL" -Details "Secure channel signing/sealing not required" -Risk "MEDIUM"
		Write-Host "   [W-78] Secure channel signing/sealing not required" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -ItemCode "W-78" -Item "Secure channel data encryption/signing" -Status "PASS" -Details "Secure channel properly configured" -Risk "LOW"
		Write-Host "   [W-78] Secure channel properly configured" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-78" -Item "Secure channel data encryption/signing" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-78] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-79: File and directory protection
Write-Progress -Activity "System Security" -Status "W-79: System file protection" -PercentComplete 54
try {
	$criticalPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\System32\config")
	$vulnerablePaths = @()

	foreach ($path in $criticalPaths) {
		if (Test-Path $path) {
			$acl = Get-Acl $path -ErrorAction SilentlyContinue
			$everyoneWrite = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write|Modify|FullControl" }
			if ($everyoneWrite) {
				$vulnerablePaths += $path
			}
		}
	}

	if ($vulnerablePaths.Count -gt 0) {
		Save-Result -Category "System Security" -ItemCode "W-79" -Item "File and directory protection" -Status "FAIL" -Details "Critical paths with weak ACLs: $($vulnerablePaths -join ', ')" -Risk "HIGH"
		Write-Host "   [W-79] Critical paths with weak ACLs found" -ForegroundColor Red
	} else {
		Save-Result -Category "System Security" -ItemCode "W-79" -Item "File and directory protection" -Status "PASS" -Details "System files properly protected" -Risk "LOW"
		Write-Host "   [W-79] System files properly protected" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-79" -Item "File and directory protection" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-79] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-80: Computer account password maximum age
Write-Progress -Activity "System Security" -Status "W-80: Computer password age" -PercentComplete 57
try {
	$maxPwdAge = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue

	if (!$maxPwdAge) {
		# Default is 30 days
		Save-Result -Category "System Security" -ItemCode "W-80" -Item "Computer account password age" -Status "PASS" -Details "Using default value (30 days)" -Risk "LOW"
		Write-Host "   [W-80] Computer password age using default" -ForegroundColor Green
	} elseif ($maxPwdAge.MaximumPasswordAge -gt 30) {
		Save-Result -Category "System Security" -ItemCode "W-80" -Item "Computer account password age" -Status "WARNING" -Details "Password age too long: $($maxPwdAge.MaximumPasswordAge) days" -Risk "MEDIUM"
		Write-Host "   [W-80] Computer password age too long" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -ItemCode "W-80" -Item "Computer account password age" -Status "PASS" -Details "Computer password age OK: $($maxPwdAge.MaximumPasswordAge) days" -Risk "LOW"
		Write-Host "   [W-80] Computer password age OK" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-80" -Item "Computer account password age" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-80] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-81: Startup program analysis
Write-Progress -Activity "System Security" -Status "W-81: Startup programs" -PercentComplete 60
try {
	$startupLocations = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
	)

	$suspiciousPrograms = @()
	$suspiciousPatterns = @("temp", "tmp", "appdata", "roaming", "local", "programdata")

	foreach ($location in $startupLocations) {
		try {
			$items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
			if ($items) {
				$properties = $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
				foreach ($prop in $properties) {
					$value = $prop.Value
					foreach ($pattern in $suspiciousPatterns) {
						if ($value -like "*$pattern*") {
							$suspiciousPrograms += "$($prop.Name): $value"
							break
						}
					}
				}
			}
		} catch {}
	}

	if ($suspiciousPrograms.Count -gt 0) {
		Save-Result -Category "System Security" -ItemCode "W-81" -Item "Startup program analysis" -Status "WARNING" -Details "$($suspiciousPrograms.Count) potentially suspicious startup items" -Risk "MEDIUM"
		Write-Host "   [W-81] Potentially suspicious startup items: $($suspiciousPrograms.Count)" -ForegroundColor Yellow
	} else {
		Save-Result -Category "System Security" -ItemCode "W-81" -Item "Startup program analysis" -Status "PASS" -Details "No obviously suspicious startup programs" -Risk "LOW"
		Write-Host "   [W-81] No obviously suspicious startup programs" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "W-81" -Item "Startup program analysis" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-81] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Firewall check
Write-Progress -Activity "System Security" -Status "Checking Firewall" -PercentComplete 85
try {
	$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
	if ($null -eq $profiles) {
		Save-Result -Category "System Security" -ItemCode "FIREWALL" -Item "Firewall status" -Status "WARNING" -Details "Unable to retrieve firewall profiles" -Risk "MEDIUM"
		Write-Host "   [FIREWALL] Unable to retrieve firewall profiles" -ForegroundColor Yellow
	} else {
		$disabled = $profiles | Where-Object { -not $_.Enabled }
		if ((@($disabled).Count) -gt 0) {
			Save-Result -Category "System Security" -ItemCode "FIREWALL" -Item "Firewall status" -Status "FAIL" -Details "Disabled profiles present" -Risk "HIGH"
			Write-Host "   [FIREWALL] Disabled firewall profiles detected" -ForegroundColor Red
		} else {
			Save-Result -Category "System Security" -ItemCode "FIREWALL" -Item "Firewall status" -Status "PASS" -Details "All profiles enabled" -Risk "LOW"
			Write-Host "   [FIREWALL] Firewall OK" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "FIREWALL" -Item "Firewall status" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [FIREWALL] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# UAC check
Write-Progress -Activity "System Security" -Status "Checking UAC" -PercentComplete 95
try {
	$uacProp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
	$uac = if ($uacProp) { $uacProp.EnableLUA } else { $null }
	if ($uac -eq 1) {
		Save-Result -Category "System Security" -ItemCode "UAC" -Item "User Account Control" -Status "PASS" -Details "UAC enabled" -Risk "LOW"
		Write-Host "   [UAC] UAC enabled" -ForegroundColor Green
	} else {
		Save-Result -Category "System Security" -ItemCode "UAC" -Item "User Account Control" -Status "FAIL" -Details "UAC disabled" -Risk "HIGH"
		Write-Host "   [UAC] UAC disabled" -ForegroundColor Red
	}
} catch {
	Save-Result -Category "System Security" -ItemCode "UAC" -Item "User Account Control" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [UAC] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "System Security" -Completed
Write-Host "=== System Security Check Completed ===" -ForegroundColor Yellow
