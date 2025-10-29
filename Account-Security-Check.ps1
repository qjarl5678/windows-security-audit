# -*- coding: utf-8 -*-
# Account Security Check Script
# KISA Windows Security Assessment - Account Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Account Security Check Started ===" -ForegroundColor Yellow

# W-01: Administrator account name change
Write-Progress -Activity "Account Security" -Status "W-01: Administrator account name" -PercentComplete 5
try {
	$adminAccount = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" }
	if ($adminAccount) {
		if ($adminAccount.Name -eq "Administrator") {
			Save-Result -Category "Account Security" -ItemCode "W-01" -Item "Administrator account name change" -Status "FAIL" -Details "Default 'Administrator' name in use" -Risk "HIGH"
			Write-Host "   [W-01] Administrator account uses default name" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-01" -Item "Administrator account name change" -Status "PASS" -Details "Account name changed to: $($adminAccount.Name)" -Risk "LOW"
			Write-Host "   [W-01] Administrator account name changed: $($adminAccount.Name)" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-01" -Item "Administrator account name change" -Status "WARNING" -Details "Unable to find Administrator account" -Risk "MEDIUM"
		Write-Host "   [W-01] Unable to find Administrator account" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-01" -Item "Administrator account name change" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-01] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-02: Guest account disabled
Write-Progress -Activity "Account Security" -Status "W-02: Guest account" -PercentComplete 10
try {
	$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
	if ($guest -and $guest.Enabled) {
		Save-Result -Category "Account Security" -ItemCode "W-02" -Item "Guest account disabled" -Status "FAIL" -Details "Enabled" -Risk "HIGH"
		Write-Host "   [W-02] Guest account is enabled" -ForegroundColor Red
	} elseif ($guest) {
		Save-Result -Category "Account Security" -ItemCode "W-02" -Item "Guest account disabled" -Status "PASS" -Details "Disabled" -Risk "LOW"
		Write-Host "   [W-02] Guest account is disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-02" -Item "Guest account disabled" -Status "WARNING" -Details "Guest account not found" -Risk "MEDIUM"
		Write-Host "   [W-02] Guest account not found" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-02" -Item "Guest account disabled" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-02] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-03: Remove unnecessary accounts
Write-Progress -Activity "Account Security" -Status "W-03: Unnecessary accounts" -PercentComplete 15
try {
	$users = Get-LocalUser -ErrorAction SilentlyContinue
	$inactive = @()
	$neverLoggedOn = @()
	if ($users) {
		$inactive = $users | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) }
		$neverLoggedOn = $users | Where-Object { $_.Enabled -and (-not $_.LastLogon) -and $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }
	}
	$totalUnnecessary = @($inactive).Count + @($neverLoggedOn).Count
	if ($totalUnnecessary -gt 0) {
		Save-Result -Category "Account Security" -ItemCode "W-03" -Item "Remove unnecessary accounts" -Status "WARNING" -Details "$totalUnnecessary inactive or unused accounts found" -Risk "MEDIUM"
		Write-Host "   [W-03] Unnecessary accounts found: $totalUnnecessary" -ForegroundColor Yellow
	} elseif ($users) {
		Save-Result -Category "Account Security" -ItemCode "W-03" -Item "Remove unnecessary accounts" -Status "PASS" -Details "No unnecessary accounts" -Risk "LOW"
		Write-Host "   [W-03] No unnecessary accounts" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-03" -Item "Remove unnecessary accounts" -Status "WARNING" -Details "Unable to enumerate users" -Risk "MEDIUM"
		Write-Host "   [W-03] Unable to enumerate users" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-03" -Item "Remove unnecessary accounts" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-03] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-04: Account lockout threshold
Write-Progress -Activity "Account Security" -Status "W-04: Account lockout threshold" -PercentComplete 20
try {
	$netAccounts = net accounts 2>&1 | Out-String
	$lockout = $null
	if ($netAccounts -match "Lockout threshold:\s+(\d+|Never)") {
		if ($matches[1] -eq "Never") {
			$lockout = 0
		} else {
			$lockout = [int]$matches[1]
		}
	}
	if ($null -eq $lockout) {
		Save-Result -Category "Account Security" -ItemCode "W-04" -Item "Account lockout threshold" -Status "WARNING" -Details "Unable to read policy" -Risk "MEDIUM"
		Write-Host "   [W-04] Unable to read account lockout threshold" -ForegroundColor Yellow
	} elseif ($lockout -gt 5 -or $lockout -le 0) {
		$displayValue = if ($lockout -eq 0) { "Never" } else { $lockout }
		Save-Result -Category "Account Security" -ItemCode "W-04" -Item "Account lockout threshold" -Status "FAIL" -Details "Current: $displayValue (Recommended: <= 5 and > 0)" -Risk "HIGH"
		Write-Host "   [W-04] Account lockout threshold needs attention: $displayValue" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-04" -Item "Account lockout threshold" -Status "PASS" -Details "Current: $lockout" -Risk "LOW"
		Write-Host "   [W-04] Account lockout threshold OK: $lockout" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-04" -Item "Account lockout threshold" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-04] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-05: Reversible encryption disabled
Write-Progress -Activity "Account Security" -Status "W-05: Reversible encryption" -PercentComplete 25
try {
	$seceditOutput = secedit /export /cfg temp_secpol.cfg /quiet 2>&1
	if (Test-Path "temp_secpol.cfg") {
		$reversible = Get-Content "temp_secpol.cfg" -ErrorAction SilentlyContinue | Select-String "ClearTextPassword"
		if ($reversible -and $reversible -match "ClearTextPassword\s*=\s*1") {
			Save-Result -Category "Account Security" -ItemCode "W-05" -Item "Reversible encryption disabled" -Status "FAIL" -Details "Reversible encryption is enabled" -Risk "HIGH"
			Write-Host "   [W-05] Reversible encryption is enabled" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-05" -Item "Reversible encryption disabled" -Status "PASS" -Details "Reversible encryption is disabled" -Risk "LOW"
			Write-Host "   [W-05] Reversible encryption is disabled" -ForegroundColor Green
		}
		Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-05" -Item "Reversible encryption disabled" -Status "WARNING" -Details "Unable to check policy" -Risk "MEDIUM"
		Write-Host "   [W-05] Unable to check policy" -ForegroundColor Yellow
	}
} catch {
	Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	Save-Result -Category "Account Security" -ItemCode "W-05" -Item "Reversible encryption disabled" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-05] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-06: Minimum administrators
Write-Progress -Activity "Account Security" -Status "W-06: Administrators group" -PercentComplete 30
try {
	$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
	$adminCount = @($admins).Count
	if ($adminCount -eq 0 -and $null -eq $admins) {
		Save-Result -Category "Account Security" -ItemCode "W-06" -Item "Minimum administrators in group" -Status "WARNING" -Details "Unable to retrieve group members" -Risk "MEDIUM"
		Write-Host "   [W-06] Unable to retrieve Administrators group members" -ForegroundColor Yellow
	} elseif ($adminCount -gt 2) {
		Save-Result -Category "Account Security" -ItemCode "W-06" -Item "Minimum administrators in group" -Status "WARNING" -Details "$adminCount members in Administrators group (Recommended: <= 2)" -Risk "MEDIUM"
		Write-Host "   [W-06] Administrators group has many members: $adminCount" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-06" -Item "Minimum administrators in group" -Status "PASS" -Details "Member count is appropriate" -Risk "LOW"
		Write-Host "   [W-06] Administrators group member count is appropriate" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-06" -Item "Minimum administrators in group" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-06] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-46: Everyone permission not applied to anonymous
Write-Progress -Activity "Account Security" -Status "W-46: Everyone to anonymous" -PercentComplete 35
try {
	$everyoneAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "everyoneincludesanonymous" -ErrorAction SilentlyContinue
	if ($everyoneAnonymous -and $everyoneAnonymous.everyoneincludesanonymous -eq 1) {
		Save-Result -Category "Account Security" -ItemCode "W-46" -Item "Everyone permission to anonymous" -Status "FAIL" -Details "Everyone includes anonymous users" -Risk "MEDIUM"
		Write-Host "   [W-46] Everyone includes anonymous users" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-46" -Item "Everyone permission to anonymous" -Status "PASS" -Details "Everyone does not include anonymous" -Risk "LOW"
		Write-Host "   [W-46] Everyone does not include anonymous" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-46" -Item "Everyone permission to anonymous" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-46] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-47: Account lockout duration
Write-Progress -Activity "Account Security" -Status "W-47: Lockout duration" -PercentComplete 40
try {
	$netAccounts = net accounts 2>&1 | Out-String
	$lockoutDuration = $null
	if ($netAccounts -match "Lockout duration.*:\s+(\d+|Never)") {
		if ($matches[1] -eq "Never") {
			$lockoutDuration = 0
		} else {
			$lockoutDuration = [int]$matches[1]
		}
	}
	if ($null -eq $lockoutDuration) {
		Save-Result -Category "Account Security" -ItemCode "W-47" -Item "Account lockout duration" -Status "WARNING" -Details "Unable to read policy" -Risk "MEDIUM"
		Write-Host "   [W-47] Unable to read lockout duration" -ForegroundColor Yellow
	} elseif ($lockoutDuration -lt 30) {
		Save-Result -Category "Account Security" -ItemCode "W-47" -Item "Account lockout duration" -Status "FAIL" -Details "Current: $lockoutDuration minutes (Recommended: >= 30)" -Risk "MEDIUM"
		Write-Host "   [W-47] Lockout duration too short: $lockoutDuration minutes" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-47" -Item "Account lockout duration" -Status "PASS" -Details "Current: $lockoutDuration minutes" -Risk "LOW"
		Write-Host "   [W-47] Lockout duration OK: $lockoutDuration minutes" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-47" -Item "Account lockout duration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-47] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-48: Password complexity
Write-Progress -Activity "Account Security" -Status "W-48: Password complexity" -PercentComplete 45
try {
	$seceditOutput = secedit /export /cfg temp_secpol.cfg /quiet 2>&1
	if (Test-Path "temp_secpol.cfg") {
		$complexity = Get-Content "temp_secpol.cfg" -ErrorAction SilentlyContinue | Select-String "PasswordComplexity"
		if ($complexity -and $complexity -match "PasswordComplexity\s*=\s*1") {
			Save-Result -Category "Account Security" -ItemCode "W-48" -Item "Password complexity enabled" -Status "PASS" -Details "Password complexity is enabled" -Risk "LOW"
			Write-Host "   [W-48] Password complexity is enabled" -ForegroundColor Green
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-48" -Item "Password complexity enabled" -Status "FAIL" -Details "Password complexity is disabled" -Risk "MEDIUM"
			Write-Host "   [W-48] Password complexity is disabled" -ForegroundColor Red
		}
		Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-48" -Item "Password complexity enabled" -Status "WARNING" -Details "Unable to check policy" -Risk "MEDIUM"
		Write-Host "   [W-48] Unable to check policy" -ForegroundColor Yellow
	}
} catch {
	Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	Save-Result -Category "Account Security" -ItemCode "W-48" -Item "Password complexity enabled" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-48] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-49: Minimum password length
Write-Progress -Activity "Account Security" -Status "W-49: Password length" -PercentComplete 50
try {
	$netAccounts = net accounts 2>&1 | Out-String
	$minLength = $null
	if ($netAccounts -match "Minimum password length:\s+(\d+)") {
		$minLength = [int]$matches[1]
	}
	if ($null -eq $minLength) {
		Save-Result -Category "Account Security" -ItemCode "W-49" -Item "Minimum password length" -Status "WARNING" -Details "Unable to read policy" -Risk "MEDIUM"
		Write-Host "   [W-49] Unable to read minimum password length" -ForegroundColor Yellow
	} elseif ($minLength -lt 8) {
		Save-Result -Category "Account Security" -ItemCode "W-49" -Item "Minimum password length" -Status "FAIL" -Details "Current: $minLength (Recommended: >= 8)" -Risk "HIGH"
		Write-Host "   [W-49] Minimum password length too low: $minLength" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-49" -Item "Minimum password length" -Status "PASS" -Details "Current: $minLength" -Risk "LOW"
		Write-Host "   [W-49] Minimum password length OK: $minLength" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-49" -Item "Minimum password length" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-49] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-50: Maximum password age
Write-Progress -Activity "Account Security" -Status "W-50: Maximum password age" -PercentComplete 55
try {
	$netAccounts = net accounts 2>&1 | Out-String
	if ($netAccounts -match "Maximum password age.*:\s+(\d+|Unlimited)") {
		$maxAge = $matches[1]
		if ($maxAge -eq "Unlimited" -or [int]$maxAge -gt 90) {
			Save-Result -Category "Account Security" -ItemCode "W-50" -Item "Maximum password age" -Status "FAIL" -Details "Current: $maxAge (Recommended: <= 90 days)" -Risk "MEDIUM"
			Write-Host "   [W-50] Maximum password age too long: $maxAge" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-50" -Item "Maximum password age" -Status "PASS" -Details "Current: $maxAge days" -Risk "LOW"
			Write-Host "   [W-50] Maximum password age OK: $maxAge days" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-50" -Item "Maximum password age" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-50] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-51: Minimum password age
Write-Progress -Activity "Account Security" -Status "W-51: Minimum password age" -PercentComplete 60
try {
	$netAccounts = net accounts 2>&1 | Out-String
	if ($netAccounts -match "Minimum password age.*:\s+(\d+)") {
		$minAge = [int]$matches[1]
		if ($minAge -eq 0) {
			Save-Result -Category "Account Security" -ItemCode "W-51" -Item "Minimum password age" -Status "FAIL" -Details "Current: 0 days (Recommended: >= 1 day)" -Risk "MEDIUM"
			Write-Host "   [W-51] Minimum password age not set" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-51" -Item "Minimum password age" -Status "PASS" -Details "Current: $minAge days" -Risk "LOW"
			Write-Host "   [W-51] Minimum password age OK: $minAge days" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-51" -Item "Minimum password age" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-51] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-52: Don't display last username
Write-Progress -Activity "Account Security" -Status "W-52: Last username display" -PercentComplete 65
try {
	$regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
	if ($regValue -and $regValue.DontDisplayLastUserName -eq 1) {
		Save-Result -Category "Account Security" -ItemCode "W-52" -Item "Don't display last username" -Status "PASS" -Details "Last username is hidden" -Risk "LOW"
		Write-Host "   [W-52] Last username display disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-52" -Item "Don't display last username" -Status "FAIL" -Details "Last username is shown at logon" -Risk "MEDIUM"
		Write-Host "   [W-52] Last username display enabled" -ForegroundColor Red
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-52" -Item "Don't display last username" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-52] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-53: Allow local logon
Write-Progress -Activity "Account Security" -Status "W-53: Local logon rights" -PercentComplete 70
try {
	$seceditOutput = secedit /export /cfg temp_secpol.cfg /quiet 2>&1
	if (Test-Path "temp_secpol.cfg") {
		$logonRight = Get-Content "temp_secpol.cfg" -ErrorAction SilentlyContinue | Select-String "SeInteractiveLogonRight"
		if ($logonRight) {
			$sids = $logonRight -replace ".*= ", ""
			$vulnerable = $false
			$vulnerableGroups = @()

			if ($sids -match "S-1-5-32-545") {  # Users
				$vulnerable = $true
				$vulnerableGroups += "Users"
			}
			if ($sids -match "S-1-5-32-551") {  # Backup Operators
				$vulnerable = $true
				$vulnerableGroups += "Backup Operators"
			}

			if ($vulnerable) {
				Save-Result -Category "Account Security" -ItemCode "W-53" -Item "Restrict local logon" -Status "FAIL" -Details "$($vulnerableGroups -join ', ') group(s) have logon rights" -Risk "HIGH"
				Write-Host "   [W-53] Local logon rights too permissive: $($vulnerableGroups -join ', ')" -ForegroundColor Red
			} else {
				Save-Result -Category "Account Security" -ItemCode "W-53" -Item "Restrict local logon" -Status "PASS" -Details "Appropriate groups only" -Risk "LOW"
				Write-Host "   [W-53] Local logon rights OK" -ForegroundColor Green
			}
		}
		Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-53" -Item "Restrict local logon" -Status "WARNING" -Details "Unable to export security policy" -Risk "MEDIUM"
		Write-Host "   [W-53] Unable to export security policy" -ForegroundColor Yellow
	}
} catch {
	Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	Save-Result -Category "Account Security" -ItemCode "W-53" -Item "Restrict local logon" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-53] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-54: Anonymous SID/Name translation
Write-Progress -Activity "Account Security" -Status "W-54: Anonymous SID translation" -PercentComplete 75
try {
	$seceditOutput = secedit /export /cfg temp_secpol.cfg /quiet 2>&1
	if (Test-Path "temp_secpol.cfg") {
		$lsaAnonymousNameLookup = Get-Content "temp_secpol.cfg" -ErrorAction SilentlyContinue | Select-String "LSAAnonymousNameLookup"
		if ($lsaAnonymousNameLookup -and $lsaAnonymousNameLookup -match "LSAAnonymousNameLookup\s*=\s*1") {
			Save-Result -Category "Account Security" -ItemCode "W-54" -Item "Disable anonymous SID/Name translation" -Status "FAIL" -Details "Anonymous SID/Name translation allowed" -Risk "MEDIUM"
			Write-Host "   [W-54] Anonymous SID/Name translation allowed" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-54" -Item "Disable anonymous SID/Name translation" -Status "PASS" -Details "Anonymous SID/Name translation disabled" -Risk "LOW"
			Write-Host "   [W-54] Anonymous SID/Name translation disabled" -ForegroundColor Green
		}
		Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-54" -Item "Disable anonymous SID/Name translation" -Status "WARNING" -Details "Unable to check policy" -Risk "MEDIUM"
		Write-Host "   [W-54] Unable to check policy" -ForegroundColor Yellow
	}
} catch {
	Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	Save-Result -Category "Account Security" -ItemCode "W-54" -Item "Disable anonymous SID/Name translation" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-54] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-55: Password history
Write-Progress -Activity "Account Security" -Status "W-55: Password history" -PercentComplete 80
try {
	$netAccounts = net accounts 2>&1 | Out-String
	if ($netAccounts -match "Length of password history.*:\s+(\d+|None)") {
		$history = $matches[1]
		if ($history -eq "None" -or [int]$history -lt 12) {
			Save-Result -Category "Account Security" -ItemCode "W-55" -Item "Password history" -Status "FAIL" -Details "Current: $history (Recommended: >= 12)" -Risk "MEDIUM"
			Write-Host "   [W-55] Password history insufficient: $history" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -ItemCode "W-55" -Item "Password history" -Status "PASS" -Details "Current: $history passwords" -Risk "LOW"
			Write-Host "   [W-55] Password history OK: $history passwords" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-55" -Item "Password history" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-55] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-56: Limit blank password use
Write-Progress -Activity "Account Security" -Status "W-56: Blank password restriction" -PercentComplete 85
try {
	$limitBlankPassword = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue
	if ($limitBlankPassword -and $limitBlankPassword.LimitBlankPasswordUse -eq 1) {
		Save-Result -Category "Account Security" -ItemCode "W-56" -Item "Limit blank password use" -Status "PASS" -Details "Blank passwords restricted to console logon only" -Risk "LOW"
		Write-Host "   [W-56] Blank password use is restricted" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-56" -Item "Limit blank password use" -Status "FAIL" -Details "Blank passwords can be used from network" -Risk "MEDIUM"
		Write-Host "   [W-56] Blank password use is not restricted" -ForegroundColor Red
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-56" -Item "Limit blank password use" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-56] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-57: Remote Desktop Users group restriction
Write-Progress -Activity "Account Security" -Status "W-57: Remote Desktop Users" -PercentComplete 90
try {
	$rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
	$rdpCount = @($rdpUsers).Count
	if ($rdpCount -gt 3) {
		Save-Result -Category "Account Security" -ItemCode "W-57" -Item "Restrict Remote Desktop Users" -Status "WARNING" -Details "$rdpCount members in Remote Desktop Users group" -Risk "MEDIUM"
		Write-Host "   [W-57] Many users in Remote Desktop Users group: $rdpCount" -ForegroundColor Yellow
	} elseif ($rdpCount -ge 0) {
		Save-Result -Category "Account Security" -ItemCode "W-57" -Item "Restrict Remote Desktop Users" -Status "PASS" -Details "Remote Desktop Users membership is appropriate" -Risk "LOW"
		Write-Host "   [W-57] Remote Desktop Users group OK" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-57" -Item "Restrict Remote Desktop Users" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-57] Check failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-42: SAM anonymous enumeration
Write-Progress -Activity "Account Security" -Status "W-42: SAM anonymous enumeration" -PercentComplete 95
try {
	$restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "restrictanonymous" -ErrorAction SilentlyContinue
	$restrictAnonymousSam = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "restrictanonymoussam" -ErrorAction SilentlyContinue

	$vulnerable = $false
	if (!$restrictAnonymous -or $restrictAnonymous.restrictanonymous -eq 0) {
		$vulnerable = $true
	}
	if (!$restrictAnonymousSam -or $restrictAnonymousSam.restrictanonymoussam -ne 1) {
		$vulnerable = $true
	}

	if ($vulnerable) {
		Save-Result -Category "Account Security" -ItemCode "W-42" -Item "Restrict SAM anonymous enumeration" -Status "FAIL" -Details "Anonymous SAM enumeration allowed" -Risk "HIGH"
		Write-Host "   [W-42] SAM anonymous enumeration allowed" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -ItemCode "W-42" -Item "Restrict SAM anonymous enumeration" -Status "PASS" -Details "Anonymous SAM enumeration blocked" -Risk "LOW"
		Write-Host "   [W-42] SAM anonymous enumeration blocked" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -ItemCode "W-42" -Item "Restrict SAM anonymous enumeration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-42] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Account Security" -Completed
Write-Host "=== Account Security Check Completed ===" -ForegroundColor Yellow
