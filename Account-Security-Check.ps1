# Account Security Check Script (Restored, English)
# - Removed emojis/garbled chars
# - Local fallback for Save-Result when not defined

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Account Security Check Started ===" -ForegroundColor Yellow
Write-Progress -Activity "Account Security" -Status "Checking Administrators group" -PercentComplete 10

# 1) Administrators group membership
try {
	$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
	$adminCount = @($admins).Count
	if ($adminCount -eq 0 -and $null -eq $admins) {
		Save-Result -Category "Account Security" -Item "Administrators group members" -Status "WARNING" -Details "Unable to retrieve group members" -Risk "MEDIUM"
		Write-Host "   Unable to retrieve Administrators group members" -ForegroundColor Yellow
	} elseif ($adminCount -gt 2) {
		Save-Result -Category "Account Security" -Item "Administrators group members" -Status "WARNING" -Details "$adminCount members in Administrators" -Risk "MEDIUM"
		Write-Host "   Administrators group has many members: $adminCount" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Account Security" -Item "Administrators group members" -Status "PASS" -Details "Member count is appropriate" -Risk "LOW"
		Write-Host "   Administrators group member count is appropriate" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -Item "Administrators group check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Administrators group check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Account Security" -Status "Checking Guest account" -PercentComplete 35
# 2) Guest account status
try {
	$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
	if ($guest -and $guest.Enabled) {
		Save-Result -Category "Account Security" -Item "Guest account" -Status "FAIL" -Details "Enabled" -Risk "HIGH"
		Write-Host "   Guest account is enabled" -ForegroundColor Red
	} elseif ($guest) {
		Save-Result -Category "Account Security" -Item "Guest account" -Status "PASS" -Details "Disabled" -Risk "LOW"
		Write-Host "   Guest account is disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -Item "Guest account" -Status "WARNING" -Details "Guest account not found" -Risk "MEDIUM"
		Write-Host "   Guest account not found" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -Item "Guest account check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Guest account check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Account Security" -Status "Checking inactive users" -PercentComplete 60
# 3) Inactive users (last logon > 90 days)
try {
	$users = Get-LocalUser -ErrorAction SilentlyContinue
	$inactive = @()
	if ($users) {
		$inactive = $users | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) }
	}
	$ic = @($inactive).Count
	if ($ic -gt 0) {
		Save-Result -Category "Account Security" -Item "Inactive users" -Status "WARNING" -Details "$ic inactive users (90+ days)" -Risk "MEDIUM"
		Write-Host "   Inactive users found: $ic" -ForegroundColor Yellow
	} elseif ($users) {
		Save-Result -Category "Account Security" -Item "Inactive users" -Status "PASS" -Details "None" -Risk "LOW"
		Write-Host "   No inactive users" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -Item "Inactive users" -Status "WARNING" -Details "Unable to enumerate users" -Risk "MEDIUM"
		Write-Host "   Unable to enumerate users" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -Item "Inactive users check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Inactive users check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Account Security" -Status "Checking password policy" -PercentComplete 85
# 4) Minimum password length (local policy)
try {
	$netAccounts = net accounts 2>&1 | Out-String
	$minLength = $null
	if ($netAccounts -match "Minimum password length:\s+(\d+)") {
		$minLength = [int]$matches[1]
	}
	if ($null -eq $minLength) {
		Save-Result -Category "Account Security" -Item "Minimum password length" -Status "WARNING" -Details "Unable to read policy" -Risk "MEDIUM"
		Write-Host "   Unable to read minimum password length" -ForegroundColor Yellow
	} elseif ($minLength -lt 8) {
		Save-Result -Category "Account Security" -Item "Minimum password length" -Status "FAIL" -Details "Current: $minLength (Recommended: 8+)" -Risk "HIGH"
		Write-Host "   Minimum password length too low: $minLength" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -Item "Minimum password length" -Status "PASS" -Details "Current: $minLength" -Risk "LOW"
		Write-Host "   Minimum password length OK: $minLength" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -Item "Password policy check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Password policy check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Account Security" -Status "Checking lockout threshold" -PercentComplete 95
# 5) Account lockout threshold
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
		Save-Result -Category "Account Security" -Item "Account lockout threshold" -Status "WARNING" -Details "Unable to read policy" -Risk "MEDIUM"
		Write-Host "   Unable to read account lockout threshold" -ForegroundColor Yellow
	} elseif ($lockout -gt 5 -or $lockout -le 0) {
		$displayValue = if ($lockout -eq 0) { "Never" } else { $lockout }
		Save-Result -Category "Account Security" -Item "Account lockout threshold" -Status "WARNING" -Details "Current: $displayValue (Recommended: <= 5 and > 0)" -Risk "MEDIUM"
		Write-Host "   Account lockout threshold needs attention: $displayValue" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Account Security" -Item "Account lockout threshold" -Status "PASS" -Details "Current: $lockout" -Risk "LOW"
		Write-Host "   Account lockout threshold OK: $lockout" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -Item "Account lockout policy" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Account lockout policy check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 6) Administrator account name change check
try {
	$adminAccount = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" }
	if ($adminAccount) {
		if ($adminAccount.Name -eq "Administrator") {
			Save-Result -Category "Account Security" -Item "Administrator account name" -Status "FAIL" -Details "Default 'Administrator' name in use" -Risk "HIGH"
			Write-Host "   Administrator account uses default name" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -Item "Administrator account name" -Status "PASS" -Details "Account name changed to: $($adminAccount.Name)" -Risk "LOW"
			Write-Host "   Administrator account name changed: $($adminAccount.Name)" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Account Security" -Item "Administrator account name" -Status "WARNING" -Details "Unable to find Administrator account" -Risk "MEDIUM"
		Write-Host "   Unable to find Administrator account" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -Item "Administrator account name" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Administrator account name check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 7) Administrator password expiration
try {
	$adminAccount = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" }
	if ($adminAccount) {
		if ($adminAccount.PasswordExpires -eq $false) {
			Save-Result -Category "Account Security" -Item "Administrator password expiration" -Status "FAIL" -Details "Password never expires" -Risk "HIGH"
			Write-Host "   Administrator password never expires" -ForegroundColor Red
		} else {
			Save-Result -Category "Account Security" -Item "Administrator password expiration" -Status "PASS" -Details "Password expiration enabled" -Risk "LOW"
			Write-Host "   Administrator password expiration enabled" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "Account Security" -Item "Administrator password expiration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Administrator password expiration check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 8) Password policy details (max/min age, history)
try {
	$netAccounts = net accounts 2>&1 | Out-String

	# Max password age
	if ($netAccounts -match "Maximum password age.*:\s+(\d+|Unlimited)") {
		$maxAge = $matches[1]
		if ($maxAge -eq "Unlimited" -or [int]$maxAge -gt 90) {
			Save-Result -Category "Account Security" -Item "Maximum password age" -Status "WARNING" -Details "Current: $maxAge (Recommended: <= 90 days)" -Risk "MEDIUM"
			Write-Host "   Maximum password age too long: $maxAge" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Account Security" -Item "Maximum password age" -Status "PASS" -Details "Current: $maxAge days" -Risk "LOW"
			Write-Host "   Maximum password age OK: $maxAge days" -ForegroundColor Green
		}
	}

	# Min password age
	if ($netAccounts -match "Minimum password age.*:\s+(\d+)") {
		$minAge = [int]$matches[1]
		if ($minAge -eq 0) {
			Save-Result -Category "Account Security" -Item "Minimum password age" -Status "WARNING" -Details "Current: 0 days (Recommended: >= 1 day)" -Risk "MEDIUM"
			Write-Host "   Minimum password age not set" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Account Security" -Item "Minimum password age" -Status "PASS" -Details "Current: $minAge days" -Risk "LOW"
			Write-Host "   Minimum password age OK: $minAge days" -ForegroundColor Green
		}
	}

	# Password history
	if ($netAccounts -match "Length of password history.*:\s+(\d+|None)") {
		$history = $matches[1]
		if ($history -eq "None" -or [int]$history -lt 12) {
			Save-Result -Category "Account Security" -Item "Password history" -Status "WARNING" -Details "Current: $history (Recommended: >= 12)" -Risk "MEDIUM"
			Write-Host "   Password history insufficient: $history" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Account Security" -Item "Password history" -Status "PASS" -Details "Current: $history passwords" -Risk "LOW"
			Write-Host "   Password history OK: $history passwords" -ForegroundColor Green
		}
	}
} catch {
	Save-Result -Category "Account Security" -Item "Password policy details" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Password policy details check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 9) Last username display policy
try {
	$regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
	if ($regValue -and $regValue.DontDisplayLastUserName -eq 1) {
		Save-Result -Category "Account Security" -Item "Last username display" -Status "PASS" -Details "Last username hidden" -Risk "LOW"
		Write-Host "   Last username display disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Account Security" -Item "Last username display" -Status "FAIL" -Details "Last username shown at logon" -Risk "HIGH"
		Write-Host "   Last username display enabled" -ForegroundColor Red
	}
} catch {
	Save-Result -Category "Account Security" -Item "Last username display" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Last username display check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 10) Local logon rights check
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
				Save-Result -Category "Account Security" -Item "Local logon rights" -Status "FAIL" -Details "$($vulnerableGroups -join ', ') group(s) have logon rights" -Risk "HIGH"
				Write-Host "   Local logon rights too permissive: $($vulnerableGroups -join ', ')" -ForegroundColor Red
			} else {
				Save-Result -Category "Account Security" -Item "Local logon rights" -Status "PASS" -Details "Appropriate groups only" -Risk "LOW"
				Write-Host "   Local logon rights OK" -ForegroundColor Green
			}
		}
		Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
	} else {
		Save-Result -Category "Account Security" -Item "Local logon rights" -Status "WARNING" -Details "Unable to export security policy" -Risk "MEDIUM"
		Write-Host "   Unable to export security policy" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Account Security" -Item "Local logon rights" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Local logon rights check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 11) SAM anonymous enumeration
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
		Save-Result -Category "Account Security" -Item "SAM anonymous enumeration" -Status "FAIL" -Details "Anonymous enumeration allowed" -Risk "HIGH"
		Write-Host "   SAM anonymous enumeration allowed" -ForegroundColor Red
	} else {
		Save-Result -Category "Account Security" -Item "SAM anonymous enumeration" -Status "PASS" -Details "Anonymous enumeration blocked" -Risk "LOW"
		Write-Host "   SAM anonymous enumeration blocked" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Account Security" -Item "SAM anonymous enumeration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   SAM anonymous enumeration check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Account Security" -Completed
Write-Host "=== Account Security Check Completed ===" -ForegroundColor Yellow