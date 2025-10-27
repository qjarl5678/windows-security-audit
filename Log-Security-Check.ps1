# Log Security Check Script (English)
# - Detailed checks, no emojis, Save-Result guard

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Log Security Check Started ===" -ForegroundColor Yellow

Write-Progress -Activity "Log Security" -Status "Checking event log settings" -PercentComplete 20
# 1) Event log size and status
try {
	$names = @("Application","System","Security")
	$issues = @()
	foreach ($name in $names) {
		$log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
		if ($log) {
			if ($log.MaximumSizeInBytes -lt 100MB) { $issues += "$name size is too small" }
			if ($log.IsLogFull) { $issues += "$name log is full" }
		}
	}
	if ((@($issues).Count) -gt 0) {
		Save-Result -Category "Log Security" -Item "Event log configuration" -Status "WARNING" -Details (($issues -join ', ')) -Risk "MEDIUM"
		Write-Host "   Event log configuration issues found" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Log Security" -Item "Event log configuration" -Status "PASS" -Details "OK" -Risk "LOW"
		Write-Host "   Event log configuration OK" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Log Security" -Item "Event log configuration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check event logs: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Log Security" -Status "Checking audit policy" -PercentComplete 55
# 2) Audit policy (key items)
try {
	$auditOutput = auditpol /get /category:* 2>&1 | Out-String
	$categories = @("Logon/Logoff","Account Logon","Account Management","Policy Change","Privilege Use","System")
	$disabled = @()
	$enabled = 0

	foreach ($cat in $categories) {
		if ($auditOutput -match "(?m)^\s*$cat\s*$") {
			# Found category, check next lines for subcategories
			$catMatch = $auditOutput -match "(?ms)$cat.*?((?:Success and Failure|Success|Failure|No Auditing))"
			if ($auditOutput -match "$cat.*?No Auditing") {
				$disabled += $cat
			} else {
				$enabled++
			}
		}
	}

	if ((@($disabled).Count) -gt 0) {
		Save-Result -Category "Log Security" -Item "Audit policy" -Status "WARNING" -Details "Some categories not fully audited: $($disabled.Count)/$($categories.Count)" -Risk "MEDIUM"
		Write-Host "   Some audit policy categories are not fully enabled" -ForegroundColor Yellow
	} elseif ($enabled -gt 0) {
		Save-Result -Category "Log Security" -Item "Audit policy" -Status "PASS" -Details "Key categories enabled" -Risk "LOW"
		Write-Host "   Key audit policy categories enabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Log Security" -Item "Audit policy" -Status "WARNING" -Details "Unable to parse audit policy" -Risk "MEDIUM"
		Write-Host "   Unable to parse audit policy" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Log Security" -Item "Audit policy" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check audit policy: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Log Security" -Status "Analyzing last 7 days events" -PercentComplete 80
# 3) Security events summary (last 7 days)
try {
	$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 5000 -ErrorAction SilentlyContinue
	if ($ev) {
		$failed = (@($ev | Where-Object { $_.Id -eq 4625 })).Count
		$lock = (@($ev | Where-Object { $_.Id -eq 4740 })).Count
		if ($failed -gt 100 -or $lock -gt 10) {
			Save-Result -Category "Log Security" -Item "Security events" -Status "WARNING" -Details "FailedLogon:$failed, Lockouts:$lock" -Risk "MEDIUM"
			Write-Host "   Security events warning (failed:$failed, lockouts:$lock)" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Log Security" -Item "Security events" -Status "PASS" -Details "Within normal range" -Risk "LOW"
			Write-Host "   Security events within normal range" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Log Security" -Item "Security events" -Status "WARNING" -Details "Unable to get events" -Risk "MEDIUM"
		Write-Host "   Unable to get security events" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Log Security" -Item "Security events" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to analyze security events: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Log Security" -Status "Checking log file integrity" -PercentComplete 95
# 4) Log file integrity (readable check)
try {
	$paths = @(
		"$env:SystemRoot\System32\winevt\Logs\Application.evtx",
		"$env:SystemRoot\System32\winevt\Logs\System.evtx",
		"$env:SystemRoot\System32\winevt\Logs\Security.evtx"
	)
	$bad = @()
	foreach ($p in $paths) {
		if (Test-Path $p) {
			try { Get-WinEvent -Path $p -MaxEvents 1 -ErrorAction Stop | Out-Null } catch { $bad += (Split-Path $p -Leaf) }
		}
	}
	if ((@($bad).Count) -gt 0) {
		Save-Result -Category "Log Security" -Item "Log file integrity" -Status "FAIL" -Details (($bad -join ', ') + " may be corrupted") -Risk "HIGH"
		Write-Host "   Suspected corrupted log files" -ForegroundColor Red
	} else {
		Save-Result -Category "Log Security" -Item "Log file integrity" -Status "PASS" -Details "OK" -Risk "LOW"
		Write-Host "   Log files OK" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Log Security" -Item "Log file integrity" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check log file integrity: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Log Security" -Completed
Write-Host "=== Log Security Check Completed ===" -ForegroundColor Yellow