# -*- coding: utf-8 -*-
# Log Security Check Script
# KISA Windows Security Assessment - Log Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Log Security Check Started ===" -ForegroundColor Yellow

# W-34: Regular log review and reporting
Write-Progress -Activity "Log Security" -Status "W-34: Log review" -PercentComplete 10
try {
	# Check for recent security events
	$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue
	if ($ev -and $ev.Count -gt 0) {
		Save-Result -Category "Log Security" -ItemCode "W-34" -Item "Regular log review and reporting" -Status "PASS" -Details "Security logs are being generated ($($ev.Count) events in last 7 days)" -Risk "LOW"
		Write-Host "   [W-34] Security logs are active" -ForegroundColor Green
	} else {
		Save-Result -Category "Log Security" -ItemCode "W-34" -Item "Regular log review and reporting" -Status "WARNING" -Details "No recent security events or unable to access logs" -Risk "MEDIUM"
		Write-Host "   [W-34] No recent security events found" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Log Security" -ItemCode "W-34" -Item "Regular log review and reporting" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-34] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-35: Remote registry path access
Write-Progress -Activity "Log Security" -Status "W-35: Remote registry" -PercentComplete 20
try {
	$remoteRegistryService = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue

	if ($remoteRegistryService -and $remoteRegistryService.Status -eq "Running") {
		Save-Result -Category "Log Security" -ItemCode "W-35" -Item "Remote registry path access" -Status "FAIL" -Details "Remote Registry service is running" -Risk "HIGH"
		Write-Host "   [W-35] Remote Registry service is running" -ForegroundColor Red
	} else {
		Save-Result -Category "Log Security" -ItemCode "W-35" -Item "Remote registry path access" -Status "PASS" -Details "Remote Registry service is stopped or disabled" -Risk "LOW"
		Write-Host "   [W-35] Remote Registry service is stopped" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Log Security" -ItemCode "W-35" -Item "Remote registry path access" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-35] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-69: System logging configuration per policy
Write-Progress -Activity "Log Security" -Status "W-69: Logging configuration" -PercentComplete 30
try {
	$auditOutput = auditpol /get /category:* 2>&1 | Out-String
	$criticalCategories = @("Logon/Logoff", "Account Logon", "Account Management", "Policy Change", "Privilege Use", "System")
	$disabled = @()
	$enabled = 0

	foreach ($cat in $criticalCategories) {
		if ($auditOutput -match "$cat.*No Auditing") {
			$disabled += $cat
		} elseif ($auditOutput -match "$cat.*(Success and Failure|Success|Failure)") {
			$enabled++
		}
	}

	if ($disabled.Count -gt 0) {
		Save-Result -Category "Log Security" -ItemCode "W-69" -Item "System logging configuration per policy" -Status "FAIL" -Details "$($disabled.Count) critical audit categories disabled: $($disabled -join ', ')" -Risk "MEDIUM"
		Write-Host "   [W-69] Critical audit categories disabled: $($disabled.Count)" -ForegroundColor Red
	} else {
		Save-Result -Category "Log Security" -ItemCode "W-69" -Item "System logging configuration per policy" -Status "PASS" -Details "All critical audit categories enabled" -Risk "LOW"
		Write-Host "   [W-69] All critical audit categories enabled" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Log Security" -ItemCode "W-69" -Item "System logging configuration per policy" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-69] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-70: Event log management settings
Write-Progress -Activity "Log Security" -Status "W-70: Event log size" -PercentComplete 40
try {
	$names = @("Application", "System", "Security")
	$issues = @()
	foreach ($name in $names) {
		$log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
		if ($log) {
			if ($log.MaximumSizeInBytes -lt 100MB) { $issues += "$name size is too small ($([math]::Round($log.MaximumSizeInBytes/1MB))MB)" }
			if ($log.IsLogFull) { $issues += "$name log is full" }
		}
	}
	if ($issues.Count -gt 0) {
		Save-Result -Category "Log Security" -ItemCode "W-70" -Item "Event log management settings" -Status "WARNING" -Details "$($issues.Count) issues: $($issues -join '; ')" -Risk "MEDIUM"
		Write-Host "   [W-70] Event log configuration issues found" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Log Security" -ItemCode "W-70" -Item "Event log management settings" -Status "PASS" -Details "Event log sizes are adequate" -Risk "LOW"
		Write-Host "   [W-70] Event log configuration OK" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Log Security" -ItemCode "W-70" -Item "Event log management settings" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-70] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-71: Block remote event log file access
Write-Progress -Activity "Log Security" -Status "W-71: Remote log access" -PercentComplete 50
try {
	# Check if event log files have proper ACLs
	$logPath = "$env:SystemRoot\System32\winevt\Logs"
	$logFiles = @("Security.evtx", "System.evtx", "Application.evtx")
	$vulnerableFiles = @()

	foreach ($logFile in $logFiles) {
		$fullPath = Join-Path $logPath $logFile
		if (Test-Path $fullPath) {
			$acl = Get-Acl $fullPath -ErrorAction SilentlyContinue
			# Check for network access or Everyone permissions
			$everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Read|Write" }
			$networkAccess = $acl.Access | Where-Object { $_.IdentityReference -match "NETWORK" -and $_.FileSystemRights -match "Read|Write" }

			if ($everyoneAccess -or $networkAccess) {
				$vulnerableFiles += $logFile
			}
		}
	}

	# Also check if EventLog service allows remote access
	$eventLogService = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
	$remoteAccess = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -Name "RestrictGuestAccess" -ErrorAction SilentlyContinue

	if ($vulnerableFiles.Count -gt 0) {
		Save-Result -Category "Log Security" -ItemCode "W-71" -Item "Block remote event log file access" -Status "FAIL" -Details "Event log files have weak ACLs: $($vulnerableFiles -join ', ')" -Risk "MEDIUM"
		Write-Host "   [W-71] Event log files have weak ACLs" -ForegroundColor Red
	} elseif (!$remoteAccess -or $remoteAccess.RestrictGuestAccess -ne 1) {
		Save-Result -Category "Log Security" -ItemCode "W-71" -Item "Block remote event log file access" -Status "WARNING" -Details "Guest access to event logs not restricted" -Risk "MEDIUM"
		Write-Host "   [W-71] Guest access to event logs not restricted" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Log Security" -ItemCode "W-71" -Item "Block remote event log file access" -Status "PASS" -Details "Remote event log access appears restricted" -Risk "LOW"
		Write-Host "   [W-71] Remote event log access appears restricted" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Log Security" -ItemCode "W-71" -Item "Block remote event log file access" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-71] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Security events summary (last 7 days)
Write-Progress -Activity "Log Security" -Status "Analyzing recent events" -PercentComplete 80
try {
	$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 5000 -ErrorAction SilentlyContinue
	if ($ev) {
		$failed = ($ev | Where-Object { $_.Id -eq 4625 }).Count
		$lock = ($ev | Where-Object { $_.Id -eq 4740 }).Count
		if ($failed -gt 100 -or $lock -gt 10) {
			Save-Result -Category "Log Security" -ItemCode "ANALYSIS" -Item "Security events analysis" -Status "WARNING" -Details "High failed logon attempts: $failed, Account lockouts: $lock" -Risk "MEDIUM"
			Write-Host "   [ANALYSIS] High security event activity (failed:$failed, lockouts:$lock)" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Log Security" -ItemCode "ANALYSIS" -Item "Security events analysis" -Status "PASS" -Details "Security events within normal range" -Risk "LOW"
			Write-Host "   [ANALYSIS] Security events within normal range" -ForegroundColor Green
		}
	}
} catch {
	Write-Host "   [ANALYSIS] Unable to analyze security events: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Log file integrity check
Write-Progress -Activity "Log Security" -Status "Checking log integrity" -PercentComplete 95
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
	if ($bad.Count -gt 0) {
		Save-Result -Category "Log Security" -ItemCode "INTEGRITY" -Item "Log file integrity" -Status "FAIL" -Details "Potentially corrupted logs: $($bad -join ', ')" -Risk "HIGH"
		Write-Host "   [INTEGRITY] Potentially corrupted log files detected" -ForegroundColor Red
	} else {
		Save-Result -Category "Log Security" -ItemCode "INTEGRITY" -Item "Log file integrity" -Status "PASS" -Details "Log files appear intact" -Risk "LOW"
		Write-Host "   [INTEGRITY] Log files OK" -ForegroundColor Green
	}
} catch {
	Write-Host "   [INTEGRITY] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Progress -Activity "Log Security" -Completed
Write-Host "=== Log Security Check Completed ===" -ForegroundColor Yellow
