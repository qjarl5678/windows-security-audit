# -*- coding: utf-8 -*-
# Database Security Check Script
# KISA Windows Security Assessment - Database Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Database Security Check Started ===" -ForegroundColor Yellow

# W-82: Windows authentication mode
Write-Progress -Activity "Database Security" -Status "W-82: SQL Server authentication" -PercentComplete 50
try {
	# Check if SQL Server is installed
	$sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }

	if ($sqlServices) {
		# Check SQL Server authentication mode via registry
		$sqlInstances = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue

		$mixedModeInstances = @()
		$windowsAuthInstances = @()

		if ($sqlInstances) {
			$instanceNames = $sqlInstances.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }

			foreach ($instance in $instanceNames) {
				$instanceId = $instance.Value
				$authMode = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer" -Name "LoginMode" -ErrorAction SilentlyContinue

				if ($authMode) {
					if ($authMode.LoginMode -eq 2) {
						# Mixed mode (Windows and SQL Server)
						$mixedModeInstances += $instance.Name
					} elseif ($authMode.LoginMode -eq 1) {
						# Windows Authentication only
						$windowsAuthInstances += $instance.Name
					}
				}
			}
		}

		if ($mixedModeInstances.Count -gt 0) {
			Save-Result -Category "Database Security" -ItemCode "W-82" -Item "Windows authentication mode" -Status "FAIL" -Details "SQL Server instances using mixed mode: $($mixedModeInstances -join ', ')" -Risk "MEDIUM"
			Write-Host "   [W-82] SQL Server instances using mixed mode authentication" -ForegroundColor Red
		} elseif ($windowsAuthInstances.Count -gt 0) {
			Save-Result -Category "Database Security" -ItemCode "W-82" -Item "Windows authentication mode" -Status "PASS" -Details "SQL Server using Windows authentication only" -Risk "LOW"
			Write-Host "   [W-82] SQL Server using Windows authentication" -ForegroundColor Green
		} else {
			Save-Result -Category "Database Security" -ItemCode "W-82" -Item "Windows authentication mode" -Status "WARNING" -Details "Unable to determine SQL Server authentication mode" -Risk "MEDIUM"
			Write-Host "   [W-82] Unable to determine authentication mode" -ForegroundColor Yellow
		}
	} else {
		Save-Result -Category "Database Security" -ItemCode "W-82" -Item "Windows authentication mode" -Status "PASS" -Details "SQL Server not running" -Risk "LOW"
		Write-Host "   [W-82] SQL Server not running or not installed" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Database Security" -ItemCode "W-82" -Item "Windows authentication mode" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-82] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Progress -Activity "Database Security" -Completed
Write-Host "=== Database Security Check Completed ===" -ForegroundColor Yellow
