# -*- coding: utf-8 -*-
# Service Security Check Script
# KISA Windows Security Assessment - Service Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Service Security Check Started ===" -ForegroundColor Yellow

# W-07: Share permissions and user groups
Write-Progress -Activity "Service Security" -Status "W-07: Share permissions" -PercentComplete 5
try {
	$shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*$" }
	$vulnerableShares = @()

	foreach ($share in $shares) {
		try {
			$shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
			$everyoneAccess = $shareAccess | Where-Object { $_.AccountName -eq "Everyone" }
			if ($everyoneAccess) {
				$vulnerableShares += $share.Name
			}
		} catch {}
	}

	if ($vulnerableShares.Count -gt 0) {
		Save-Result -Category "Service Security" -ItemCode "W-07" -Item "Share permissions and user groups" -Status "FAIL" -Details "$($vulnerableShares.Count) shares with Everyone permission: $($vulnerableShares -join ', ')" -Risk "HIGH"
		Write-Host "   [W-07] Shares with Everyone permission: $($vulnerableShares.Count)" -ForegroundColor Red
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-07" -Item "Share permissions and user groups" -Status "PASS" -Details "No shares with Everyone permission" -Risk "LOW"
		Write-Host "   [W-07] Share permissions are secure" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-07" -Item "Share permissions and user groups" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-07] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-08: Remove default hard disk shares
Write-Progress -Activity "Service Security" -Status "W-08: Default shares" -PercentComplete 10
try {
	$adminShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$" -and $_.Name -match '^[A-Z]\$' }
	if ($adminShares -and $adminShares.Count -gt 0) {
		Save-Result -Category "Service Security" -ItemCode "W-08" -Item "Remove default hard disk shares" -Status "WARNING" -Details "$($adminShares.Count) administrative shares found" -Risk "MEDIUM"
		Write-Host "   [W-08] Administrative shares found: $($adminShares.Count)" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-08" -Item "Remove default hard disk shares" -Status "PASS" -Details "No default administrative shares" -Risk "LOW"
		Write-Host "   [W-08] No default administrative shares" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-08" -Item "Remove default hard disk shares" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-08] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-09: Remove unnecessary services
Write-Progress -Activity "Service Security" -Status "W-09: Unnecessary services" -PercentComplete 15
try {
	$riskyServices = @(
		"Telnet", "TlntSvr", "SNMP", "MSFTPSVC", "SimpleT CPSvc",
		"RpcLocator", "RemoteRegistry", "RemoteAccess", "Messenger"
	)
	$foundRiskyServices = @()

	foreach ($serviceName in $riskyServices) {
		$svc = Get-Service -Name "*$serviceName*" -ErrorAction SilentlyContinue
		if ($svc) {
			foreach ($service in $svc) {
				if ($service.Status -eq "Running") {
					$foundRiskyServices += $service.Name
				}
			}
		}
	}

	if ($foundRiskyServices.Count -gt 0) {
		Save-Result -Category "Service Security" -ItemCode "W-09" -Item "Remove unnecessary services" -Status "FAIL" -Details "$($foundRiskyServices.Count) risky services running: $($foundRiskyServices -join ', ')" -Risk "HIGH"
		Write-Host "   [W-09] Risky services running: $($foundRiskyServices.Count)" -ForegroundColor Red
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-09" -Item "Remove unnecessary services" -Status "PASS" -Details "No risky services running" -Risk "LOW"
		Write-Host "   [W-09] No risky services running" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-09" -Item "Remove unnecessary services" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-09] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-24: NetBIOS binding service
Write-Progress -Activity "Service Security" -Status "W-24: NetBIOS service" -PercentComplete 20
try {
	$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled -eq $true }
	$vulnerable = $false
	$vulnerableCount = 0

	foreach ($adapter in $adapters) {
		# TcpipNetbiosOptions: 0 = Default (DHCP), 1 = Enabled, 2 = Disabled
		if ($adapter.TcpipNetbiosOptions -eq 0 -or $adapter.TcpipNetbiosOptions -eq 1) {
			$vulnerable = $true
			$vulnerableCount++
		}
	}

	if ($vulnerable) {
		Save-Result -Category "Service Security" -ItemCode "W-24" -Item "NetBIOS binding service" -Status "FAIL" -Details "NetBIOS enabled on $vulnerableCount adapters" -Risk "HIGH"
		Write-Host "   [W-24] NetBIOS enabled on $vulnerableCount adapters" -ForegroundColor Red
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-24" -Item "NetBIOS binding service" -Status "PASS" -Details "NetBIOS disabled on all adapters" -Risk "LOW"
		Write-Host "   [W-24] NetBIOS disabled on all adapters" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-24" -Item "NetBIOS binding service" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-24] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-25: FTP service running check
Write-Progress -Activity "Service Security" -Status "W-25: FTP service" -PercentComplete 25
try {
	$ftpServices = Get-Service -Name "*ftp*" -ErrorAction SilentlyContinue
	$ftpRunning = $false
	$runningFtpServices = @()

	foreach ($service in $ftpServices) {
		if ($service.Status -eq "Running") {
			$ftpRunning = $true
			$runningFtpServices += $service.Name
		}
	}

	if ($ftpRunning) {
		Save-Result -Category "Service Security" -ItemCode "W-25" -Item "FTP service check" -Status "FAIL" -Details "FTP service running: $($runningFtpServices -join ', ')" -Risk "HIGH"
		Write-Host "   [W-25] FTP service is running" -ForegroundColor Red
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-25" -Item "FTP service check" -Status "PASS" -Details "FTP service stopped or not installed" -Risk "LOW"
		Write-Host "   [W-25] FTP service stopped or not installed" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-25" -Item "FTP service check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-25] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-26: FTP directory access permissions
Write-Progress -Activity "Service Security" -Status "W-26: FTP directory permissions" -PercentComplete 30
try {
	$ftpService = Get-Service -Name "*ftp*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object -First 1

	if ($ftpService) {
		$ftpRootPaths = @("C:\inetpub\ftproot", "D:\ftproot", "C:\ftproot")
		$vulnerableFtpDirs = @()

		foreach ($path in $ftpRootPaths) {
			if (Test-Path $path) {
				$acl = Get-Acl $path -ErrorAction SilentlyContinue
				$everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }
				if ($everyoneAccess) {
					$vulnerableFtpDirs += $path
				}
			}
		}

		if ($vulnerableFtpDirs.Count -gt 0) {
			Save-Result -Category "Service Security" -ItemCode "W-26" -Item "FTP directory access permissions" -Status "FAIL" -Details "FTP directories with Everyone permission: $($vulnerableFtpDirs -join ', ')" -Risk "HIGH"
			Write-Host "   [W-26] FTP directories with weak permissions found" -ForegroundColor Red
		} else {
			Save-Result -Category "Service Security" -ItemCode "W-26" -Item "FTP directory access permissions" -Status "PASS" -Details "FTP directory permissions are secure" -Risk "LOW"
			Write-Host "   [W-26] FTP directory permissions are secure" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-26" -Item "FTP directory access permissions" -Status "PASS" -Details "FTP service not running" -Risk "LOW"
		Write-Host "   [W-26] FTP service not running" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-26" -Item "FTP directory access permissions" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-26] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-27: Anonymous FTP disabled
Write-Progress -Activity "Service Security" -Status "W-27: Anonymous FTP" -PercentComplete 35
try {
	$ftpService = Get-Service -Name "*ftp*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object -First 1

	if ($ftpService) {
		# Check IIS FTP configuration (if available)
		$ftpAnonymousEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp\FTPService" -Name "AllowAnonymous" -ErrorAction SilentlyContinue

		if ($ftpAnonymousEnabled -and $ftpAnonymousEnabled.AllowAnonymous -eq 1) {
			Save-Result -Category "Service Security" -ItemCode "W-27" -Item "Anonymous FTP disabled" -Status "FAIL" -Details "Anonymous FTP is enabled" -Risk "HIGH"
			Write-Host "   [W-27] Anonymous FTP is enabled" -ForegroundColor Red
		} else {
			Save-Result -Category "Service Security" -ItemCode "W-27" -Item "Anonymous FTP disabled" -Status "PASS" -Details "Anonymous FTP appears to be disabled" -Risk "LOW"
			Write-Host "   [W-27] Anonymous FTP appears to be disabled" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-27" -Item "Anonymous FTP disabled" -Status "PASS" -Details "FTP service not running" -Risk "LOW"
		Write-Host "   [W-27] FTP service not running" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-27" -Item "Anonymous FTP disabled" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-27] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-28: FTP access control
Write-Progress -Activity "Service Security" -Status "W-28: FTP access control" -PercentComplete 40
try {
	$ftpService = Get-Service -Name "*ftp*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object -First 1

	if ($ftpService) {
		# Check if FTP is bound to all interfaces (0.0.0.0)
		$netstat = netstat -an | Select-String ":21\s" | Out-String
		if ($netstat -match "0\.0\.0\.0:21") {
			Save-Result -Category "Service Security" -ItemCode "W-28" -Item "FTP access control" -Status "WARNING" -Details "FTP listening on all interfaces (0.0.0.0)" -Risk "MEDIUM"
			Write-Host "   [W-28] FTP listening on all interfaces" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Service Security" -ItemCode "W-28" -Item "FTP access control" -Status "PASS" -Details "FTP access appears to be restricted" -Risk "LOW"
			Write-Host "   [W-28] FTP access appears to be restricted" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-28" -Item "FTP access control" -Status "PASS" -Details "FTP service not running" -Risk "LOW"
		Write-Host "   [W-28] FTP service not running" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-28" -Item "FTP access control" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-28] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-29: DNS Zone Transfer settings
Write-Progress -Activity "Service Security" -Status "W-29: DNS Zone Transfer" -PercentComplete 45
try {
	$dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

	if ($dnsService -and $dnsService.Status -eq "Running") {
		# Check DNS zones for Zone Transfer settings
		$dnsZones = Get-DnsServerZone -ErrorAction SilentlyContinue
		$vulnerableZones = @()

		foreach ($zone in $dnsZones) {
			if ($zone.SecureSecondaries -eq "NoTransfer") {
				# Secure - no transfer allowed
			} elseif ($zone.SecureSecondaries -eq "TransferAnyServer") {
				$vulnerableZones += $zone.ZoneName
			}
		}

		if ($vulnerableZones.Count -gt 0) {
			Save-Result -Category "Service Security" -ItemCode "W-29" -Item "DNS Zone Transfer settings" -Status "FAIL" -Details "$($vulnerableZones.Count) zones allow any server transfer" -Risk "HIGH"
			Write-Host "   [W-29] DNS zones allow unrestricted transfer: $($vulnerableZones.Count)" -ForegroundColor Red
		} else {
			Save-Result -Category "Service Security" -ItemCode "W-29" -Item "DNS Zone Transfer settings" -Status "PASS" -Details "DNS zone transfer is restricted" -Risk "LOW"
			Write-Host "   [W-29] DNS zone transfer is restricted" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-29" -Item "DNS Zone Transfer settings" -Status "PASS" -Details "DNS service not running" -Risk "LOW"
		Write-Host "   [W-29] DNS service not running" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-29" -Item "DNS Zone Transfer settings" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-29] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-30: RDS (Remote Data Services) removed
Write-Progress -Activity "Service Security" -Status "W-30: RDS removal" -PercentComplete 50
try {
	$rdsRegPath = "HKLM:\SOFTWARE\Microsoft\DataFactory\HandlerInfo"
	$rdsExists = Test-Path $rdsRegPath

	if ($rdsExists) {
		Save-Result -Category "Service Security" -ItemCode "W-30" -Item "RDS removal" -Status "FAIL" -Details "RDS registry keys exist" -Risk "HIGH"
		Write-Host "   [W-30] RDS is installed" -ForegroundColor Red
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-30" -Item "RDS removal" -Status "PASS" -Details "RDS not found" -Risk "LOW"
		Write-Host "   [W-30] RDS not found" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-30" -Item "RDS removal" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-30] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-60: SNMP service check
Write-Progress -Activity "Service Security" -Status "W-60: SNMP service" -PercentComplete 55
try {
	$snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

	if ($snmpService -and $snmpService.Status -eq "Running") {
		Save-Result -Category "Service Security" -ItemCode "W-60" -Item "SNMP service check" -Status "WARNING" -Details "SNMP service is running" -Risk "MEDIUM"
		Write-Host "   [W-60] SNMP service is running" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-60" -Item "SNMP service check" -Status "PASS" -Details "SNMP service stopped or not installed" -Risk "LOW"
		Write-Host "   [W-60] SNMP service stopped or not installed" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-60" -Item "SNMP service check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-60] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-61: SNMP community string complexity
Write-Progress -Activity "Service Security" -Status "W-61: SNMP community string" -PercentComplete 60
try {
	$snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

	if ($snmpService -and $snmpService.Status -eq "Running") {
		$snmpCommunities = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction SilentlyContinue
		$weakCommunities = @()

		if ($snmpCommunities) {
			$communityNames = $snmpCommunities.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | Select-Object -ExpandProperty Name
			foreach ($community in $communityNames) {
				if ($community -in @("public", "private", "community", "snmp")) {
					$weakCommunities += $community
				}
			}
		}

		if ($weakCommunities.Count -gt 0) {
			Save-Result -Category "Service Security" -ItemCode "W-61" -Item "SNMP community string complexity" -Status "FAIL" -Details "Weak community strings found: $($weakCommunities -join ', ')" -Risk "MEDIUM"
			Write-Host "   [W-61] Weak SNMP community strings found" -ForegroundColor Red
		} else {
			Save-Result -Category "Service Security" -ItemCode "W-61" -Item "SNMP community string complexity" -Status "PASS" -Details "No weak community strings found" -Risk "LOW"
			Write-Host "   [W-61] SNMP community strings appear secure" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-61" -Item "SNMP community string complexity" -Status "PASS" -Details "SNMP service not running" -Risk "LOW"
		Write-Host "   [W-61] SNMP service not running" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-61" -Item "SNMP community string complexity" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-61] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-62: SNMP access control
Write-Progress -Activity "Service Security" -Status "W-62: SNMP access control" -PercentComplete 65
try {
	$snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

	if ($snmpService -and $snmpService.Status -eq "Running") {
		$snmpPermittedManagers = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" -ErrorAction SilentlyContinue

		if ($snmpPermittedManagers) {
			$managerCount = ($snmpPermittedManagers.PSObject.Properties | Where-Object { $_.Name -match "^\d+$" }).Count
			if ($managerCount -eq 0) {
				Save-Result -Category "Service Security" -ItemCode "W-62" -Item "SNMP access control" -Status "FAIL" -Details "SNMP accepts requests from any host" -Risk "MEDIUM"
				Write-Host "   [W-62] SNMP accepts requests from any host" -ForegroundColor Red
			} else {
				Save-Result -Category "Service Security" -ItemCode "W-62" -Item "SNMP access control" -Status "PASS" -Details "SNMP access is restricted to $managerCount hosts" -Risk "LOW"
				Write-Host "   [W-62] SNMP access is restricted" -ForegroundColor Green
			}
		} else {
			Save-Result -Category "Service Security" -ItemCode "W-62" -Item "SNMP access control" -Status "WARNING" -Details "Unable to check SNMP access control" -Risk "MEDIUM"
			Write-Host "   [W-62] Unable to check SNMP access control" -ForegroundColor Yellow
		}
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-62" -Item "SNMP access control" -Status "PASS" -Details "SNMP service not running" -Risk "LOW"
		Write-Host "   [W-62] SNMP service not running" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-62" -Item "SNMP access control" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-62] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-63: DNS service check
Write-Progress -Activity "Service Security" -Status "W-63: DNS service" -PercentComplete 70
try {
	$dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

	if ($dnsService -and $dnsService.Status -eq "Running") {
		Save-Result -Category "Service Security" -ItemCode "W-63" -Item "DNS service check" -Status "WARNING" -Details "DNS service is running" -Risk "MEDIUM"
		Write-Host "   [W-63] DNS service is running" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-63" -Item "DNS service check" -Status "PASS" -Details "DNS service stopped or not installed" -Risk "LOW"
		Write-Host "   [W-63] DNS service stopped or not installed" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-63" -Item "DNS service check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-63] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-64: HTTP/FTP/SMTP banner hiding
Write-Progress -Activity "Service Security" -Status "W-64: Service banners" -PercentComplete 75
try {
	$bannersHidden = $true
	$exposedServices = @()

	# Check HTTP banner (IIS)
	$httpBanner = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "DisableServerHeader" -ErrorAction SilentlyContinue
	if (!$httpBanner -or $httpBanner.DisableServerHeader -ne 1) {
		$exposedServices += "HTTP"
		$bannersHidden = $false
	}

	# Check SMTP banner
	$smtpService = Get-Service -Name "*smtp*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
	if ($smtpService) {
		$exposedServices += "SMTP"
		$bannersHidden = $false
	}

	if (!$bannersHidden) {
		Save-Result -Category "Service Security" -ItemCode "W-64" -Item "Service banner hiding" -Status "WARNING" -Details "Service banners exposed: $($exposedServices -join ', ')" -Risk "LOW"
		Write-Host "   [W-64] Service banners exposed" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-64" -Item "Service banner hiding" -Status "PASS" -Details "Service banners appear to be hidden" -Risk "LOW"
		Write-Host "   [W-64] Service banners appear to be hidden" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-64" -Item "Service banner hiding" -Status "WARNING" -Details $_.Exception.Message -Risk "LOW"
	Write-Host "   [W-64] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-65: Telnet security settings
Write-Progress -Activity "Service Security" -Status "W-65: Telnet security" -PercentComplete 80
try {
	$telnetService = Get-Service -Name "*telnet*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }

	if ($telnetService) {
		Save-Result -Category "Service Security" -ItemCode "W-65" -Item "Telnet security settings" -Status "FAIL" -Details "Telnet service is running (inherently insecure)" -Risk "MEDIUM"
		Write-Host "   [W-65] Telnet service is running" -ForegroundColor Red
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-65" -Item "Telnet security settings" -Status "PASS" -Details "Telnet service stopped or not installed" -Risk "LOW"
		Write-Host "   [W-65] Telnet service stopped or not installed" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-65" -Item "Telnet security settings" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-65] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-66: Unnecessary ODBC/OLE-DB data sources and drivers
Write-Progress -Activity "Service Security" -Status "W-66: ODBC data sources" -PercentComplete 85
try {
	$systemDSN = Get-ItemProperty -Path "HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources" -ErrorAction SilentlyContinue
	$dsnCount = 0

	if ($systemDSN) {
		$dsnCount = ($systemDSN.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
	}

	if ($dsnCount -gt 5) {
		Save-Result -Category "Service Security" -ItemCode "W-66" -Item "Unnecessary ODBC/OLE-DB data sources" -Status "WARNING" -Details "$dsnCount system DSNs configured" -Risk "MEDIUM"
		Write-Host "   [W-66] Many ODBC data sources configured: $dsnCount" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-66" -Item "Unnecessary ODBC/OLE-DB data sources" -Status "PASS" -Details "ODBC data sources appear minimal" -Risk "LOW"
		Write-Host "   [W-66] ODBC data sources appear minimal" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-66" -Item "Unnecessary ODBC/OLE-DB data sources" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-66] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# W-68: Scheduled tasks inspection
Write-Progress -Activity "Service Security" -Status "W-68: Scheduled tasks" -PercentComplete 95
try {
	$scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" }
	$suspiciousTasks = @()

	$suspiciousPatterns = @("cmd.exe", "powershell.exe", "wscript", "cscript", "mshta", "regsvr32", "rundll32")

	foreach ($task in $scheduledTasks) {
		$action = $task.Actions | Select-Object -First 1
		if ($action) {
			$executable = $action.Execute
			$arguments = $action.Arguments

			foreach ($pattern in $suspiciousPatterns) {
				if ($executable -like "*$pattern*" -or $arguments -like "*$pattern*") {
					$suspiciousTasks += $task.TaskName
					break
				}
			}
		}
	}

	if ($suspiciousTasks.Count -gt 0) {
		Save-Result -Category "Service Security" -ItemCode "W-68" -Item "Scheduled tasks inspection" -Status "WARNING" -Details "$($suspiciousTasks.Count) potentially suspicious tasks found" -Risk "MEDIUM"
		Write-Host "   [W-68] Potentially suspicious scheduled tasks: $($suspiciousTasks.Count)" -ForegroundColor Yellow
	} else {
		Save-Result -Category "Service Security" -ItemCode "W-68" -Item "Scheduled tasks inspection" -Status "PASS" -Details "No obviously suspicious tasks found" -Risk "LOW"
		Write-Host "   [W-68] No obviously suspicious tasks found" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Service Security" -ItemCode "W-68" -Item "Scheduled tasks inspection" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-68] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Progress -Activity "Service Security" -Completed
Write-Host "=== Service Security Check Completed ===" -ForegroundColor Yellow
