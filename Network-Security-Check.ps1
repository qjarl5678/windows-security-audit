# Network Security Check Script (English)
# - Detailed checks, no emojis, Save-Result guard

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Network Security Check Started ===" -ForegroundColor Yellow

Write-Progress -Activity "Network Security" -Status "Checking listening ports" -PercentComplete 15
# 1) Risky listening ports
try {
	$danger = @(21,23,25,53,80,135,139,445,1433,3389,5432,5900)
	$open = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalPort,OwningProcess
	$open = @($open)
	$risky = $open | Where-Object { $_.LocalPort -in $danger }
	$rc = @($risky).Count
	if ($rc -gt 0) {
		Save-Result -Category "Network Security" -Item "Risky ports" -Status "WARNING" -Details "$rc listening on risky ports" -Risk "MEDIUM"
		Write-Host "   Risky listening ports: $rc" -ForegroundColor Yellow
	} elseif ($open.Count -ge 0) {
		Save-Result -Category "Network Security" -Item "Risky ports" -Status "PASS" -Details "None" -Risk "LOW"
		Write-Host "   No risky listening ports" -ForegroundColor Green
	} else {
		Save-Result -Category "Network Security" -Item "Risky ports" -Status "WARNING" -Details "Unable to enumerate connections" -Risk "MEDIUM"
		Write-Host "   Unable to enumerate connections" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -Item "Listening ports check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check listening ports: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Network Security" -Status "Checking DNS configuration" -PercentComplete 40
# 2) DNS configuration (public DNS use)
try {
	$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses }
	$pub = 0
	if ($dns) {
		foreach ($d in $dns) {
			foreach ($s in $d.ServerAddresses) {
				if ($s -match "^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1)$") { $pub++ }
			}
		}
	}
	if ($pub -gt 0) {
		Save-Result -Category "Network Security" -Item "DNS configuration" -Status "WARNING" -Details "$pub public DNS in use" -Risk "MEDIUM"
		Write-Host "   Public DNS in use: $pub" -ForegroundColor Yellow
	} elseif ($dns) {
		Save-Result -Category "Network Security" -Item "DNS configuration" -Status "PASS" -Details "Internal DNS in use" -Risk "LOW"
		Write-Host "   Internal DNS in use" -ForegroundColor Green
	} else {
		Save-Result -Category "Network Security" -Item "DNS configuration" -Status "WARNING" -Details "Unable to get DNS servers" -Risk "MEDIUM"
		Write-Host "   Unable to get DNS servers" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -Item "DNS configuration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check DNS config: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Network Security" -Status "Checking SMB shares" -PercentComplete 65
# 3) SMB shares risk
try {
	$shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*$" }
	if ($shares) {
		$riskyShares = $shares | Where-Object { $_.Path -like "*Users*" -or $_.Path -like "*Program Files*" }
		$sc = @($riskyShares).Count
		if ($sc -gt 0) {
			Save-Result -Category "Network Security" -Item "Network shares" -Status "WARNING" -Details "$sc risky shares" -Risk "MEDIUM"
			Write-Host "   Risky shares: $sc" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Network Security" -Item "Network shares" -Status "PASS" -Details "No risky shares" -Risk "LOW"
			Write-Host "   No risky shares" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Network Security" -Item "Network shares" -Status "WARNING" -Details "Unable to enumerate shares" -Risk "MEDIUM"
		Write-Host "   Unable to enumerate shares" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -Item "Network shares" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check shares: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Network Security" -Status "Checking RDP & NLA" -PercentComplete 85
# 4) RDP and NLA
try {
	$rdpProp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
	$nlaProp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
	$rdp = if ($rdpProp) { $rdpProp.fDenyTSConnections } else { $null }
	$nla = if ($nlaProp) { $nlaProp.UserAuthentication } else { $null }
	if ($rdp -eq 0 -and $nla -ne 1) {
		Save-Result -Category "Network Security" -Item "RDP/NLA" -Status "WARNING" -Details "RDP on, NLA off" -Risk "MEDIUM"
		Write-Host "   RDP enabled but NLA disabled" -ForegroundColor Yellow
	} elseif ($rdp -eq 0 -and $nla -eq 1) {
		Save-Result -Category "Network Security" -Item "RDP/NLA" -Status "PASS" -Details "RDP on, NLA on" -Risk "LOW"
		Write-Host "   RDP enabled and NLA enabled" -ForegroundColor Green
	} elseif ($rdp -eq 1) {
		Save-Result -Category "Network Security" -Item "RDP/NLA" -Status "PASS" -Details "RDP off" -Risk "LOW"
		Write-Host "   RDP disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Network Security" -Item "RDP/NLA" -Status "WARNING" -Details "Unable to read RDP/NLA settings" -Risk "MEDIUM"
		Write-Host "   Unable to read RDP/NLA settings" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -Item "RDP settings" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check RDP settings: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Network Security" -Status "Checking SMB settings" -PercentComplete 95
# 5) SMB configuration
try {
	$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol,RequireSecuritySignature
	if ($smb) {
		if ($smb.EnableSMB1Protocol) {
			Save-Result -Category "Network Security" -Item "SMB1" -Status "FAIL" -Details "SMB1 enabled" -Risk "HIGH"
			Write-Host "   SMB1 enabled" -ForegroundColor Red
		} else {
			Save-Result -Category "Network Security" -Item "SMB1" -Status "PASS" -Details "SMB1 disabled" -Risk "LOW"
			Write-Host "   SMB1 disabled" -ForegroundColor Green
		}
		if (-not $smb.RequireSecuritySignature) {
			Save-Result -Category "Network Security" -Item "SMB signing" -Status "WARNING" -Details "Signing not required" -Risk "MEDIUM"
			Write-Host "   SMB signing not required" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Network Security" -Item "SMB signing" -Status "PASS" -Details "Signing required" -Risk "LOW"
			Write-Host "   SMB signing required" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Network Security" -Item "SMB configuration" -Status "WARNING" -Details "Unable to read SMB settings" -Risk "MEDIUM"
		Write-Host "   Unable to read SMB settings" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -Item "SMB configuration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check SMB configuration: $($_.Exception.Message)" -ForegroundColor Red
}

# 6) NetBIOS over TCP/IP check
try {
	$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled -eq $true }
	$vulnerable = $false
	$vulnerableAdapters = @()

	foreach ($adapter in $adapters) {
		# TcpipNetbiosOptions: 0 = Default (DHCP), 1 = Enabled, 2 = Disabled
		if ($adapter.TcpipNetbiosOptions -eq 0 -or $adapter.TcpipNetbiosOptions -eq 1) {
			$vulnerable = $true
			$vulnerableAdapters += $adapter.Caption
		}
	}

	if ($vulnerable) {
		Save-Result -Category "Network Security" -Item "NetBIOS over TCP/IP" -Status "FAIL" -Details "$($vulnerableAdapters.Count) adapters with NetBIOS enabled" -Risk "HIGH"
		Write-Host "   NetBIOS enabled on $($vulnerableAdapters.Count) adapters" -ForegroundColor Red
	} else {
		Save-Result -Category "Network Security" -Item "NetBIOS over TCP/IP" -Status "PASS" -Details "NetBIOS disabled on all adapters" -Risk "LOW"
		Write-Host "   NetBIOS disabled on all adapters" -ForegroundColor Green
	}
} catch {
	Save-Result -Category "Network Security" -Item "NetBIOS over TCP/IP" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   Failed to check NetBIOS: $($_.Exception.Message)" -ForegroundColor Red
}

# 7) RDP encryption level check
try {
	$rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
	if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
		# RDP is enabled, check encryption level
		$encLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue

		if (!$encLevel -or $encLevel.MinEncryptionLevel -lt 3) {
			Save-Result -Category "Network Security" -Item "RDP encryption level" -Status "FAIL" -Details "Encryption level low or not set" -Risk "HIGH"
			Write-Host "   RDP encryption level low or not set" -ForegroundColor Red
		} else {
			Save-Result -Category "Network Security" -Item "RDP encryption level" -Status "PASS" -Details "High encryption level" -Risk "LOW"
			Write-Host "   RDP encryption level is high" -ForegroundColor Green
		}
	} else {
		Write-Host "   RDP is disabled, encryption check skipped" -ForegroundColor Cyan
	}
} catch {
	Write-Host "   Failed to check RDP encryption: $($_.Exception.Message)" -ForegroundColor Red
}

# 8) RDP session timeout check
try {
	$rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
	if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
		# RDP is enabled, check session timeout
		$sessionTimeout = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue

		if (!$sessionTimeout -or $sessionTimeout.MaxIdleTime -eq 0) {
			Save-Result -Category "Network Security" -Item "RDP session timeout" -Status "WARNING" -Details "No idle timeout set" -Risk "MEDIUM"
			Write-Host "   RDP session timeout not set" -ForegroundColor Yellow
		} else {
			$timeoutMinutes = [math]::Round($sessionTimeout.MaxIdleTime / 60000, 0)
			if ($timeoutMinutes -gt 30) {
				Save-Result -Category "Network Security" -Item "RDP session timeout" -Status "WARNING" -Details "$timeoutMinutes minutes (Recommended: <= 30)" -Risk "MEDIUM"
				Write-Host "   RDP session timeout too long: $timeoutMinutes minutes" -ForegroundColor Yellow
			} else {
				Save-Result -Category "Network Security" -Item "RDP session timeout" -Status "PASS" -Details "$timeoutMinutes minutes" -Risk "LOW"
				Write-Host "   RDP session timeout OK: $timeoutMinutes minutes" -ForegroundColor Green
			}
		}
	} else {
		Write-Host "   RDP is disabled, session timeout check skipped" -ForegroundColor Cyan
	}
} catch {
	Write-Host "   Failed to check RDP session timeout: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Network Security" -Completed
Write-Host "=== Network Security Check Completed ===" -ForegroundColor Yellow