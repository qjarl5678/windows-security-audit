# -*- coding: utf-8 -*-
# Network Security Check Script
# KISA Windows Security Assessment - Network Management

if (-not (Get-Command Save-Result -ErrorAction SilentlyContinue)) {
	function Save-Result {
		param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
		if (-not $script:Results) { $script:Results = @{} }
		if (-not $script:Results.ContainsKey($Category)) { $script:Results[$Category] = @() }
		$script:Results[$Category] += @{ ItemCode=$ItemCode; Item=$Item; Status=$Status; Details=$Details; Risk=$Risk; Timestamp=Get-Date }
	}
}

Write-Host "`n=== Network Security Check Started ===" -ForegroundColor Yellow

# Risky listening ports check
Write-Progress -Activity "Network Security" -Status "Checking risky ports" -PercentComplete 15
try {
	$danger = @(21,23,25,53,80,135,139,445,1433,3389,5432,5900)
	$open = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalPort,OwningProcess
	$open = @($open)
	$risky = $open | Where-Object { $_.LocalPort -in $danger }
	$rc = @($risky).Count
	if ($rc -gt 0) {
		Save-Result -Category "Network Security" -ItemCode "PORTS" -Item "Risky listening ports" -Status "WARNING" -Details "$rc listening on risky ports" -Risk "MEDIUM"
		Write-Host "   [PORTS] Risky listening ports: $rc" -ForegroundColor Yellow
	} elseif ($open.Count -ge 0) {
		Save-Result -Category "Network Security" -ItemCode "PORTS" -Item "Risky listening ports" -Status "PASS" -Details "None" -Risk "LOW"
		Write-Host "   [PORTS] No risky listening ports" -ForegroundColor Green
	} else {
		Save-Result -Category "Network Security" -ItemCode "PORTS" -Item "Risky listening ports" -Status "WARNING" -Details "Unable to enumerate connections" -Risk "MEDIUM"
		Write-Host "   [PORTS] Unable to enumerate connections" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -ItemCode "PORTS" -Item "Listening ports check" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [PORTS] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# DNS configuration check
Write-Progress -Activity "Network Security" -Status "Checking DNS" -PercentComplete 40
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
		Save-Result -Category "Network Security" -ItemCode "DNS" -Item "DNS configuration" -Status "WARNING" -Details "$pub public DNS in use" -Risk "MEDIUM"
		Write-Host "   [DNS] Public DNS in use: $pub" -ForegroundColor Yellow
	} elseif ($dns) {
		Save-Result -Category "Network Security" -ItemCode "DNS" -Item "DNS configuration" -Status "PASS" -Details "Internal DNS in use" -Risk "LOW"
		Write-Host "   [DNS] Internal DNS in use" -ForegroundColor Green
	} else {
		Save-Result -Category "Network Security" -ItemCode "DNS" -Item "DNS configuration" -Status "WARNING" -Details "Unable to get DNS servers" -Risk "MEDIUM"
		Write-Host "   [DNS] Unable to get DNS servers" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -ItemCode "DNS" -Item "DNS configuration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [DNS] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# SMB shares risk check
Write-Progress -Activity "Network Security" -Status "Checking SMB shares" -PercentComplete 65
try {
	$shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*$" }
	if ($shares) {
		$riskyShares = $shares | Where-Object { $_.Path -like "*Users*" -or $_.Path -like "*Program Files*" }
		$sc = @($riskyShares).Count
		if ($sc -gt 0) {
			Save-Result -Category "Network Security" -ItemCode "SHARES" -Item "Network shares" -Status "WARNING" -Details "$sc risky shares" -Risk "MEDIUM"
			Write-Host "   [SHARES] Risky shares: $sc" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Network Security" -ItemCode "SHARES" -Item "Network shares" -Status "PASS" -Details "No risky shares" -Risk "LOW"
			Write-Host "   [SHARES] No risky shares" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Network Security" -ItemCode "SHARES" -Item "Network shares" -Status "WARNING" -Details "Unable to enumerate shares" -Risk "MEDIUM"
		Write-Host "   [SHARES] Unable to enumerate shares" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -ItemCode "SHARES" -Item "Network shares" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [SHARES] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-58: RDP and NLA check
Write-Progress -Activity "Network Security" -Status "W-58: RDP & NLA" -PercentComplete 85
try {
	$rdpProp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
	$nlaProp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue

	$rdp = if ($rdpProp) { $rdpProp.fDenyTSConnections } else { $null }
	$nla = if ($nlaProp) { $nlaProp.UserAuthentication } else { $null }

	# Check encryption level
	$encLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue

	if ($rdp -eq 0 -and $nla -ne 1) {
		Save-Result -Category "Network Security" -ItemCode "W-58" -Item "RDP/NLA configuration" -Status "WARNING" -Details "RDP on, NLA off" -Risk "MEDIUM"
		Write-Host "   [W-58] RDP enabled but NLA disabled" -ForegroundColor Yellow
	} elseif ($rdp -eq 0 -and $nla -eq 1) {
		if (!$encLevel -or $encLevel.MinEncryptionLevel -lt 3) {
			Save-Result -Category "Network Security" -ItemCode "W-58" -Item "RDP/NLA configuration" -Status "WARNING" -Details "RDP encryption level low" -Risk "MEDIUM"
			Write-Host "   [W-58] RDP encryption level too low" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Network Security" -ItemCode "W-58" -Item "RDP/NLA configuration" -Status "PASS" -Details "RDP on, NLA on, high encryption" -Risk "LOW"
			Write-Host "   [W-58] RDP properly configured" -ForegroundColor Green
		}
	} elseif ($rdp -eq 1) {
		Save-Result -Category "Network Security" -ItemCode "W-58" -Item "RDP/NLA configuration" -Status "PASS" -Details "RDP off" -Risk "LOW"
		Write-Host "   [W-58] RDP disabled" -ForegroundColor Green
	} else {
		Save-Result -Category "Network Security" -ItemCode "W-58" -Item "RDP/NLA configuration" -Status "WARNING" -Details "Unable to read RDP/NLA settings" -Risk "MEDIUM"
		Write-Host "   [W-58] Unable to read RDP/NLA settings" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -ItemCode "W-58" -Item "RDP/NLA configuration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [W-58] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# W-67: RDP session timeout check
Write-Progress -Activity "Network Security" -Status "W-67: RDP timeout" -PercentComplete 90
try {
	$rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
	if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
		$sessionTimeout = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue

		if (!$sessionTimeout -or $sessionTimeout.MaxIdleTime -eq 0) {
			Save-Result -Category "Network Security" -ItemCode "W-67" -Item "RDP session timeout" -Status "WARNING" -Details "No idle timeout set" -Risk "MEDIUM"
			Write-Host "   [W-67] RDP session timeout not set" -ForegroundColor Yellow
		} else {
			$timeoutMinutes = [math]::Round($sessionTimeout.MaxIdleTime / 60000, 0)
			if ($timeoutMinutes -gt 30) {
				Save-Result -Category "Network Security" -ItemCode "W-67" -Item "RDP session timeout" -Status "WARNING" -Details "$timeoutMinutes minutes (Recommended: <= 30)" -Risk "MEDIUM"
				Write-Host "   [W-67] RDP session timeout too long: $timeoutMinutes minutes" -ForegroundColor Yellow
			} else {
				Save-Result -Category "Network Security" -ItemCode "W-67" -Item "RDP session timeout" -Status "PASS" -Details "$timeoutMinutes minutes" -Risk "LOW"
				Write-Host "   [W-67] RDP session timeout OK: $timeoutMinutes minutes" -ForegroundColor Green
			}
		}
	} else {
		Save-Result -Category "Network Security" -ItemCode "W-67" -Item "RDP session timeout" -Status "PASS" -Details "RDP disabled" -Risk "LOW"
		Write-Host "   [W-67] RDP is disabled" -ForegroundColor Cyan
	}
} catch {
	Save-Result -Category "Network Security" -ItemCode "W-67" -Item "RDP session timeout" -Status "WARNING" -Details $_.Exception.Message -Risk "MEDIUM"
	Write-Host "   [W-67] Check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# SMB configuration check
Write-Progress -Activity "Network Security" -Status "Checking SMB settings" -PercentComplete 95
try {
	$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol,RequireSecuritySignature
	if ($smb) {
		if ($smb.EnableSMB1Protocol) {
			Save-Result -Category "Network Security" -ItemCode "SMB1" -Item "SMB1 protocol" -Status "FAIL" -Details "SMB1 enabled" -Risk "HIGH"
			Write-Host "   [SMB1] SMB1 enabled" -ForegroundColor Red
		} else {
			Save-Result -Category "Network Security" -ItemCode "SMB1" -Item "SMB1 protocol" -Status "PASS" -Details "SMB1 disabled" -Risk "LOW"
			Write-Host "   [SMB1] SMB1 disabled" -ForegroundColor Green
		}
		if (-not $smb.RequireSecuritySignature) {
			Save-Result -Category "Network Security" -ItemCode "SMB-SIGN" -Item "SMB signing" -Status "WARNING" -Details "Signing not required" -Risk "MEDIUM"
			Write-Host "   [SMB-SIGN] SMB signing not required" -ForegroundColor Yellow
		} else {
			Save-Result -Category "Network Security" -ItemCode "SMB-SIGN" -Item "SMB signing" -Status "PASS" -Details "Signing required" -Risk "LOW"
			Write-Host "   [SMB-SIGN] SMB signing required" -ForegroundColor Green
		}
	} else {
		Save-Result -Category "Network Security" -ItemCode "SMB" -Item "SMB configuration" -Status "WARNING" -Details "Unable to read SMB settings" -Risk "MEDIUM"
		Write-Host "   [SMB] Unable to read SMB settings" -ForegroundColor Yellow
	}
} catch {
	Save-Result -Category "Network Security" -ItemCode "SMB" -Item "SMB configuration" -Status "FAIL" -Details $_.Exception.Message -Risk "HIGH"
	Write-Host "   [SMB] Check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Progress -Activity "Network Security" -Completed
Write-Host "=== Network Security Check Completed ===" -ForegroundColor Yellow
