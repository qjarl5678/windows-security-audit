# 네트워크 보안 점검 스크립트
# Network Security Check Script for KISA Security Assessment
# 작성자: Security Audit Team
# 버전: 1.0

Write-Host "`n=== 네트워크 보안 점검 시작 ===" -ForegroundColor Yellow

# 1. 열린 포트 점검
Write-Host "1. 열린 포트 점검 중..." -ForegroundColor Cyan
try {
    $OpenPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalPort, OwningProcess
    $DangerousPorts = @(21, 23, 25, 53, 80, 135, 139, 445, 1433, 3389, 5432, 5900)
    
    $OpenDangerousPorts = $OpenPorts | Where-Object { $_.LocalPort -in $DangerousPorts }
    
    if ($OpenDangerousPorts.Count -gt 0) {
        Save-Result -Category "네트워크 보안" -Item "위험한 포트" -Status "WARNING" -Details "$($OpenDangerousPorts.Count) 개의 위험한 포트가 열려있음" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($OpenDangerousPorts.Count) 개의 위험한 포트가 열려있습니다." -ForegroundColor Yellow
        foreach ($Port in $OpenDangerousPorts) {
            Write-Host "      - 포트 $($Port.LocalPort) (PID: $($Port.OwningProcess))" -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "네트워크 보안" -Item "위험한 포트" -Status "PASS" -Details "위험한 포트가 열려있지 않음" -Risk "LOW"
        Write-Host "   ✅ 위험한 포트가 열려있지 않습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "열린 포트 점검" -Status "FAIL" -Details "포트 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 포트 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 2. 네트워크 어댑터 보안 설정 점검
Write-Host "2. 네트워크 어댑터 보안 설정 점검 중..." -ForegroundColor Cyan
try {
    $NetworkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $UnsecuredAdapters = @()
    
    foreach ($Adapter in $NetworkAdapters) {
        $AdapterConfig = Get-NetAdapterAdvancedProperty -Name $Adapter.Name -ErrorAction SilentlyContinue
        # 여기서 추가적인 어댑터 보안 설정을 확인할 수 있습니다
    }
    
    if ($UnsecuredAdapters.Count -gt 0) {
        Save-Result -Category "네트워크 보안" -Item "네트워크 어댑터" -Status "WARNING" -Details "$($UnsecuredAdapters.Count) 개의 보안 설정이 부족한 어댑터" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($UnsecuredAdapters.Count) 개의 보안 설정이 부족한 어댑터가 있습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "네트워크 보안" -Item "네트워크 어댑터" -Status "PASS" -Details "네트워크 어댑터 보안 설정 양호" -Risk "LOW"
        Write-Host "   ✅ 네트워크 어댑터 보안 설정이 양호합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "네트워크 어댑터" -Status "FAIL" -Details "네트워크 어댑터 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 네트워크 어댑터 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 3. DNS 설정 점검
Write-Host "3. DNS 설정 점검 중..." -ForegroundColor Cyan
try {
    $DNSServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }
    $PublicDNSCount = 0
    
    foreach ($DNS in $DNSServers) {
        foreach ($Server in $DNS.ServerAddresses) {
            if ($Server -match "^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1)$") {
                $PublicDNSCount++
            }
        }
    }
    
    if ($PublicDNSCount -gt 0) {
        Save-Result -Category "네트워크 보안" -Item "DNS 설정" -Status "WARNING" -Details "공용 DNS 서버 $PublicDNSCount 개 사용 중" -Risk "MEDIUM"
        Write-Host "   ⚠️ 공용 DNS 서버 $PublicDNSCount 개가 사용되고 있습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "네트워크 보안" -Item "DNS 설정" -Status "PASS" -Details "내부 DNS 서버 사용 중" -Risk "LOW"
        Write-Host "   ✅ 내부 DNS 서버가 사용되고 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "DNS 설정" -Status "FAIL" -Details "DNS 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ DNS 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 4. 네트워크 공유 점검
Write-Host "4. 네트워크 공유 점검 중..." -ForegroundColor Cyan
try {
    $NetworkShares = Get-SmbShare | Where-Object { $_.ScopeName -eq "*" -and $_.Name -notlike "*$" }
    $DangerousShares = $NetworkShares | Where-Object { 
        $_.Name -in @("C$", "D$", "ADMIN$", "IPC$") -or 
        $_.Path -like "*Users*" -or 
        $_.Path -like "*Program Files*" 
    }
    
    if ($DangerousShares.Count -gt 0) {
        Save-Result -Category "네트워크 보안" -Item "네트워크 공유" -Status "WARNING" -Details "$($DangerousShares.Count) 개의 위험한 공유 발견" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($DangerousShares.Count) 개의 위험한 공유가 발견되었습니다." -ForegroundColor Yellow
        foreach ($Share in $DangerousShares) {
            Write-Host "      - $($Share.Name): $($Share.Path)" -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "네트워크 보안" -Item "네트워크 공유" -Status "PASS" -Details "위험한 공유가 없음" -Risk "LOW"
        Write-Host "   ✅ 위험한 공유가 없습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "네트워크 공유" -Status "FAIL" -Details "네트워크 공유 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 네트워크 공유 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 5. 원격 데스크톱 설정 점검
Write-Host "5. 원격 데스크톱 설정 점검 중..." -ForegroundColor Cyan
try {
    $RDPEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    $RDPNetworkLevelAuth = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
    
    if ($RDPEnabled -eq 0) {
        if ($RDPNetworkLevelAuth -eq 1) {
            Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "PASS" -Details "RDP 활성화, NLA 사용" -Risk "LOW"
            Write-Host "   ✅ 원격 데스크톱이 활성화되어 있고 NLA가 사용됩니다." -ForegroundColor Green
        } else {
            Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "WARNING" -Details "RDP 활성화, NLA 미사용" -Risk "MEDIUM"
            Write-Host "   ⚠️ 원격 데스크톱이 활성화되어 있지만 NLA가 사용되지 않습니다." -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "PASS" -Details "RDP 비활성화" -Risk "LOW"
        Write-Host "   ✅ 원격 데스크톱이 비활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "FAIL" -Details "원격 데스크톱 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 원격 데스크톱 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 6. 네트워크 프로토콜 보안 점검
Write-Host "6. 네트워크 프로토콜 보안 점검 중..." -ForegroundColor Cyan
try {
    # SMB 버전 점검
    $SMBVersion = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB1Protocol
    if ($SMBVersion.EnableSMB1Protocol -eq $true) {
        Save-Result -Category "네트워크 보안" -Item "SMB 프로토콜" -Status "FAIL" -Details "SMB1 프로토콜이 활성화되어 있음" -Risk "HIGH"
        Write-Host "   ❌ SMB1 프로토콜이 활성화되어 있습니다." -ForegroundColor Red
    } else {
        Save-Result -Category "네트워크 보안" -Item "SMB 프로토콜" -Status "PASS" -Details "SMB1 프로토콜이 비활성화됨" -Risk "LOW"
        Write-Host "   ✅ SMB1 프로토콜이 비활성화되어 있습니다." -ForegroundColor Green
    }
    
    # SMB 서명 요구 점검
    if ($SMBVersion.RequireSecuritySignature -eq $false) {
        Save-Result -Category "네트워크 보안" -Item "SMB 서명" -Status "WARNING" -Details "SMB 서명이 요구되지 않음" -Risk "MEDIUM"
        Write-Host "   ⚠️ SMB 서명이 요구되지 않습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "네트워크 보안" -Item "SMB 서명" -Status "PASS" -Details "SMB 서명이 요구됨" -Risk "LOW"
        Write-Host "   ✅ SMB 서명이 요구됩니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "네트워크 프로토콜" -Status "FAIL" -Details "네트워크 프로토콜 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 네트워크 프로토콜 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 7. 네트워크 연결 상태 점검
Write-Host "7. 네트워크 연결 상태 점검 중..." -ForegroundColor Cyan
try {
    $ActiveConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
    $SuspiciousConnections = $ActiveConnections | Where-Object { 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)" -and
        $_.RemotePort -in @(80, 443, 8080, 8443, 22, 23, 21, 25, 53, 110, 143, 993, 995)
    }
    
    if ($SuspiciousConnections.Count -gt 10) {
        Save-Result -Category "네트워크 보안" -Item "외부 연결" -Status "WARNING" -Details "$($SuspiciousConnections.Count) 개의 외부 연결 발견" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($SuspiciousConnections.Count) 개의 외부 연결이 발견되었습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "네트워크 보안" -Item "외부 연결" -Status "PASS" -Details "외부 연결 수가 적절함" -Risk "LOW"
        Write-Host "   ✅ 외부 연결 수가 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "네트워크 연결" -Status "FAIL" -Details "네트워크 연결 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 네트워크 연결 정보를 가져올 수 없습니다." -ForegroundColor Red
}

Write-Host "=== 네트워크 보안 점검 완료 ===" -ForegroundColor Yellow
