# -*- coding: utf-8 -*-
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

# 2. 방화벽 규칙 점검
Write-Host "2. 방화벽 규칙 점검 중..." -ForegroundColor Cyan
try {
    $InboundRules = Get-NetFirewallRule | Where-Object { $_.Direction -eq "Inbound" -and $_.Enabled -eq $true -and $_.Action -eq "Allow" }
    $DangerousInboundRules = $InboundRules | Where-Object { $_.DisplayName -like "*Any*" -or $_.LocalAddress -eq "Any" }

    if ($DangerousInboundRules.Count -gt 10) {
        Save-Result -Category "네트워크 보안" -Item "방화벽 규칙" -Status "WARNING" -Details "$($DangerousInboundRules.Count) 개의 광범위한 허용 규칙" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($DangerousInboundRules.Count) 개의 광범위한 허용 규칙이 있습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "네트워크 보안" -Item "방화벽 규칙" -Status "PASS" -Details "방화벽 규칙이 적절함" -Risk "LOW"
        Write-Host "   ✅ 방화벽 규칙이 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "방화벽 규칙" -Status "FAIL" -Details "방화벽 규칙을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 방화벽 규칙을 확인할 수 없습니다." -ForegroundColor Red
}

# 3. SMB 설정 점검
Write-Host "3. SMB 설정 점검 중..." -ForegroundColor Cyan
try {
    $SMBConfig = Get-SmbServerConfiguration
    if ($SMBConfig.EnableSMB1Protocol -eq $true) {
        Save-Result -Category "네트워크 보안" -Item "SMB 설정" -Status "FAIL" -Details "SMB1 프로토콜이 활성화되어 있음" -Risk "HIGH"
        Write-Host "   ❌ 위험한 SMB1 프로토콜이 활성화되어 있습니다." -ForegroundColor Red
    } else {
        Save-Result -Category "네트워크 보안" -Item "SMB 설정" -Status "PASS" -Details "SMB1 프로토콜이 비활성화됨" -Risk "LOW"
        Write-Host "   ✅ SMB1 프로토콜이 비활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "SMB 설정" -Status "FAIL" -Details "SMB 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ SMB 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 4. 원격 데스크톱 설정 점검
Write-Host "4. 원격 데스크톱 설정 점검 중..." -ForegroundColor Cyan
try {
    $RDPEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($RDPEnabled -eq 0) {
        Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "WARNING" -Details "원격 데스크톱이 활성화되어 있음" -Risk "MEDIUM"
        Write-Host "   ⚠️ 원격 데스크톱이 활성화되어 있습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "PASS" -Details "원격 데스크톱이 비활성화됨" -Risk "LOW"
        Write-Host "   ✅ 원격 데스크톱이 비활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "네트워크 보안" -Item "원격 데스크톱" -Status "FAIL" -Details "원격 데스크톱 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 원격 데스크톱 설정을 확인할 수 없습니다." -ForegroundColor Red
}

Write-Host "=== 네트워크 보안 점검 완료 ===" -ForegroundColor Yellow