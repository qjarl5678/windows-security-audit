# 시스템 보안 점검 스크립트
# System Security Check Script for KISA Security Assessment
# 작성자: Security Audit Team
# 버전: 1.0

Write-Host "`n=== 시스템 보안 점검 시작 ===" -ForegroundColor Yellow

# 1. Windows 업데이트 상태 점검
Write-Host "1. Windows 업데이트 상태 점검 중..." -ForegroundColor Cyan
try {
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
    
    if ($SearchResult.Updates.Count -gt 0) {
        Save-Result -Category "시스템 보안" -Item "Windows 업데이트" -Status "WARNING" -Details "$($SearchResult.Updates.Count) 개의 미설치 업데이트 존재" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($SearchResult.Updates.Count) 개의 미설치 업데이트가 있습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "시스템 보안" -Item "Windows 업데이트" -Status "PASS" -Details "모든 업데이트가 설치됨" -Risk "LOW"
        Write-Host "   ✅ 모든 업데이트가 설치되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "Windows 업데이트" -Status "FAIL" -Details "업데이트 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 업데이트 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 2. 방화벽 상태 점검
Write-Host "2. Windows 방화벽 상태 점검 중..." -ForegroundColor Cyan
try {
    $FirewallProfiles = Get-NetFirewallProfile
    $DisabledProfiles = $FirewallProfiles | Where-Object { $_.Enabled -eq $false }
    
    if ($DisabledProfiles.Count -gt 0) {
        Save-Result -Category "시스템 보안" -Item "Windows 방화벽" -Status "FAIL" -Details "$($DisabledProfiles.Count) 개의 방화벽 프로필이 비활성화됨" -Risk "HIGH"
        Write-Host "   ❌ $($DisabledProfiles.Count) 개의 방화벽 프로필이 비활성화되어 있습니다." -ForegroundColor Red
    } else {
        Save-Result -Category "시스템 보안" -Item "Windows 방화벽" -Status "PASS" -Details "모든 방화벽 프로필이 활성화됨" -Risk "LOW"
        Write-Host "   ✅ 모든 방화벽 프로필이 활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "Windows 방화벽" -Status "FAIL" -Details "방화벽 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 방화벽 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 3. 안티바이러스 상태 점검
Write-Host "3. 안티바이러스 상태 점검 중..." -ForegroundColor Cyan
try {
    $AntivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
    if ($AntivirusProducts) {
        $ActiveAntivirus = $AntivirusProducts | Where-Object { $_.productState -ne 0 }
        if ($ActiveAntivirus.Count -gt 0) {
            Save-Result -Category "시스템 보안" -Item "안티바이러스" -Status "PASS" -Details "$($ActiveAntivirus.Count) 개의 활성 안티바이러스 발견" -Risk "LOW"
            Write-Host "   ✅ $($ActiveAntivirus.Count) 개의 활성 안티바이러스가 설치되어 있습니다." -ForegroundColor Green
        } else {
            Save-Result -Category "시스템 보안" -Item "안티바이러스" -Status "FAIL" -Details "활성 안티바이러스가 없음" -Risk "HIGH"
            Write-Host "   ❌ 활성 안티바이러스가 없습니다." -ForegroundColor Red
        }
    } else {
        Save-Result -Category "시스템 보안" -Item "안티바이러스" -Status "WARNING" -Details "안티바이러스 정보를 확인할 수 없음" -Risk "MEDIUM"
        Write-Host "   ⚠️ 안티바이러스 정보를 확인할 수 없습니다." -ForegroundColor Yellow
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "안티바이러스" -Status "FAIL" -Details "안티바이러스 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 안티바이러스 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 4. 불필요한 서비스 점검
Write-Host "4. 불필요한 서비스 점검 중..." -ForegroundColor Cyan
try {
    $DangerousServices = @(
        "Telnet",
        "FTP Publishing Service", 
        "Simple Mail Transfer Protocol (SMTP)",
        "World Wide Web Publishing Service"
    )
    
    $RunningDangerousServices = Get-Service | Where-Object { 
        $_.Name -in $DangerousServices -and $_.Status -eq "Running" 
    }
    
    if ($RunningDangerousServices.Count -gt 0) {
        Save-Result -Category "시스템 보안" -Item "불필요한 서비스" -Status "WARNING" -Details "$($RunningDangerousServices.Count) 개의 위험한 서비스가 실행 중" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($RunningDangerousServices.Count) 개의 위험한 서비스가 실행 중입니다." -ForegroundColor Yellow
        foreach ($Service in $RunningDangerousServices) {
            Write-Host "      - $($Service.Name): $($Service.DisplayName)" -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "시스템 보안" -Item "불필요한 서비스" -Status "PASS" -Details "위험한 서비스가 실행되지 않음" -Risk "LOW"
        Write-Host "   ✅ 위험한 서비스가 실행되지 않고 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "불필요한 서비스" -Status "FAIL" -Details "서비스 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 서비스 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 5. 레지스트리 보안 설정 점검
Write-Host "5. 레지스트리 보안 설정 점검 중..." -ForegroundColor Cyan
try {
    # 원격 레지스트리 서비스 점검
    $RemoteRegistry = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
    if ($RemoteRegistry -and $RemoteRegistry.Status -eq "Running") {
        Save-Result -Category "시스템 보안" -Item "원격 레지스트리" -Status "WARNING" -Details "원격 레지스트리 서비스가 실행 중" -Risk "MEDIUM"
        Write-Host "   ⚠️ 원격 레지스트리 서비스가 실행 중입니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "시스템 보안" -Item "원격 레지스트리" -Status "PASS" -Details "원격 레지스트리 서비스가 비활성화됨" -Risk "LOW"
        Write-Host "   ✅ 원격 레지스트리 서비스가 비활성화되어 있습니다." -ForegroundColor Green
    }
    
    # 자동 로그인 설정 점검
    $AutoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    if ($AutoLogon.AutoAdminLogon -eq 1) {
        Save-Result -Category "시스템 보안" -Item "자동 로그인" -Status "FAIL" -Details "자동 로그인이 활성화되어 있음" -Risk "HIGH"
        Write-Host "   ❌ 자동 로그인이 활성화되어 있습니다." -ForegroundColor Red
    } else {
        Save-Result -Category "시스템 보안" -Item "자동 로그인" -Status "PASS" -Details "자동 로그인이 비활성화됨" -Risk "LOW"
        Write-Host "   ✅ 자동 로그인이 비활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "레지스트리 보안" -Status "FAIL" -Details "레지스트리 보안 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 레지스트리 보안 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 6. 시스템 파일 무결성 점검
Write-Host "6. 시스템 파일 무결성 점검 중..." -ForegroundColor Cyan
try {
    $SFCResult = sfc /verifyonly 2>&1
    if ($SFCResult -match "Windows Resource Protection found corrupt files") {
        Save-Result -Category "시스템 보안" -Item "시스템 파일 무결성" -Status "WARNING" -Details "손상된 시스템 파일 발견" -Risk "MEDIUM"
        Write-Host "   ⚠️ 손상된 시스템 파일이 발견되었습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "시스템 보안" -Item "시스템 파일 무결성" -Status "PASS" -Details "시스템 파일 무결성 양호" -Risk "LOW"
        Write-Host "   ✅ 시스템 파일 무결성이 양호합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "시스템 파일 무결성" -Status "FAIL" -Details "시스템 파일 무결성을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 시스템 파일 무결성을 확인할 수 없습니다." -ForegroundColor Red
}

# 7. UAC 설정 점검
Write-Host "7. UAC 설정 점검 중..." -ForegroundColor Cyan
try {
    $UACEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    if ($UACEnabled -eq 1) {
        Save-Result -Category "시스템 보안" -Item "UAC 설정" -Status "PASS" -Details "UAC가 활성화되어 있음" -Risk "LOW"
        Write-Host "   ✅ UAC가 활성화되어 있습니다." -ForegroundColor Green
    } else {
        Save-Result -Category "시스템 보안" -Item "UAC 설정" -Status "FAIL" -Details "UAC가 비활성화되어 있음" -Risk "HIGH"
        Write-Host "   ❌ UAC가 비활성화되어 있습니다." -ForegroundColor Red
    }
} catch {
    Save-Result -Category "시스템 보안" -Item "UAC 설정" -Status "FAIL" -Details "UAC 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ UAC 설정을 확인할 수 없습니다." -ForegroundColor Red
}

Write-Host "=== 시스템 보안 점검 완료 ===" -ForegroundColor Yellow
