# 계정 보안 점검 스크립트
# Account Security Check Script for KISA Security Assessment
# 작성자: Security Audit Team
# 버전: 1.0

Write-Host "`n=== 계정 보안 점검 시작 ===" -ForegroundColor Yellow

# 1. 관리자 계정 점검
Write-Host "1. 관리자 계정 점검 중..." -ForegroundColor Cyan
try {
    $AdminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $AdminCount = if ($AdminUsers) { $AdminUsers.Count } else { 0 }

    if ($AdminCount -gt 2) {
        Save-Result -Category "계정 보안" -Item "관리자 계정 수" -Status "WARNING" -Details "관리자 계정이 $AdminCount 개로 다수 존재" -Risk "MEDIUM"
        Write-Host "   ⚠️ 관리자 계정이 $AdminCount 개 존재합니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "계정 보안" -Item "관리자 계정 수" -Status "PASS" -Details "관리자 계정 수가 적절함" -Risk "LOW"
        Write-Host "   ✅ 관리자 계정 수가 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "계정 보안" -Item "관리자 계정 점검" -Status "FAIL" -Details "관리자 계정 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 관리자 계정 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 2. 암호 정책 점검
Write-Host "2. 암호 정책 점검 중..." -ForegroundColor Cyan
try {
    $PasswordPolicy = Get-LocalSecurityPolicy -Area SECURITY_POLICY | Where-Object { $_.Name -like "*Password*" }
    
    # 최소 암호 길이 확인
    $MinLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -ErrorAction SilentlyContinue).MinimumPasswordLength
    if ($MinLength -lt 8) {
        Save-Result -Category "계정 보안" -Item "최소 암호 길이" -Status "FAIL" -Details "최소 암호 길이가 $MinLength 자로 부족함 (권장: 8자 이상)" -Risk "HIGH"
        Write-Host "   ❌ 최소 암호 길이가 $MinLength 자로 부족합니다." -ForegroundColor Red
    } else {
        Save-Result -Category "계정 보안" -Item "최소 암호 길이" -Status "PASS" -Details "최소 암호 길이가 $MinLength 자로 적절함" -Risk "LOW"
        Write-Host "   ✅ 최소 암호 길이가 $MinLength 자로 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "계정 보안" -Item "암호 정책 점검" -Status "FAIL" -Details "암호 정책 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 암호 정책 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 3. 계정 잠금 정책 점검
Write-Host "3. 계정 잠금 정책 점검 중..." -ForegroundColor Cyan
try {
    $LockoutThreshold = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutThreshold" -ErrorAction SilentlyContinue).LockoutThreshold
    if ($LockoutThreshold -eq 0 -or $LockoutThreshold -gt 5) {
        Save-Result -Category "계정 보안" -Item "계정 잠금 정책" -Status "WARNING" -Details "계정 잠금 임계값이 $LockoutThreshold 로 부적절함" -Risk "MEDIUM"
        Write-Host "   ⚠️ 계정 잠금 정책이 부적절합니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "계정 보안" -Item "계정 잠금 정책" -Status "PASS" -Details "계정 잠금 임계값이 $LockoutThreshold 로 적절함" -Risk "LOW"
        Write-Host "   ✅ 계정 잠금 정책이 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "계정 보안" -Item "계정 잠금 정책" -Status "FAIL" -Details "계정 잠금 정책 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 계정 잠금 정책 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 4. 비활성 계정 점검
Write-Host "4. 비활성 계정 점검 중..." -ForegroundColor Cyan
try {
    $InactiveUsers = Get-LocalUser | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-90) -and $_.Enabled -eq $true }
    $InactiveCount = if ($InactiveUsers) { $InactiveUsers.Count } else { 0 }

    if ($InactiveCount -gt 0) {
        Save-Result -Category "계정 보안" -Item "비활성 계정" -Status "WARNING" -Details "$InactiveCount 개의 비활성 계정 발견 (90일 이상 미사용)" -Risk "MEDIUM"
        Write-Host "   ⚠️ $InactiveCount 개의 비활성 계정이 발견되었습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "계정 보안" -Item "비활성 계정" -Status "PASS" -Details "비활성 계정이 없음" -Risk "LOW"
        Write-Host "   ✅ 비활성 계정이 없습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "계정 보안" -Item "비활성 계정 점검" -Status "FAIL" -Details "비활성 계정 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 비활성 계정 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 5. Guest 계정 상태 점검
Write-Host "5. Guest 계정 상태 점검 중..." -ForegroundColor Cyan
try {
    $GuestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($GuestAccount -and $GuestAccount.Enabled -eq $true) {
        Save-Result -Category "계정 보안" -Item "Guest 계정" -Status "FAIL" -Details "Guest 계정이 활성화되어 있음" -Risk "HIGH"
        Write-Host "   ❌ Guest 계정이 활성화되어 있습니다." -ForegroundColor Red
    } else {
        Save-Result -Category "계정 보안" -Item "Guest 계정" -Status "PASS" -Details "Guest 계정이 비활성화되어 있음" -Risk "LOW"
        Write-Host "   ✅ Guest 계정이 비활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "계정 보안" -Item "Guest 계정 점검" -Status "FAIL" -Details "Guest 계정 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ Guest 계정 정보를 가져올 수 없습니다." -ForegroundColor Red
}

# 6. 암호 만료 정책 점검
Write-Host "6. 암호 만료 정책 점검 중..." -ForegroundColor Cyan
try {
    $MaxPasswordAge = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue).MaximumPasswordAge
    if ($MaxPasswordAge -eq 0 -or $MaxPasswordAge -gt 90) {
        Save-Result -Category "계정 보안" -Item "암호 만료 정책" -Status "WARNING" -Details "암호 최대 사용 기간이 $MaxPasswordAge 일로 부적절함" -Risk "MEDIUM"
        Write-Host "   ⚠️ 암호 만료 정책이 부적절합니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "계정 보안" -Item "암호 만료 정책" -Status "PASS" -Details "암호 최대 사용 기간이 $MaxPasswordAge 일로 적절함" -Risk "LOW"
        Write-Host "   ✅ 암호 만료 정책이 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "계정 보안" -Item "암호 만료 정책" -Status "FAIL" -Details "암호 만료 정책 정보를 가져올 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 암호 만료 정책 정보를 가져올 수 없습니다." -ForegroundColor Red
}

Write-Host "=== 계정 보안 점검 완료 ===" -ForegroundColor Yellow
