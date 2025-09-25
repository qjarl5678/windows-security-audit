# -*- coding: utf-8 -*-
# 로그 보안 점검 스크립트
# Log Security Check Script for KISA Security Assessment
# 작성자: Security Audit Team
# 버전: 1.0

Write-Host "`n=== 로그 보안 점검 시작 ===" -ForegroundColor Yellow

# 1. 이벤트 로그 설정 점검
Write-Host "1. 이벤트 로그 설정 점검 중..." -ForegroundColor Cyan
try {
    $EventLogs = @("Application", "System", "Security")
    $LogIssues = @()

    foreach ($LogName in $EventLogs) {
        $Log = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
        if ($Log) {
            if ($Log.MaximumSizeInBytes -lt 100MB) {
                $LogIssues += "$LogName 로그 크기가 $([math]::Round($Log.MaximumSizeInBytes/1MB, 2))MB로 부족함"
            }
        }
    }

    if ($LogIssues.Count -gt 0) {
        Save-Result -Category "로그 보안" -Item "이벤트 로그 설정" -Status "WARNING" -Details "$($LogIssues.Count) 개의 로그 설정 문제 발견" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($LogIssues.Count) 개의 로그 설정 문제가 발견되었습니다." -ForegroundColor Yellow
        foreach ($Issue in $LogIssues) {
            Write-Host "      - $Issue" -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "로그 보안" -Item "이벤트 로그 설정" -Status "PASS" -Details "이벤트 로그 설정이 적절함" -Risk "LOW"
        Write-Host "   ✅ 이벤트 로그 설정이 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "로그 보안" -Item "이벤트 로그 설정" -Status "FAIL" -Details "이벤트 로그 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 이벤트 로그 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 2. 보안 이벤트 점검
Write-Host "2. 보안 이벤트 점검 중..." -ForegroundColor Cyan
try {
    $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue

    if ($SecurityEvents) {
        $FailedLogonEvents = $SecurityEvents | Where-Object { $_.Id -eq 4625 }
        if ($FailedLogonEvents.Count -gt 50) {
            Save-Result -Category "로그 보안" -Item "실패한 로그인" -Status "WARNING" -Details "최근 7일간 $($FailedLogonEvents.Count) 건의 실패한 로그인 시도" -Risk "MEDIUM"
            Write-Host "   ⚠️ 최근 7일간 $($FailedLogonEvents.Count) 건의 실패한 로그인 시도가 있습니다." -ForegroundColor Yellow
        } else {
            Save-Result -Category "로그 보안" -Item "실패한 로그인" -Status "PASS" -Details "실패한 로그인 시도가 적절함" -Risk "LOW"
            Write-Host "   ✅ 실패한 로그인 시도가 적절합니다." -ForegroundColor Green
        }
    } else {
        Save-Result -Category "로그 보안" -Item "보안 이벤트" -Status "WARNING" -Details "보안 이벤트를 가져올 수 없음" -Risk "MEDIUM"
        Write-Host "   ⚠️ 보안 이벤트를 가져올 수 없습니다." -ForegroundColor Yellow
    }
} catch {
    Save-Result -Category "로그 보안" -Item "보안 이벤트" -Status "FAIL" -Details "보안 이벤트를 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 보안 이벤트를 확인할 수 없습니다." -ForegroundColor Red
}

# 3. 감사 정책 점검
Write-Host "3. 감사 정책 점검 중..." -ForegroundColor Cyan
try {
    $AuditPol = auditpol /get /category:* 2>$null
    if ($AuditPol) {
        Save-Result -Category "로그 보안" -Item "감사 정책" -Status "PASS" -Details "감사 정책이 설정되어 있음" -Risk "LOW"
        Write-Host "   ✅ 감사 정책이 설정되어 있습니다." -ForegroundColor Green
    } else {
        Save-Result -Category "로그 보안" -Item "감사 정책" -Status "WARNING" -Details "감사 정책 확인 필요" -Risk "MEDIUM"
        Write-Host "   ⚠️ 감사 정책 확인이 필요합니다." -ForegroundColor Yellow
    }
} catch {
    Save-Result -Category "로그 보안" -Item "감사 정책" -Status "FAIL" -Details "감사 정책을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 감사 정책을 확인할 수 없습니다." -ForegroundColor Red
}

# 4. 로그 파일 무결성 점검
Write-Host "4. 로그 파일 무결성 점검 중..." -ForegroundColor Cyan
try {
    $LogFiles = @(
        "$env:SystemRoot\System32\winevt\Logs\Application.evtx",
        "$env:SystemRoot\System32\winevt\Logs\System.evtx",
        "$env:SystemRoot\System32\winevt\Logs\Security.evtx"
    )

    $CorruptedLogs = @()
    foreach ($LogFile in $LogFiles) {
        if (Test-Path $LogFile) {
            try {
                $null = Get-WinEvent -Path $LogFile -MaxEvents 1 -ErrorAction Stop
            } catch {
                $CorruptedLogs += Split-Path $LogFile -Leaf
            }
        }
    }

    if ($CorruptedLogs.Count -gt 0) {
        Save-Result -Category "로그 보안" -Item "로그 파일 무결성" -Status "FAIL" -Details "$($CorruptedLogs.Count) 개의 손상된 로그 파일" -Risk "HIGH"
        Write-Host "   ❌ $($CorruptedLogs.Count) 개의 손상된 로그 파일이 있습니다." -ForegroundColor Red
    } else {
        Save-Result -Category "로그 보안" -Item "로그 파일 무결성" -Status "PASS" -Details "모든 로그 파일이 정상임" -Risk "LOW"
        Write-Host "   ✅ 모든 로그 파일이 정상입니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "로그 보안" -Item "로그 파일 무결성" -Status "FAIL" -Details "로그 파일 무결성을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 로그 파일 무결성을 확인할 수 없습니다." -ForegroundColor Red
}

Write-Host "=== 로그 보안 점검 완료 ===" -ForegroundColor Yellow