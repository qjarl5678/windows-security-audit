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
            if ($Log.RecordCount -gt ($Log.MaximumSizeInBytes * 0.9)) {
                $LogIssues += "$LogName 로그가 거의 가득참"
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

# 2. 감사 정책 점검
Write-Host "2. 감사 정책 점검 중..." -ForegroundColor Cyan
try {
    $AuditPolicies = @(
        "AuditAccountLogon",
        "AuditAccountManage", 
        "AuditLogonEvents",
        "AuditObjectAccess",
        "AuditPolicyChange",
        "AuditPrivilegeUse",
        "AuditSystemEvents"
    )
    
    $DisabledAuditPolicies = @()
    
    foreach ($Policy in $AuditPolicies) {
        $PolicyValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name $Policy -ErrorAction SilentlyContinue).$Policy
        if ($PolicyValue -eq 0) {
            $DisabledAuditPolicies += $Policy
        }
    }
    
    if ($DisabledAuditPolicies.Count -gt 0) {
        Save-Result -Category "로그 보안" -Item "감사 정책" -Status "WARNING" -Details "$($DisabledAuditPolicies.Count) 개의 감사 정책이 비활성화됨" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($DisabledAuditPolicies.Count) 개의 감사 정책이 비활성화되어 있습니다." -ForegroundColor Yellow
        foreach ($Policy in $DisabledAuditPolicies) {
            Write-Host "      - $Policy" -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "로그 보안" -Item "감사 정책" -Status "PASS" -Details "모든 감사 정책이 활성화됨" -Risk "LOW"
        Write-Host "   ✅ 모든 감사 정책이 활성화되어 있습니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "로그 보안" -Item "감사 정책" -Status "FAIL" -Details "감사 정책을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 감사 정책을 확인할 수 없습니다." -ForegroundColor Red
}

# 3. 보안 로그 이벤트 점검
Write-Host "3. 보안 로그 이벤트 점검 중..." -ForegroundColor Cyan
try {
    $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    if ($SecurityEvents) {
        $FailedLogonEvents = $SecurityEvents | Where-Object { $_.Id -eq 4625 }
        $SuccessfulLogonEvents = $SecurityEvents | Where-Object { $_.Id -eq 4624 }
        $AccountLockoutEvents = $SecurityEvents | Where-Object { $_.Id -eq 4740 }
        
        if ($FailedLogonEvents.Count -gt 100) {
            Save-Result -Category "로그 보안" -Item "실패한 로그인" -Status "WARNING" -Details "최근 7일간 $($FailedLogonEvents.Count) 건의 실패한 로그인 시도" -Risk "MEDIUM"
            Write-Host "   ⚠️ 최근 7일간 $($FailedLogonEvents.Count) 건의 실패한 로그인 시도가 있습니다." -ForegroundColor Yellow
        } else {
            Save-Result -Category "로그 보안" -Item "실패한 로그인" -Status "PASS" -Details "실패한 로그인 시도가 적절함" -Risk "LOW"
            Write-Host "   ✅ 실패한 로그인 시도가 적절합니다." -ForegroundColor Green
        }
        
        if ($AccountLockoutEvents.Count -gt 10) {
            Save-Result -Category "로그 보안" -Item "계정 잠금" -Status "WARNING" -Details "최근 7일간 $($AccountLockoutEvents.Count) 건의 계정 잠금 이벤트" -Risk "MEDIUM"
            Write-Host "   ⚠️ 최근 7일간 $($AccountLockoutEvents.Count) 건의 계정 잠금 이벤트가 있습니다." -ForegroundColor Yellow
        } else {
            Save-Result -Category "로그 보안" -Item "계정 잠금" -Status "PASS" -Details "계정 잠금 이벤트가 적절함" -Risk "LOW"
            Write-Host "   ✅ 계정 잠금 이벤트가 적절합니다." -ForegroundColor Green
        }
    } else {
        Save-Result -Category "로그 보안" -Item "보안 로그" -Status "WARNING" -Details "보안 로그 이벤트를 가져올 수 없음" -Risk "MEDIUM"
        Write-Host "   ⚠️ 보안 로그 이벤트를 가져올 수 없습니다." -ForegroundColor Yellow
    }
} catch {
    Save-Result -Category "로그 보안" -Item "보안 로그 이벤트" -Status "FAIL" -Details "보안 로그 이벤트를 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 보안 로그 이벤트를 확인할 수 없습니다." -ForegroundColor Red
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
                $Log = Get-WinEvent -Path $LogFile -MaxEvents 1 -ErrorAction Stop
            } catch {
                $CorruptedLogs += Split-Path $LogFile -Leaf
            }
        }
    }
    
    if ($CorruptedLogs.Count -gt 0) {
        Save-Result -Category "로그 보안" -Item "로그 파일 무결성" -Status "FAIL" -Details "$($CorruptedLogs.Count) 개의 손상된 로그 파일" -Risk "HIGH"
        Write-Host "   ❌ $($CorruptedLogs.Count) 개의 손상된 로그 파일이 있습니다." -ForegroundColor Red
        foreach ($Log in $CorruptedLogs) {
            Write-Host "      - $Log" -ForegroundColor Red
        }
    } else {
        Save-Result -Category "로그 보안" -Item "로그 파일 무결성" -Status "PASS" -Details "모든 로그 파일이 정상임" -Risk "LOW"
        Write-Host "   ✅ 모든 로그 파일이 정상입니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "로그 보안" -Item "로그 파일 무결성" -Status "FAIL" -Details "로그 파일 무결성을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 로그 파일 무결성을 확인할 수 없습니다." -ForegroundColor Red
}

# 5. 로그 전달 설정 점검
Write-Host "5. 로그 전달 설정 점검 중..." -ForegroundColor Cyan
try {
    $LogForwarding = Get-WinEvent -ListLog "ForwardedEvents" -ErrorAction SilentlyContinue
    if ($LogForwarding -and $LogForwarding.RecordCount -gt 0) {
        Save-Result -Category "로그 보안" -Item "로그 전달" -Status "PASS" -Details "로그 전달이 설정되어 있음" -Risk "LOW"
        Write-Host "   ✅ 로그 전달이 설정되어 있습니다." -ForegroundColor Green
    } else {
        Save-Result -Category "로그 보안" -Item "로그 전달" -Status "WARNING" -Details "로그 전달이 설정되지 않음" -Risk "MEDIUM"
        Write-Host "   ⚠️ 로그 전달이 설정되지 않았습니다." -ForegroundColor Yellow
    }
} catch {
    Save-Result -Category "로그 보안" -Item "로그 전달" -Status "FAIL" -Details "로그 전달 설정을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 로그 전달 설정을 확인할 수 없습니다." -ForegroundColor Red
}

# 6. 로그 보존 정책 점검
Write-Host "6. 로그 보존 정책 점검 중..." -ForegroundColor Cyan
try {
    $LogRetentionPolicies = @(
        @{Name="Application"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"},
        @{Name="System"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"},
        @{Name="Security"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"}
    )
    
    $RetentionIssues = @()
    
    foreach ($Policy in $LogRetentionPolicies) {
        $RetentionDays = (Get-ItemProperty -Path $Policy.Path -Name "Retention" -ErrorAction SilentlyContinue).Retention
        if ($RetentionDays -lt 30) {
            $RetentionIssues += "$($Policy.Name) 로그 보존 기간이 $RetentionDays 일로 부족함"
        }
    }
    
    if ($RetentionIssues.Count -gt 0) {
        Save-Result -Category "로그 보안" -Item "로그 보존 정책" -Status "WARNING" -Details "$($RetentionIssues.Count) 개의 로그 보존 정책 문제" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($RetentionIssues.Count) 개의 로그 보존 정책 문제가 있습니다." -ForegroundColor Yellow
        foreach ($Issue in $RetentionIssues) {
            Write-Host "      - $Issue" -ForegroundColor Yellow
        }
    } else {
        Save-Result -Category "로그 보안" -Item "로그 보존 정책" -Status "PASS" -Details "로그 보존 정책이 적절함" -Risk "LOW"
        Write-Host "   ✅ 로그 보존 정책이 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "로그 보안" -Item "로그 보존 정책" -Status "FAIL" -Details "로그 보존 정책을 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 로그 보존 정책을 확인할 수 없습니다." -ForegroundColor Red
}

# 7. 로그 압축 및 아카이빙 점검
Write-Host "7. 로그 압축 및 아카이빙 점검 중..." -ForegroundColor Cyan
try {
    $LogDirectory = "$env:SystemRoot\System32\winevt\Logs"
    $OldLogFiles = Get-ChildItem -Path $LogDirectory -Filter "*.evtx" | Where-Object { 
        $_.LastWriteTime -lt (Get-Date).AddDays(-30) -and $_.Length -gt 100MB 
    }
    
    if ($OldLogFiles.Count -gt 0) {
        Save-Result -Category "로그 보안" -Item "로그 압축" -Status "WARNING" -Details "$($OldLogFiles.Count) 개의 큰 오래된 로그 파일" -Risk "MEDIUM"
        Write-Host "   ⚠️ $($OldLogFiles.Count) 개의 큰 오래된 로그 파일이 있습니다." -ForegroundColor Yellow
    } else {
        Save-Result -Category "로그 보안" -Item "로그 압축" -Status "PASS" -Details "로그 파일 크기가 적절함" -Risk "LOW"
        Write-Host "   ✅ 로그 파일 크기가 적절합니다." -ForegroundColor Green
    }
} catch {
    Save-Result -Category "로그 보안" -Item "로그 압축" -Status "FAIL" -Details "로그 파일 정보를 확인할 수 없음" -Risk "HIGH"
    Write-Host "   ❌ 로그 파일 정보를 확인할 수 없습니다." -ForegroundColor Red
}

Write-Host "=== 로그 보안 점검 완료 ===" -ForegroundColor Yellow
