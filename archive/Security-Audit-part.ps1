# Windows 보안 취약점 종합 검사 스크립트 (확장판)
# 관리자 권한으로 실행 필요

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Windows 보안 취약점 종합 검사 시작 (확장판)" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

# 결과 저장용 배열
$vulnerabilities = @()

# 스크립트 실행 시작 시간
$startTime = Get-Date

# 함수: 취약점 결과 추가
function Add-Vulnerability {
    param($Title, $Status, $CurrentValue, $RecommendedValue = "", $Description = "")
    $script:vulnerabilities += [PSCustomObject]@{
        Title = $Title
        Status = $Status
        CurrentValue = $CurrentValue
        RecommendedValue = $RecommendedValue
        Description = $Description
    }
}

Write-Host "`n1. Administrator 계정명 변경 확인" -ForegroundColor Green
try {
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount.Name -eq "Administrator") {
        Add-Vulnerability "Administrator 계정명" "취약" $adminAccount.Name "변경된 계정명" "기본 Administrator 계정명 사용"
        Write-Host "   [취약] 기본 Administrator 계정명 사용중" -ForegroundColor Red
    } else {
        Add-Vulnerability "Administrator 계정명" "안전" $adminAccount.Name "" "계정명이 변경됨"
        Write-Host "   [안전] 계정명 변경됨: $($adminAccount.Name)" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] Administrator 계정 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2. 계정 잠금 정책 확인" -ForegroundColor Green
try {
    $lockoutPolicy = net accounts | Select-String "잠금 임계값|Lockout threshold"
    $lockoutValue = if ($lockoutPolicy) { ($lockoutPolicy -split ":")[1].Trim() } else { "0" }
    
    if ($lockoutValue -eq "사용 안 함" -or $lockoutValue -eq "Never" -or $lockoutValue -eq "0") {
        Add-Vulnerability "계정 잠금 임계값" "취약" "0 (사용 안함)" "3-5회" "무제한 로그인 시도 허용"
        Write-Host "   [취약] 계정 잠금 설정 안됨" -ForegroundColor Red
    } else {
        Add-Vulnerability "계정 잠금 임계값" "안전" $lockoutValue "" "계정 잠금 정책 설정됨"
        Write-Host "   [안전] 계정 잠금 임계값: $lockoutValue" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] 계정 잠금 정책 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3. Administrator 계정 암호 만료 설정 확인" -ForegroundColor Green
try {
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount.PasswordExpires -eq $false) {
        Add-Vulnerability "Administrator 암호 만료" "취약" "제한 없음 (FALSE)" "제한 적용 (TRUE)" "암호 무기한 사용 가능"
        Write-Host "   [취약] Administrator 계정 암호 사용 기간 제한 없음" -ForegroundColor Red
    } else {
        Add-Vulnerability "Administrator 암호 만료" "안전" "제한 적용" "" "암호 만료 설정됨"
        Write-Host "   [안전] Administrator 계정 암호 만료 설정됨" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] Administrator 암호 만료 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4. 암호 정책 확인" -ForegroundColor Green
try {
    # 최대 암호 사용 기간
    $maxPwdAge = net accounts | Select-String "최대 암호 사용 기간|Maximum password age"
    $maxAge = if ($maxPwdAge) { ($maxPwdAge -split ":")[1].Trim() } else { "알 수 없음" }
    
    # 최소 암호 사용 기간
    $minPwdAge = net accounts | Select-String "최소 암호 사용 기간|Minimum password age"
    $minAge = if ($minPwdAge) { ($minPwdAge -split ":")[1].Trim() } else { "0" }
    
    # 암호 기록
    $pwdHistory = net accounts | Select-String "암호 기록|Password history"
    $historyCount = if ($pwdHistory) { ($pwdHistory -split ":")[1].Trim() } else { "0" }
    
    Write-Host "   최대 암호 사용 기간: $maxAge"
    Write-Host "   최소 암호 사용 기간: $minAge" 
    Write-Host "   암호 기록: $historyCount"
    
    if ($minAge -eq "0" -or $minAge -eq "0 일") {
        Add-Vulnerability "최소 암호 사용 기간" "취약" "0일" "1일 이상" "즉시 암호 변경 가능"
        Write-Host "   [취약] 최소 암호 사용 기간 미설정" -ForegroundColor Red
    } else {
        Add-Vulnerability "최소 암호 사용 기간" "안전" $minAge "" "최소 암호 사용 기간 설정됨"
        Write-Host "   [안전] 최소 암호 사용 기간: $minAge" -ForegroundColor Green
    }
    
    if ($historyCount -eq "0" -or $historyCount -eq "없음") {
        Add-Vulnerability "암호 기록" "취약" "0개" "12개 이상" "이전 암호 재사용 가능"
        Write-Host "   [취약] 암호 기록 미설정" -ForegroundColor Red
    } else {
        Add-Vulnerability "암호 기록" "안전" $historyCount "" "암호 기록 설정됨"
        Write-Host "   [안전] 암호 기록: $historyCount" -ForegroundColor Green
    }
    
} catch {
    Write-Host "   [오류] 암호 정책 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5. 마지막 사용자 이름 표시 정책 확인" -ForegroundColor Green
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
    if ($regValue -and $regValue.DontDisplayLastUserName -eq 1) {
        Add-Vulnerability "마지막 사용자 이름 표시" "안전" "사용 안함" "" "마지막 사용자명 숨김"
        Write-Host "   [안전] 마지막 사용자 이름 표시 안함 설정됨" -ForegroundColor Green
    } else {
        Add-Vulnerability "마지막 사용자 이름 표시" "취약" "사용" "사용 안함" "마지막 사용자명 표시됨"
        Write-Host "   [취약] 마지막 사용자 이름이 표시됨" -ForegroundColor Red
    }
} catch {
    Write-Host "   [오류] 레지스트리 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6. 로컬 로그온 권한 확인" -ForegroundColor Green
try {
    $seceditOutput = secedit /export /cfg temp_secpol.cfg /quiet
    if (Test-Path "temp_secpol.cfg") {
        $logonRight = Get-Content "temp_secpol.cfg" | Select-String "SeInteractiveLogonRight"
        if ($logonRight) {
            $sids = $logonRight -replace ".*= ", ""
            Write-Host "   현재 설정: $sids"
            
            $vulnerable = $false
            $vulnerableGroups = @()
            
            if ($sids -match "S-1-5-32-545") {  # Users
                $vulnerable = $true
                $vulnerableGroups += "Users"
                Write-Host "   [취약] Users 그룹에 로컬 로그온 권한 있음" -ForegroundColor Red
            }
            if ($sids -match "S-1-5-32-551") {  # Backup Operators
                $vulnerable = $true
                $vulnerableGroups += "Backup Operators"
                Write-Host "   [취약] Backup Operators 그룹에 로컬 로그온 권한 있음" -ForegroundColor Red
            }
            
            if ($vulnerable) {
                Add-Vulnerability "로컬 로그온 권한" "취약" "$($vulnerableGroups -join ', ') 그룹 포함" "Administrators, IIS_IUSRS만" "일반 사용자 로그온 허용"
            } else {
                Add-Vulnerability "로컬 로그온 권한" "안전" "적절한 그룹만 설정" "" "안전한 로그온 권한 설정"
                Write-Host "   [안전] 적절한 그룹만 로컬 로그온 권한 보유" -ForegroundColor Green
            }
        }
        Remove-Item "temp_secpol.cfg" -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "   [오류] 로컬 로그온 권한 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n7. NetBIOS over TCP/IP 설정 확인" -ForegroundColor Green
try {
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    $vulnerable = $false
    $vulnerableAdapters = @()
    
    foreach ($adapter in $adapters) {
        if ($adapter.TcpipNetbiosOptions -eq 0 -or $adapter.TcpipNetbiosOptions -eq 1) {
            $vulnerable = $true
            $vulnerableAdapters += $adapter.Caption
            Write-Host "   [취약] $($adapter.Caption): NetBIOS 사용됨 (값: $($adapter.TcpipNetbiosOptions))" -ForegroundColor Red
        }
    }
    
    if ($vulnerable) {
        Add-Vulnerability "NetBIOS over TCP/IP" "취약" "사용" "사용 안함" "NetBIOS 공격 위험"
    } else {
        Add-Vulnerability "NetBIOS over TCP/IP" "안전" "사용 안함" "" "NetBIOS 비활성화됨"
        Write-Host "   [안전] 모든 어댑터에서 NetBIOS 비활성화됨" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] NetBIOS 설정 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n8. FTP 서비스 확인" -ForegroundColor Green
try {
    $ftpService = Get-Service -Name "*ftp*" -ErrorAction SilentlyContinue
    $ftpRunning = $false
    
    foreach ($service in $ftpService) {
        if ($service.Status -eq "Running") {
            $ftpRunning = $true
            Write-Host "   [취약] $($service.Name) 서비스가 실행 중입니다" -ForegroundColor Red
        }
    }
    
    if ($ftpRunning) {
        Add-Vulnerability "FTP 서비스" "취약" "실행 중" "중지" "보안되지 않은 FTP 서비스 실행"
    } else {
        Add-Vulnerability "FTP 서비스" "안전" "중지됨" "" "FTP 서비스 중지됨"
        Write-Host "   [안전] FTP 서비스가 중지되거나 설치되지 않음" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] FTP 서비스 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n9. 원격 데스크톱 서비스 확인" -ForegroundColor Green
try {
    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0) {
        Write-Host "   [정보] 원격 데스크톱 서비스가 활성화되어 있습니다" -ForegroundColor Yellow
        
        # 암호화 수준 확인
        $encLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        if (!$encLevel -or $encLevel.MinEncryptionLevel -lt 3) {
            Add-Vulnerability "RDP 암호화 수준" "취약" "미설정 또는 낮음" "높은 수준(3)" "약한 암호화 사용"
            Write-Host "   [취약] RDP 암호화 수준이 낮거나 미설정" -ForegroundColor Red
        } else {
            Add-Vulnerability "RDP 암호화 수준" "안전" "높은 수준" "" "강력한 암호화 사용"
            Write-Host "   [안전] RDP 암호화 수준이 높음으로 설정됨" -ForegroundColor Green
        }
        
        # 세션 타임아웃 확인
        $sessionTimeout = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue
        if (!$sessionTimeout) {
            Add-Vulnerability "RDP 세션 타임아웃" "취약" "미설정" "30분 이하" "무제한 세션 유지"
            Write-Host "   [취약] RDP 세션 타임아웃 미설정" -ForegroundColor Red
        } else {
            $timeoutMinutes = [math]::Round($sessionTimeout.MaxIdleTime / 60000, 0)
            Add-Vulnerability "RDP 세션 타임아웃" "안전" "$timeoutMinutes분" "" "세션 타임아웃 설정됨"
            Write-Host "   [안전] RDP 세션 타임아웃: $timeoutMinutes분" -ForegroundColor Green
        }
    } else {
        Write-Host "   [안전] 원격 데스크톱 서비스가 비활성화되어 있습니다" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] 원격 데스크톱 설정 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n10. SAM 익명 열거 정책 확인" -ForegroundColor Green
try {
    $restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "restrictanonymous" -ErrorAction SilentlyContinue
    if (!$restrictAnonymous -or $restrictAnonymous.restrictanonymous -eq 0) {
        Add-Vulnerability "SAM 익명 열거" "취약" "허용" "차단" "익명 계정 열거 가능"
        Write-Host "   [취약] SAM 계정 익명 열거가 허용됨" -ForegroundColor Red
    } else {
        Add-Vulnerability "SAM 익명 열거" "안전" "차단" "" "익명 열거 차단됨"
        Write-Host "   [안전] SAM 계정 익명 열거가 차단됨" -ForegroundColor Green
    }
    
    # restrictanonymoussam도 확인
    $restrictAnonymousSam = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "restrictanonymoussam" -ErrorAction SilentlyContinue
    if ($restrictAnonymousSam -and $restrictAnonymousSam.restrictanonymoussam -eq 1) {
        Write-Host "   [안전] SAM 계정 익명 열거 추가 차단 설정됨" -ForegroundColor Green
    }
} catch {
    Write-Host "   [오류] SAM 정책 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n11. 사용자 홈 디렉터리 권한 확인" -ForegroundColor Green
try {
    $usersPath = "C:\Users"
    $vulnerableDirs = @()
    
    if (Test-Path $usersPath) {
        $userDirs = Get-ChildItem $usersPath -Directory
        foreach ($dir in $userDirs) {
            $acl = Get-Acl $dir.FullName
            $everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }
            if ($everyoneAccess) {
                $vulnerableDirs += $dir.Name
                Write-Host "   [취약] $($dir.Name): Everyone 권한 존재" -ForegroundColor Red
            }
        }
        
        if ($vulnerableDirs.Count -gt 0) {
            Add-Vulnerability "홈 디렉터리 권한" "취약" "$($vulnerableDirs -join ', '): Everyone 권한 존재" "Everyone 권한 제거" "모든 사용자 접근 가능"
        } else {
            Add-Vulnerability "홈 디렉터리 권한" "안전" "적절한 권한 설정" "" "Everyone 권한 없음"
            Write-Host "   [안전] 모든 홈 디렉터리에 적절한 권한 설정됨" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "   [오류] 홈 디렉터리 권한 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n12. 설치된 업데이트 및 보안 패치 확인" -ForegroundColor Green
try {
    $updates = Get-HotFix | Sort-Object InstalledOn -Descending
    $latestUpdate = $updates | Select-Object -First 1
    $daysSinceUpdate = (Get-Date) - $latestUpdate.InstalledOn
    
    Write-Host "   최근 업데이트: $($latestUpdate.HotFixID) ($($latestUpdate.InstalledOn.ToString('yyyy-MM-dd')))"
    Write-Host "   마지막 업데이트 후 경과일: $([math]::Round($daysSinceUpdate.TotalDays))일"
    
    # 전체 업데이트 상태
    if ($daysSinceUpdate.TotalDays -gt 30) {
        Add-Vulnerability "시스템 업데이트" "취약" "$([math]::Round($daysSinceUpdate.TotalDays))일 전" "30일 이내" "오래된 시스템"
        Write-Host "   [취약] 30일 이상 업데이트되지 않음" -ForegroundColor Red
    } else {
        Add-Vulnerability "시스템 업데이트" "양호" "$([math]::Round($daysSinceUpdate.TotalDays))일 전" "" "최신 업데이트 적용됨"
        Write-Host "   [양호] 최근에 업데이트됨" -ForegroundColor Green
    }
    
    # 중요 보안 패치 확인
    $criticalPatches = @{
        "RDP 원격 코드 실행" = @("KB4522355", "KB4516115", "KB4516044", "KB4515384")
        ".NET 서비스 거부" = @("KB5020874", "KB5021237", "KB5021238")
        "Visual Studio 원격 코드 실행" = @("KB5020879", "KB5021225")
        "CLFS 드라이버" = @("KB5020953", "KB5021234")
        "SmartScreen" = @("KB5020872", "KB5021239")
    }
    
    $installedKBs = $updates | ForEach-Object { $_.HotFixID }
    
    foreach ($patchCategory in $criticalPatches.Keys) {
        $requiredKBs = $criticalPatches[$patchCategory]
        $hasRequiredPatch = $false
        
        foreach ($kb in $requiredKBs) {
            if ($installedKBs -contains $kb) {
                $hasRequiredPatch = $true
                break
            }
        }
        
        if (!$hasRequiredPatch) {
            Add-Vulnerability "$patchCategory 패치" "취약" "미설치" $requiredKBs[0] "보안 패치 부재"
            Write-Host "   [취약] $patchCategory 관련 패치 미설치" -ForegroundColor Red
        } else {
            Write-Host "   [안전] $patchCategory 관련 패치 설치됨" -ForegroundColor Green
        }
    }
    
} catch {
    Write-Host "   [오류] 업데이트 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n13. 실행 중인 위험 서비스 확인" -ForegroundColor Green
try {
    $riskyServices = @{
        "Telnet" = "원격 접속 위험"
        "FTP" = "암호화되지 않은 파일 전송"
        "SNMP" = "네트워크 정보 유출"
        "RemoteRegistry" = "원격 레지스트리 접근"
        "TlntSvr" = "텔넷 서버"
        "MSFTPSVC" = "Microsoft FTP 서비스"
    }
    
    $foundRiskyServices = @()
    
    foreach ($serviceName in $riskyServices.Keys) {
        $svc = Get-Service -Name "*$serviceName*" -ErrorAction SilentlyContinue
        if ($svc) {
            foreach ($service in $svc) {
                if ($service.Status -eq "Running") {
                    $foundRiskyServices += $service.Name
                    Add-Vulnerability "위험 서비스" "취약" "$($service.Name) 실행 중" "중지" $riskyServices[$serviceName]
                    Write-Host "   [취약] $($service.Name) 서비스가 실행 중" -ForegroundColor Red
                }
            }
        }
    }
    
    if ($foundRiskyServices.Count -eq 0) {
        Write-Host "   [안전] 위험한 서비스가 실행 중이지 않음" -ForegroundColor Green
    }
    
} catch {
    Write-Host "   [오류] 서비스 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n14. Visual Studio 버전 및 보안 상태 확인" -ForegroundColor Green
try {
    $vsRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\*\Setup\VS",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\*\Setup\VS"
    )
    
    $vsFound = $false
    
    foreach ($regPath in $vsRegPaths) {
        $vsInstalls = Get-ChildItem $regPath -ErrorAction SilentlyContinue
        foreach ($install in $vsInstalls) {
            $vsFound = $true
            $version = Get-ItemProperty -Path $install.PSPath -Name "ProductVersion" -ErrorAction SilentlyContinue
            if ($version) {
                Write-Host "   Visual Studio 버전 발견: $($version.ProductVersion)"
                
                $versionNumber = $version.ProductVersion
                $isVulnerable = $true
                
                # 버전별 보안 버전 체크
                if ($versionNumber -like "15.*") {  # VS 2017
                    if ([version]$versionNumber -ge [version]"15.9.57") { $isVulnerable = $false }
                } elseif ($versionNumber -like "16.*") {  # VS 2019
                    if ([version]$versionNumber -ge [version]"16.11.30") { $isVulnerable = $false }
                } elseif ($versionNumber -like "17.*") {  # VS 2022
                    if ([version]$versionNumber -ge [version]"17.7.6") { $isVulnerable = $false }
                }
                
                if ($isVulnerable) {
                    Add-Vulnerability "Visual Studio 보안" "취약" $versionNumber "최신 보안 버전" "취약한 Visual Studio 버전"
                    Write-Host "   [취약] Visual Studio $versionNumber - 보안 업데이트 필요" -ForegroundColor Red
                } else {
                    Add-Vulnerability "Visual Studio 보안" "안전" $versionNumber "" "안전한 Visual Studio 버전"
                    Write-Host "   [안전] Visual Studio $versionNumber - 보안 버전" -ForegroundColor Green
                }
            }
        }
    }
    
    if (!$vsFound) {
        Write-Host "   [정보] Visual Studio가 설치되지 않음" -ForegroundColor Cyan
    }
    
} catch {
    Write-Host "   [오류] Visual Studio 확인 실패: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n15. 시스템 백업 정책 확인" -ForegroundColor Green
try {
    # Windows Backup 서비스 확인
    $backupService = Get-Service -Name "SDRSVC" -ErrorAction SilentlyContinue
    $wbadminStatus = & wbadmin get versions -quiet 2>$null
    
    if ($wbadminStatus -and $wbadminStatus -notmatch "No backup") {
        Add-Vulnerability "시스템 백업" "안전" "백업 정책 존재" "" "정기 백업 수행 중"
        Write-Host "   [안전] 시스템 백업이 구성되어 있습니다" -ForegroundColor Green
    } else {
        Add-Vulnerability "시스템 백업" "취약" "백업 없음" "정기 백업 설정" "데이터 손실 위험"
        Write-Host "   [취약] 시스템 백업이 구성되지 않음" -ForegroundColor Red
        Write-Host "   [권장] 정기적인 백업 정책을 수립하세요" -ForegroundColor Yellow
    }
    
} catch {
    Add-Vulnerability "시스템 백업" "취약" "확인 불가" "수동 확인 필요" "백업 정책 확인 필요"
    Write-Host "   [취약] 백업 상태 확인 불가 - 수동으로 백업 정책을 확인하세요" -ForegroundColor Red
}

# 결과 요약 출력
Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "종합 검사 결과 요약" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

$totalChecks = $vulnerabilities.Count
$vulnerableChecks = ($vulnerabilities | Where-Object { $_.Status -eq "취약" }).Count
$safeChecks = ($vulnerabilities | Where-Object { $_.Status -eq "안전" }).Count
$warningChecks = ($vulnerabilities | Where-Object { $_.Status -eq "양호" }).Count

Write-Host "`n전체 검사 항목: $totalChecks" -ForegroundColor White
Write-Host "취약 항목: $vulnerableChecks" -ForegroundColor Red
Write-Host "안전 항목: $safeChecks" -ForegroundColor Green
Write-Host "양호 항목: $warningChecks" -ForegroundColor Yellow

# 위험도별 분류
$highRisk = @("시스템 업데이트", "Administrator 암호 만료", "RDP 암호화 수준", "SAM 익명 열거")
$mediumRisk = @("로컬 로그온 권한", "NetBIOS over TCP/IP", "위험 서비스")
$lowRisk = @("마지막 사용자 이름 표시", "홈 디렉터리 권한")

$highRiskVulns = $vulnerabilities | Where-Object { $_.Status -eq "취약" -and $_.Title -in $highRisk }
$mediumRiskVulns = $vulnerabilities | Where-Object { $_.Status -eq "취약" -and $_.Title -in $mediumRisk }

Write-Host "`n위험도 분석:" -ForegroundColor Yellow
Write-Host "고위험: $($highRiskVulns.Count)개" -ForegroundColor Red
Write-Host "중위험: $($mediumRiskVulns.Count)개" -ForegroundColor Magenta
Write-Host "저위험: $(($vulnerableChecks - $highRiskVulns.Count - $mediumRiskVulns.Count))개" -ForegroundColor DarkYellow

if ($vulnerableChecks -gt 0) {
    Write-Host "`n취약점 상세 정보:" -ForegroundColor Red
    Write-Host "=" * 80 -ForegroundColor DarkRed
    
    # 고위험 취약점 우선 표시
    if ($highRiskVulns.Count -gt 0) {
        Write-Host "`n🚨 고위험 취약점 (즉시 조치 필요):" -ForegroundColor Red
        $highRiskVulns | Format-Table -AutoSize -Wrap
    }
    
    # 중위험 취약점
    if ($mediumRiskVulns.Count -gt 0) {
        Write-Host "`n⚠️  중위험 취약점:" -ForegroundColor Magenta  
        $mediumRiskVulns | Format-Table -AutoSize -Wrap
    }
    
    # 나머지 취약점
    $otherVulns = $vulnerabilities | Where-Object { $_.Status -eq "취약" -and $_.Title -notin ($highRisk + $mediumRisk) }
    if ($otherVulns.Count -gt 0) {
        Write-Host "`n📋 기타 취약점:" -ForegroundColor DarkYellow
        $otherVulns | Format-Table -AutoSize -Wrap
    }
}

# 권장 조치 사항
if ($vulnerableChecks -gt 0) {
    Write-Host "`n📋 권장 조치 사항:" -ForegroundColor Cyan
    Write-Host "1. 고위험 취약점부터 우선 조치" -ForegroundColor White
    Write-Host "2. Windows Update 즉시 실행" -ForegroundColor White
    Write-Host "3. 위험 서비스 중지 및 비활성화" -ForegroundColor White
    Write-Host "4. 보안 정책 강화 (암호, 로그온 권한 등)" -ForegroundColor White
    Write-Host "5. 정기적인 보안 점검 수행" -ForegroundColor White
}

# CSV 파일로 결과 저장
$csvPath = "SecurityAudit_Extended_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$vulnerabilities | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`n결과가 다음 파일에 저장되었습니다: $csvPath" -ForegroundColor Green

# 실행 시간 계산
$endTime = Get-Date
$executionTime = $endTime - $startTime
Write-Host "`n실행 시간: $([math]::Round($executionTime.TotalSeconds, 2))초" -ForegroundColor Cyan

Write-Host "`n종합 보안 검사 완료!" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

# 스크립트 종료 방지 - 사용자 입력 대기
Write-Host "`nPress any key to exit..." -ForegroundColor White
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")