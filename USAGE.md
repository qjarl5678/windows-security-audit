# 사용법 가이드

## KISA 보안 심사 점검 도구 사용법

### 🚀 빠른 시작

#### 1. 관리자 권한으로 PowerShell 실행
```powershell
# Windows 키 + X → "Windows PowerShell (관리자)" 선택
# 또는 시작 메뉴에서 PowerShell을 우클릭 → "관리자 권한으로 실행"
```

#### 2. 실행 정책 확인 및 설정
```powershell
# 현재 실행 정책 확인
Get-ExecutionPolicy

# 실행 정책이 Restricted인 경우 다음 명령 실행
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 3. 스크립트 실행
```powershell
# 전체 보안 점검 실행
.\Security-Audit-Main.ps1

# 빠른 점검 실행 (주요 항목만)
.\Security-Audit-Main.ps1 -QuickCheck

# 상세 보고서 생성
.\Security-Audit-Main.ps1 -DetailedReport
```

### 📋 개별 스크립트 실행

#### 계정 보안 점검
```powershell
.\Account-Security-Check.ps1
```
- 관리자 계정 수 확인
- 암호 정책 점검
- 계정 잠금 정책 확인
- 비활성 계정 점검
- Guest 계정 상태 확인

#### 시스템 보안 점검
```powershell
.\System-Security-Check.ps1
```
- Windows 업데이트 상태
- 방화벽 설정 확인
- 안티바이러스 상태
- 불필요한 서비스 점검
- 레지스트리 보안 설정
- UAC 설정 확인

#### 네트워크 보안 점검
```powershell
.\Network-Security-Check.ps1
```
- 열린 포트 확인
- 네트워크 어댑터 보안
- DNS 설정 점검
- 네트워크 공유 확인
- 원격 데스크톱 설정
- SMB 프로토콜 보안

#### 로그 보안 점검
```powershell
.\Log-Security-Check.ps1
```
- 이벤트 로그 설정
- 감사 정책 확인
- 보안 로그 이벤트 분석
- 로그 파일 무결성
- 로그 전달 설정
- 로그 보존 정책

### 📊 결과 확인

#### 콘솔 출력
실행 중 실시간으로 점검 결과가 콘솔에 표시됩니다:
- ✅ **PASS**: 보안 설정이 적절함
- ⚠️ **WARNING**: 주의가 필요한 설정
- ❌ **FAIL**: 보안 취약점 발견

#### HTML 보고서
점검 완료 후 `Reports` 폴더에 HTML 보고서가 생성됩니다:
```
Reports/
└── Security-Audit-Report-YYYYMMDD-HHMMSS.html
```

#### 로그 파일
실행 과정이 `Logs` 폴더에 기록됩니다:
```
Logs/
└── Security-Audit-YYYYMMDD-HHMMSS.log
```

### 🔧 고급 사용법

#### 사용자 정의 출력 경로
```powershell
.\Security-Audit-Main.ps1 -OutputPath "C:\CustomReports"
```

#### 특정 카테고리만 점검
```powershell
# 계정 보안만 점검
.\Account-Security-Check.ps1

# 네트워크 보안만 점검  
.\Network-Security-Check.ps1
```

#### 스크립트 실행 전 사전 점검
```powershell
# PowerShell 버전 확인
$PSVersionTable.PSVersion

# 관리자 권한 확인
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# 필요한 모듈 확인
Get-Module -ListAvailable | Where-Object { $_.Name -like "*Security*" }
```

### ⚠️ 주의사항

#### 실행 전 확인사항
1. **관리자 권한 필수**: 모든 스크립트는 관리자 권한으로 실행해야 합니다.
2. **실행 정책**: PowerShell 실행 정책이 스크립트 실행을 허용해야 합니다.
3. **네트워크 연결**: 일부 점검 항목은 인터넷 연결이 필요할 수 있습니다.

#### 보안 고려사항
1. **테스트 환경**: 운영 환경에서 실행하기 전에 테스트 환경에서 충분히 검증하세요.
2. **백업**: 중요한 시스템 설정을 변경하기 전에 백업을 수행하세요.
3. **권한 최소화**: 필요한 최소한의 권한으로 스크립트를 실행하세요.

### 🐛 문제 해결

#### 일반적인 오류

**오류**: "실행할 수 없는 스크립트입니다"
```powershell
# 해결방법
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**오류**: "관리자 권한이 필요합니다"
```powershell
# 해결방법: 관리자 권한으로 PowerShell 재실행
```

**오류**: "모듈을 찾을 수 없습니다"
```powershell
# 해결방법: 필요한 모듈 설치
Install-Module -Name SecurityPolicyDsc -Force
```

#### 로그 확인
문제가 발생한 경우 로그 파일을 확인하세요:
```powershell
Get-Content ".\Logs\Security-Audit-*.log" | Select-String "ERROR"
```

### 📞 지원

#### 문제 신고
- GitHub Issues를 통해 버그 리포트나 기능 요청을 등록하세요.
- 로그 파일과 함께 상세한 오류 정보를 제공해 주세요.

#### 기능 요청
- 새로운 보안 점검 항목 제안
- 보고서 형식 개선 제안
- 성능 최적화 제안

---

**KISA 보안 심사 준비를 위한 필수 도구입니다!** 🛡️
