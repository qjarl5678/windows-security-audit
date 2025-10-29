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


---

#### Windows 보안 항목

# 윈도우즈 서버 취약점 분석·평가 항목

## 1. 계정 관리

| 항목코드 | 점검항목 | 중요도 |
|---------|---------|--------|
| W-01 | Administrator 계정 이름 변경 또는 보안성 강화 | 상 |
| W-02 | Guest 계정 비활성화 | 상 |
| W-03 | 불필요한 계정 제거 | 상 |
| W-04 | 계정 잠금 임계값 설정 | 상 |
| W-05 | 해독 가능한 암호화를 사용하여 암호 저장 해제 | 상 |
| W-06 | 관리자 그룹에 최소한의 사용자 포함 | 상 |
| W-46 | Everyone 사용권한을 익명 사용자에 적용 해제 | 중 |
| W-47 | 계정 잠금 기간 설정 | 중 |
| W-48 | 패스워드 복잡성 설정 | 중 |
| W-49 | 패스워드 최소 암호 길이 | 중 |
| W-50 | 패스워드 최대 사용 기간 | 중 |
| W-51 | 패스워드 최소 사용 기간 | 중 |
| W-52 | 마지막 사용자 이름 표시 안함 | 중 |
| W-53 | 로컬 로그온 허용 | 중 |
| W-54 | 익명 SID/이름 변환 허용 해제 | 중 |
| W-55 | 최근 암호 기억 | 중 |
| W-56 | 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 | 중 |
| W-57 | 원격터미널 접속 가능한 사용자 그룹 제한 | 중 |

## 2. 서비스 관리

| 항목코드 | 점검항목 | 중요도 |
|---------|---------|--------|
| W-07 | 공유 권한 및 사용자 그룹 설정 | 상 |
| W-08 | 하드디스크 기본 공유 제거 | 상 |
| W-09 | 불필요한 서비스 제거 | 상 |
| W-10 | IIS 서비스 구동 점검 | 상 |
| W-11 | IIS 디렉토리 리스팅 제거 | 상 |
| W-12 | IIS CGI 실행 제한 | 상 |
| W-13 | IIS 상위 디렉토리 접근 금지 | 상 |
| W-14 | IIS 불필요한 파일 제거 | 상 |
| W-15 | IIS 웹프로세스 권한 제한 | 상 |
| W-16 | IIS 링크 사용 금지 | 상 |
| W-17 | IIS 파일 업로드 및 다운로드 제한 | 상 |
| W-18 | IIS DB 연결 취약점 점검 | 상 |
| W-19 | IIS 가상 디렉토리 삭제 | 상 |
| W-20 | IIS 데이터파일 ACL 적용 | 상 |
| W-21 | IIS 미사용 스크립트 매핑 제거 | 상 |
| W-22 | IIS Exec 명령어 쉘 호출 진단 | 상 |
| W-23 | IIS WebDAV 비활성화 | 상 |
| W-24 | NetBIOS 바인딩 서비스 구동 점검 | 상 |
| W-25 | FTP 서비스 구동 점검 | 상 |
| W-26 | FTP 디렉토리 접근 권한 설정 | 상 |
| W-27 | Anonymous FTP 금지 | 상 |
| W-28 | FTP 접근 제어 설정 | 상 |
| W-29 | DNS Zone Transfer 설정 | 상 |
| W-30 | RDS(Remote Data Services) 제거 | 상 |
| W-31 | 최신 서비스팩 적용 | 상 |
| W-58 | 터미널 서비스 암호화 수준 설정 | 중 |
| W-59 | IIS 웹 서비스 정보 숨김 | 중 |
| W-60 | SNMP 서비스 구동 점검 | 중 |
| W-61 | SNMP 서비스 커뮤니티스트링의 복잡성 설정 | 중 |
| W-62 | SNMP Access control 설정 | 중 |
| W-63 | DNS 서비스 구동 점검 | 중 |
| W-64 | HTTP/FTP/SMTP 배너 차단 | 하 |
| W-65 | Telnet 보안 설정 | 중 |
| W-66 | 불필요한 ODBC/OLE-DB 데이터소스와 드라이브 제거 | 중 |
| W-67 | 원격터미널 접속 타임아웃 설정 | 중 |
| W-68 | 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검 | 중 |

## 3. 패치 관리

| 항목코드 | 점검항목 | 중요도 |
|---------|---------|--------|
| W-32 | 최신 HOT FIX 적용 | 상 |
| W-33 | 백신 프로그램 업데이트 | 상 |
| W-69 | 정책에 따른 시스템 로깅설정 | 중 |

## 4. 로그 관리

| 항목코드 | 점검항목 | 중요도 |
|---------|---------|--------|
| W-34 | 로그의 정기적 검토 및 보고 | 상 |
| W-35 | 원격으로 액세스 할 수 있는 레지스트리 경로 | 상 |
| W-70 | 이벤트 로그 관리 설정 | 하 |
| W-71 | 원격에서 이벤트 로그파일 접근 차단 | 중 |

## 5. 보안 관리

| 항목코드 | 점검항목 | 중요도 |
|---------|---------|--------|
| W-36 | 백신 프로그램 설치 | 상 |
| W-37 | SAM 파일 접근 통제 설정 | 상 |
| W-38 | 화면보호기 설정 | 상 |
| W-39 | 로그온 하지 않고 시스템 종료 허용 해제 | 상 |
| W-40 | 원격 시스템에서 강제로 시스템 종료 | 상 |
| W-41 | 보안감사를 로그할 수 없는 경우 즉시 시스템 종료 해제 | 상 |
| W-42 | SAM 계정과 공유의 익명 열거 허용 안함 | 상 |
| W-43 | Autologon 기능 제어 | 상 |
| W-44 | 이동식 미디어 포맷 및 꺼내기 허용 | 상 |
| W-45 | 디스크 볼륨 암호화 설정 | 상 |
| W-72 | DoS 공격 방어 레지스트리 설정 | 중 |
| W-73 | 사용자가 프린터 드라이버를 설치할 수 없게 함 | 중 |
| W-74 | 세션 연결을 중단하기 전에 필요한 유휴시간 | 중 |
| W-75 | 경고 메시지 설정 | 하 |
| W-76 | 사용자별 홈 디렉토리 권한 설정 | 중 |
| W-77 | LAN Manager 인증 수준 | 중 |
| W-78 | 보안 채널 데이터 디지털 암호화 또는 서명 | 중 |
| W-79 | 파일 및 디렉토리 보호 | 중 |
| W-80 | 컴퓨터 계정 암호 최대 사용 기간 | 중 |
| W-81 | 시작 프로그램 목록 분석 | 중 |

## 6. DB 관리

| 항목코드 | 점검항목 | 중요도 |
|---------|---------|--------|
| W-82 | Windows 인증 모드 사용 | 중 |

---

## 요약

**총 82개 항목**
- 상: 45개
- 중: 36개
- 하: 2개