# KISA 보안 심사용 통합 보안 점검 스크립트
# Windows Security Audit Script for KISA Security Assessment
# 작성자: Security Audit Team
# 버전: 1.0
# 날짜: 2024

# UTF-8 인코딩 설정
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

param(
    [switch]$QuickCheck,
    [switch]$DetailedReport,
    [string]$OutputPath = ".\Reports"
)

# 스크립트 실행 전 관리자 권한 확인
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "이 스크립트는 관리자 권한으로 실행해야 합니다."
    exit 1
}

# 전역 변수 설정
$Script:StartTime = Get-Date
$Script:LogPath = ".\Logs"
$Script:ReportPath = $OutputPath
$Script:Results = @{}

# 로그 및 보고서 디렉토리 생성
if (!(Test-Path $Script:LogPath)) { New-Item -ItemType Directory -Path $Script:LogPath -Force }
if (!(Test-Path $Script:ReportPath)) { New-Item -ItemType Directory -Path $Script:ReportPath -Force }

# 로그 함수
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    $LogMessage | Out-File -FilePath "$Script:LogPath\Security-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append
}

# 결과 저장 함수
function Save-Result {
    param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW")
    if (-not $Script:Results.ContainsKey($Category)) {
        $Script:Results[$Category] = @()
    }
    $Script:Results[$Category] += @{
        Item = $Item
        Status = $Status
        Details = $Details
        Risk = $Risk
        Timestamp = Get-Date
    }
}

# HTML 보고서 생성 함수
function Generate-HTMLReport {
    $ReportFile = "$Script:ReportPath\Security-Audit-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    
    $HTML = @"
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KISA 보안 심사 점검 보고서</title>
    <style>
        body { font-family: 'Malgun Gothic', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007acc; }
        .summary-card.high { border-left-color: #dc3545; }
        .summary-card.medium { border-left-color: #ffc107; }
        .summary-card.low { border-left-color: #28a745; }
        .category { margin-bottom: 30px; }
        .category h3 { background: #007acc; color: white; padding: 10px 15px; margin: 0; border-radius: 4px 4px 0 0; }
        .item { background: #f8f9fa; margin: 0; padding: 15px; border-left: 4px solid #dee2e6; }
        .item.pass { border-left-color: #28a745; }
        .item.fail { border-left-color: #dc3545; }
        .item.warning { border-left-color: #ffc107; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ KISA 보안 심사 점검 보고서</h1>
            <p>생성일시: $(Get-Date -Format 'yyyy년 MM월 dd일 HH:mm:ss')</p>
            <p>서버명: $env:COMPUTERNAME</p>
        </div>
        
        <div class="summary">
            <div class="summary-card high">
                <h3>🔴 높은 위험</h3>
                <div style="font-size: 2em; font-weight: bold;">$($Script:Results.Values | Where-Object { $_.Risk -eq "HIGH" } | Measure-Object).Count</div>
            </div>
            <div class="summary-card medium">
                <h3>🟡 중간 위험</h3>
                <div style="font-size: 2em; font-weight: bold;">$($Script:Results.Values | Where-Object { $_.Risk -eq "MEDIUM" } | Measure-Object).Count</div>
            </div>
            <div class="summary-card low">
                <h3>🟢 낮은 위험</h3>
                <div style="font-size: 2em; font-weight: bold;">$($Script:Results.Values | Where-Object { $_.Risk -eq "LOW" } | Measure-Object).Count</div>
            </div>
        </div>
"@

    foreach ($Category in $Script:Results.Keys) {
        $HTML += "<div class='category'><h3>$Category</h3>"
        foreach ($Result in $Script:Results[$Category]) {
            $StatusClass = switch ($Result.Status) {
                "PASS" { "pass" }
                "FAIL" { "fail" }
                "WARNING" { "warning" }
                default { "" }
            }
            $RiskClass = "risk-$($Result.Risk.ToLower())"
            
            $HTML += @"
            <div class="item $StatusClass">
                <strong>$($Result.Item)</strong> - 
                <span class="$RiskClass">$($Result.Status)</span>
                <br><small>$($Result.Details)</small>
            </div>
"@
        }
        $HTML += "</div>"
    }

    $HTML += @"
        <div class="footer">
            <p>이 보고서는 KISA 보안 심사 준비를 위해 자동 생성되었습니다.</p>
            <p>보고서 생성 시간: $((Get-Date) - $Script:StartTime)</p>
        </div>
    </div>
</body>
</html>
"@

    $HTML | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Log "HTML 보고서가 생성되었습니다: $ReportFile"
    return $ReportFile
}

# 메인 실행 함수
function Start-SecurityAudit {
    Write-Log "KISA 보안 심사 점검을 시작합니다..." "INFO"
    
    # 각 카테고리별 점검 실행
    $Categories = @(
        "Account-Security-Check.ps1",
        "System-Security-Check.ps1", 
        "Network-Security-Check.ps1",
        "Log-Security-Check.ps1"
    )
    
    foreach ($Script in $Categories) {
        if (Test-Path $Script) {
            Write-Log "$Script 실행 중..." "INFO"
            try {
                & ".\$Script"
                Write-Log "$Script 실행 완료" "INFO"
            }
            catch {
                Write-Log "$Script 실행 중 오류 발생: $($_.Exception.Message)" "ERROR"
            }
        }
        else {
            Write-Log "$Script 파일을 찾을 수 없습니다." "WARNING"
        }
    }
    
    # HTML 보고서 생성
    $ReportFile = Generate-HTMLReport
    Write-Log "보안 점검 완료. 보고서: $ReportFile" "INFO"
    
    # 요약 정보 출력
    $TotalItems = ($Script:Results.Values | Measure-Object).Count
    $HighRisk = ($Script:Results.Values | Where-Object { $_.Risk -eq "HIGH" } | Measure-Object).Count
    $MediumRisk = ($Script:Results.Values | Where-Object { $_.Risk -eq "MEDIUM" } | Measure-Object).Count
    $LowRisk = ($Script:Results.Values | Where-Object { $_.Risk -eq "LOW" } | Measure-Object).Count
    
    Write-Host "`n=== 보안 점검 완료 ===" -ForegroundColor Green
    Write-Host "총 점검 항목: $TotalItems" -ForegroundColor White
    Write-Host "높은 위험: $HighRisk" -ForegroundColor Red
    Write-Host "중간 위험: $MediumRisk" -ForegroundColor Yellow  
    Write-Host "낮은 위험: $LowRisk" -ForegroundColor Green
    Write-Host "보고서 파일: $ReportFile" -ForegroundColor Cyan
}

# 스크립트 시작
Write-Host "🛡️ KISA 보안 심사 점검 도구 v1.0" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# 결과 저장소 초기화
$Script:Results = @{
    "계정 보안" = @()
    "시스템 보안" = @()
    "네트워크 보안" = @()
    "로그 보안" = @()
}

Start-SecurityAudit
