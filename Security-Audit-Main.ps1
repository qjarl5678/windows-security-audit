# -*- coding: utf-8 -*-
param(
    [switch]$QuickCheck,
    [switch]$DetailedReport,
    [string]$OutputPath = ".\Reports"
)

# KISA Security Assessment - Windows Security Audit Script (English)
# Author: Security Audit Team
# Version: 1.0
# Date: 2024

# UTF-8 output configuration (safe defaults)
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

try {
    chcp 65001 | Out-Null
    [System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
} catch {
}

# Require Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Globals
$Script:StartTime = Get-Date
$Script:LogPath = ".\Logs"
$Script:ReportPath = if ($OutputPath) { $OutputPath } else { ".\Reports" }
$Script:LogFile = "$Script:LogPath\Security-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:Results = @{}

# Ensure folders
Write-Host "Log Path: $Script:LogPath" -ForegroundColor Gray
Write-Host "Report Path: $Script:ReportPath" -ForegroundColor Gray

if (!(Test-Path $Script:LogPath)) {
    try {
        New-Item -ItemType Directory -Path $Script:LogPath -Force | Out-Null
        Write-Host "Logs folder created." -ForegroundColor Green
    } catch {
        Write-Host "Failed to create Logs folder: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Logs folder exists." -ForegroundColor Green
}

if (!(Test-Path $Script:ReportPath)) {
    try {
        New-Item -ItemType Directory -Path $Script:ReportPath -Force | Out-Null
        Write-Host "Reports folder created." -ForegroundColor Green
    } catch {
        Write-Host "Failed to create Reports folder: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Reports folder exists." -ForegroundColor Green
}

# Start transcript (session log)
try {
    $transcriptPath = Join-Path $Script:LogPath ("Transcript-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt")
    Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Null
    Write-Host "Transcript: $transcriptPath" -ForegroundColor Gray
} catch {
    Write-Host "Transcript could not be started: $($_.Exception.Message)" -ForegroundColor Yellow
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    $LogMessage | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
}

function Save-Result {
    param([string]$Category, [string]$Item, [string]$Status, [string]$Details = "", [string]$Risk = "LOW", [string]$ItemCode = "")
    if (-not $Script:Results.ContainsKey($Category)) {
        $Script:Results[$Category] = @()
    }
    $Script:Results[$Category] += @{
        ItemCode = $ItemCode
        Item = $Item
        Status = $Status
        Details = $Details
        Risk = $Risk
        Timestamp = Get-Date
    }
}

function Generate-HTMLReport {
    $ReportFile = "$Script:ReportPath\Security-Audit-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KISA Security Assessment - Technical Checks Report</title>
    <style>
        body { font-family: Arial, 'Segoe UI', 'Malgun Gothic', sans-serif; margin: 20px; background-color: #f5f5f5; }
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
            <h1>KISA Security Assessment - Technical Checks Report</h1>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>Hostname: $env:COMPUTERNAME</p>
        </div>
        
        <div class="summary">
            <div class="summary-card high">
                <h3>High Risk</h3>
                <div style="font-size: 2em; font-weight: bold;">$(($Script:Results.Values | ForEach-Object { $_ } | Where-Object { $_.Risk -eq "HIGH" }).Count)</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Risk</h3>
                <div style="font-size: 2em; font-weight: bold;">$(($Script:Results.Values | ForEach-Object { $_ } | Where-Object { $_.Risk -eq "MEDIUM" }).Count)</div>
            </div>
            <div class="summary-card low">
                <h3>Low Risk</h3>
                <div style="font-size: 2em; font-weight: bold;">$(($Script:Results.Values | ForEach-Object { $_ } | Where-Object { $_.Risk -eq "LOW" }).Count)</div>
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
            $riskValue = if ($Result.Risk) { $Result.Risk.ToLower() } else { "low" }
            $RiskClass = "risk-$riskValue"
            $codeDisplay = if ($Result.ItemCode) { "[$($Result.ItemCode)] " } else { "" }

            $HTML += @"
            <div class="item $StatusClass">
                <strong>$codeDisplay$($Result.Item)</strong> -
                <span class="$RiskClass">$($Result.Status)</span>
                <br><small>$($Result.Details)</small>
            </div>
"@
        }
        $HTML += "</div>"
    }

    $HTML += @"
        <div class="footer">
            <p>This report was automatically generated to prepare for KISA security assessment.</p>
            <p>Elapsed time: $((Get-Date) - $Script:StartTime)</p>
        </div>
    </div>
</body>
</html>
"@

    if (!(Test-Path $Script:ReportPath)) {
        New-Item -ItemType Directory -Path $Script:ReportPath -Force | Out-Null
    }

    $HTML | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Log "HTML report generated: $ReportFile"
    Write-Host "Report file: $ReportFile" -ForegroundColor Cyan

    # Generate PDF from HTML
    $PDFFile = Convert-HTMLToPDF -HTMLFile $ReportFile
    if ($PDFFile) {
        Write-Host "PDF report: $PDFFile" -ForegroundColor Cyan
    }

    return $ReportFile
}

function Convert-HTMLToPDF {
    param([string]$HTMLFile)

    $PDFFile = $HTMLFile -replace '\.html$', '.pdf'

    Write-Host "Generating PDF report..." -ForegroundColor Yellow

    try {
        # Try Microsoft Edge first (most common on Windows 10/11)
        $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        if (!(Test-Path $edgePath)) {
            $edgePath = "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        }

        if (Test-Path $edgePath) {
            Write-Host "Using Microsoft Edge to generate PDF..." -ForegroundColor Cyan
            $process = Start-Process -FilePath $edgePath -ArgumentList "--headless", "--disable-gpu", "--print-to-pdf=`"$PDFFile`"", "`"$HTMLFile`"" -Wait -PassThru -WindowStyle Hidden

            if ($process.ExitCode -eq 0 -and (Test-Path $PDFFile)) {
                Write-Log "PDF report generated: $PDFFile"
                return $PDFFile
            }
        }

        # Try Google Chrome as fallback
        $chromePaths = @(
            "C:\Program Files\Google\Chrome\Application\chrome.exe",
            "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
        )

        foreach ($chromePath in $chromePaths) {
            if (Test-Path $chromePath) {
                Write-Host "Using Google Chrome to generate PDF..." -ForegroundColor Cyan
                $process = Start-Process -FilePath $chromePath -ArgumentList "--headless", "--disable-gpu", "--print-to-pdf=`"$PDFFile`"", "`"$HTMLFile`"" -Wait -PassThru -WindowStyle Hidden

                if ($process.ExitCode -eq 0 -and (Test-Path $PDFFile)) {
                    Write-Log "PDF report generated: $PDFFile"
                    return $PDFFile
                }
            }
        }

        Write-Host "Unable to generate PDF: Edge or Chrome not found" -ForegroundColor Yellow
        Write-Host "You can manually open the HTML file in a browser and print to PDF" -ForegroundColor Yellow
        Write-Log "PDF generation skipped: Browser not found"
        return $null

    } catch {
        Write-Host "PDF generation failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log "PDF generation error: $($_.Exception.Message)"
        return $null
    }
}

function Start-SecurityAudit {
    Write-Log "Starting security checks..." "INFO"

    $Categories = @(
        "Account-Security-Check.ps1",
        "System-Security-Check.ps1",
        "Service-Security-Check.ps1",
        "Network-Security-Check.ps1",
        "IIS-Security-Check.ps1",
        "Log-Security-Check.ps1",
        "DB-Security-Check.ps1"
    )

    $total = $Categories.Count
    $i = 0
    Write-Progress -Activity "Security Audit" -Status "Preparing..." -PercentComplete 0
    
    foreach ($scriptName in $Categories) {
        $i++
        $percent = [int](($i-1) / $total * 100)
        Write-Progress -Activity "Security Audit" -Status "Running $scriptName ($i of $total)" -PercentComplete $percent
        if (Test-Path $scriptName) {
            Write-Log "Running $scriptName ..." "INFO"
            try {
                . ".\$scriptName"
                Write-Log "$scriptName completed" "INFO"
            }
            catch {
                Write-Log "Error while running ${scriptName}: $($_.Exception.Message)" "ERROR"
            }
        }
        else {
            Write-Log "$scriptName not found" "WARNING"
        }
    }

    Write-Progress -Activity "Security Audit" -Status "Generating report..." -PercentComplete 95
    $ReportFile = Generate-HTMLReport
    Write-Log "Security checks finished. Report: $ReportFile" "INFO"
    Write-Progress -Activity "Security Audit" -Completed
    
    $AllItems = $Script:Results.Values | ForEach-Object { $_ }
    $TotalItems = @($AllItems).Count
    $HighRisk = @($AllItems | Where-Object { $_.Risk -eq "HIGH" }).Count
    $MediumRisk = @($AllItems | Where-Object { $_.Risk -eq "MEDIUM" }).Count
    $LowRisk = @($AllItems | Where-Object { $_.Risk -eq "LOW" }).Count
    
    Write-Host "`n=== Security Audit Completed ===" -ForegroundColor Green
    Write-Host "Total Items: $TotalItems" -ForegroundColor White
    Write-Host "High Risk: $HighRisk" -ForegroundColor Red
    Write-Host "Medium Risk: $MediumRisk" -ForegroundColor Yellow
    Write-Host "Low Risk: $LowRisk" -ForegroundColor Green
    Write-Host ""
    Write-Host "Report Location:" -ForegroundColor Cyan
    Write-Host "   $ReportFile" -ForegroundColor White

    $AbsolutePath = (Resolve-Path $ReportFile -ErrorAction SilentlyContinue)
    if ($AbsolutePath) {
        Write-Host "   Full Path: $AbsolutePath" -ForegroundColor Gray
    }
}

Write-Host "KISA Security Assessment Tool v1.0" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$Script:Results = @{
    "Account Security" = @()
    "System Security" = @()
    "Service Security" = @()
    "Network Security" = @()
    "IIS Security" = @()
    "Log Security" = @()
    "Database Security" = @()
}

Start-SecurityAudit

Write-Host "`n=== Execution completed ===" -ForegroundColor Green
Write-Host "Press any key to close this window..." -ForegroundColor Yellow

try {
    if ($Host.Name -eq "ConsoleHost") {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } else {
        throw "Not ConsoleHost"
    }
} catch {
    try {
        Read-Host "`nType anything and press Enter"
    } catch {
        cmd /c pause
    }
}

# Stop transcript
try { Stop-Transcript | Out-Null } catch {}
