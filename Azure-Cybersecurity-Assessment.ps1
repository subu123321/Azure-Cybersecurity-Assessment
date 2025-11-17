# Azure-Cybersecurity-Assessment.ps1
# Fully automatic — no Log Analytics input needed
# Covers Identity, IaaS, PaaS, Network, Defender, Governance

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

$ErrorActionPreference = "Stop"
$reportSections = @()

# === LOAD MODULES ===
$azModules = @("Az.Accounts", "Az.Resources", "Az.Security", "Az.Compute", "Az.Network", "Az.Storage", "Az.Sql", "Az.KeyVault", "Az.Monitor", "Az.PolicyInsights", "Az.RecoveryServices", "Az.OperationalInsights")
$graphModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns", "Microsoft.Graph.Identity.Governance", "Microsoft.Graph.Applications")

foreach ($mod in $azModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "[!] Please install: Install-Module $mod -Scope CurrentUser -Force" -ForegroundColor Red
        exit 1
    }
    Import-Module $mod -Force
}

# === CONNECT ===
Write-Host "[+] Connecting to Azure..." -ForegroundColor Cyan
Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId | Out-Null
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

Write-Host "[+] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All" -TenantId $TenantId | Out-Null

# === AUTO-DISCOVER LOG ANALYTICS WORKSPACES ===
Write-Host "[+] Discovering Log Analytics workspaces..." -ForegroundColor Cyan
$laWorkspaces = Get-AzOperationalInsightsWorkspace
Write-Host "    → Found $($laWorkspaces.Count) workspace(s)" -ForegroundColor Green

# Function to query patches across all LA workspaces
function Get-VMPatchStatus {
    param([string]$VMName, [string]$OSType)

    if ($laWorkspaces.Count -eq 0) { return "No LA workspace" }

    foreach ($ws in $laWorkspaces) {
        try {
            if ($OSType -eq "Windows") {
                $query = "Update | where Computer has '$VMName' and UpdateState == 'Needed' | summarize count() | project Count"
            } else {
                $query = "UpdateSummary | where Computer has '$VMName' | project CriticalUpdatesMissing + SecurityUpdatesMissing"
            }

            $result = Invoke-AzOperationalInsightsQuery -WorkspaceName $ws.Name -ResourceGroupName $ws.ResourceGroupName -Query $query -Timespan (New-TimeSpan -Days 7) -ErrorAction Stop

            if ($result.Results) {
                if ($OSType -eq "Windows") {
                    $missing = [int]$result.Results[0].Count
                } else {
                    $missing = [int]$result.Results[0].Column1
                }
                return if ($missing -gt 0) { "$missing missing" } else { "Compliant" }
            }
        } catch {
            # Try next workspace
        }
    }
    return "No data in LA"
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"

# === 1. IDENTITY & ACCESS (ENTRA ID) ===
Write-Host "[+] Assessing Entra ID..." -ForegroundColor Green
$identityFindings = @()

# Global Admins without MFA
$globalAdminRole = "62e90394-69f5-4237-9190-012177145e10"
$globalAdmins = Get-MgRoleManagementDirectoryRoleAssignment -All | Where-Object { $_.RoleDefinitionId -eq $globalAdminRole }
$adminsWithoutMFA = 0
foreach ($admin in $globalAdmins) {
    $methods = Get-MgUserAuthenticationMethod -UserId $admin.PrincipalId -ErrorAction SilentlyContinue
    if (-not $methods) { $adminsWithoutMFA++ }
}
$identityFindings += if ($adminsWithoutMFA -gt 0) {
    @{Check = "Global Admins without MFA"; Status = "High"; Details = "$adminsWithoutMFA admins" }
} else {
    @{Check = "Global Admin MFA Enforcement"; Status = "Low"; Details = "All admins secured" }
}

# Legacy Auth (last 24h)
$legacySignIns = Get-MgAuditLogSignIn -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000' or AppId eq '00000006-0000-0ff1-ce00-000000000000'" -Top 5 -ErrorAction SilentlyContinue
$identityFindings += if ($legacySignIns) {
    @{Check = "Legacy Authentication (IMAP/SMTP)"; Status = "High"; Details = "Detected in last 24h" }
} else {
    @{Check = "Legacy Authentication"; Status = "Low"; Details = "Not detected recently" }
}

# Guest Users
$guests = Get-MgUser -All -Filter "userType eq 'Guest'" -CountVariable guestCount -ErrorAction SilentlyContinue
$identityFindings += @{Check = "External Guest Users"; Status = if ($guestCount -gt 10) { "Medium" } else { "Low" }; Details = "$guestCount guests" }

# === 2. COMPUTE (VMs) ===
Write-Host "[+] Assessing Virtual Machines..." -ForegroundColor Green
$computeFindings = @()
$vms = Get-AzVM

foreach ($vm in $vms) {
    $rg = $vm.ResourceGroupName
    $vmName = $vm.Name
    $osType = $vm.StorageProfile.OsDisk.OsType

    # Disk Encryption
    $disk = Get-AzDisk -ResourceGroupName $rg -DiskName $vm.StorageProfile.OsDisk.Name
    if ($disk.Encryption.Type -notlike "*Customer*") {
        $computeFindings += @{Resource = $vmName; Check = "Disk Encryption"; Status = "Medium"; Details = "Platform-managed only" }
    }

    # Backup
    $protected = $false
    $vaults = Get-AzRecoveryServicesVault
    foreach ($vault in $vaults) {
        Set-AzRecoveryServicesVaultContext -Vault $vault | Out-Null
        $item = Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType VM -ErrorAction SilentlyContinue |
                Where-Object { $_.ContainerName -like "*$vmName*" -and $_.ProtectionStatus -eq "Healthy" }
        if ($item) { $protected = $true; break }
    }
    if (-not $protected) {
        $computeFindings += @{Resource = $vmName; Check = "Backup Protection"; Status = "High"; Details = "Not enabled" }
    }

    # Patch Status
    $patchStatus = Get-VMPatchStatus -VMName $vmName -OSType $osType
    $patchRisk = switch -Wildcard ($patchStatus) {
        "Compliant" { "Low" }
        "No *" { "Unknown" }
        default { if ([int]($patchStatus -replace '\D') -gt 5) { "High" } else { "Medium" } }
    }
    $computeFindings += @{Resource = $vmName; Check = "Patch Compliance"; Status = $patchRisk; Details = $patchStatus }
}

# === 3. PaaS SERVICES ===
Write-Host "[+] Assessing PaaS Resources..." -ForegroundColor Green
$paaSFindings = @()

# Storage Accounts
foreach ($sa in Get-AzStorageAccount) {
    if (-not $sa.EnableHttpsTrafficOnly) {
        $paaSFindings += @{Resource = $sa.StorageAccountName; Check = "Storage - HTTPS Only"; Status = "High"; Details = "Disabled" }
    }
    if ($sa.MinimumTlsVersion -ne "TLS1_2") {
        $paaSFindings += @{Resource = $sa.StorageAccountName; Check = "Storage - TLS 1.2"; Status = "Medium"; Details = "Not enforced" }
    }
}

# SQL Servers
foreach ($sql in Get-AzSqlServer) {
    $auditing = Get-AzSqlServerAuditing -ResourceGroupName $sql.ResourceGroupName -ServerName $sql.ServerName -ErrorAction SilentlyContinue
    if (-not $auditing.AuditState -eq "Enabled") {
        $paaSFindings += @{Resource = $sql.ServerName; Check = "SQL Auditing"; Status = "High"; Details = "Disabled" }
    }
}

# Key Vaults
foreach ($kv in Get-AzKeyVault) {
    if (-not $kv.SoftDeleteEnabled) {
        $paaSFindings += @{Resource = $kv.VaultName; Check = "Key Vault - Soft Delete"; Status = "High"; Details = "Off" }
    }
    if (-not $kv.EnablePurgeProtection) {
        $paaSFindings += @{Resource = $kv.VaultName; Check = "Key Vault - Purge Protection"; Status = "High"; Details = "Off" }
    }
}

# === 4. NETWORK ===
Write-Host "[+] Assessing Network..." -ForegroundColor Green
$networkFindings = @()

$publicIPs = Get-AzPublicIpAddress
if ($publicIPs.Count -gt 0) {
    $networkFindings += @{Resource = "Public IPs"; Check = "Public-Facing Resources"; Status = "Medium"; Details = "$($publicIPs.Count) found" }
}

$vnets = Get-AzVirtualNetwork
$ddosProtected = $vnets | Where-Object { $_.DdosProtectionPlan }
if ($vnets.Count -gt 0 -and -not $ddosProtected) {
    $networkFindings += @{Resource = "Virtual Networks"; Check = "DDoS Protection"; Status = "Medium"; Details = "Not enabled" }
}

# === 5. DEFENDER FOR CLOUD ===
Write-Host "[+] Fetching Defender for Cloud assessments..." -ForegroundColor Green
$defenderFindings = @()
try {
    $assessments = Get-AzSecurityAssessment -ErrorAction Stop | Where-Object { $_.Status.Code -ne "Healthy" }
    $defenderFindings += @{Resource = "Defender"; Check = "Non-Healthy Assessments"; Status = "High"; Details = "$($assessments.Count) gaps" }
} catch {
    $defenderFindings += @{Resource = "Defender"; Check = "Data Retrieval"; Status = "Unknown"; Details = "Failed" }
}

# === 6. GOVERNANCE ===
Write-Host "[+] Assessing Governance..." -ForegroundColor Green
$govFindings = @()

$nonCompliant = Get-AzPolicyState -Filter "ComplianceState eq 'NonCompliant'" -Top 10 -ErrorAction SilentlyContinue
if ($nonCompliant) {
    $govFindings += @{Resource = "Azure Policy"; Check = "Non-Compliant Resources"; Status = "Medium"; Details = "$($nonCompliant.Count) violations" }
}

$resources = Get-AzResource
$noDiagCount = 0
foreach ($res in $resources) {
    $diag = Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction SilentlyContinue
    if (-not $diag) { $noDiagCount++ }
}
if ($noDiagCount -gt 0) {
    $govFindings += @{Resource = "Monitoring"; Check = "Resources Without Logs"; Status = "Medium"; Details = "$noDiagCount" }
}

# === HTML REPORT ===
$colorMap = @{
    "High" = "class='high'"
    "Medium" = "class='medium'"
    "Low" = "class='low'"
    "Unknown" = "class='unknown'"
}

function ConvertTo-HtmlRow {
    param($list)
    $html = ""
    foreach ($item in $list) {
        $html += "<tr><td>$($item.Resource)</td><td>$($item.Check)</td><td $($colorMap[$item.Status])>$($item.Status)</td><td>$($item.Details)</td></tr>"
    }
    return $html
}

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Cybersecurity Posture Assessment</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f9fbfd; }
        h1, h2 { color: #1e3a8a; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
        th, td { border: 1px solid #dbeafe; padding: 10px; text-align: left; }
        th { background-color: #2563eb; color: white; }
        .high { background-color: #fef2f2; color: #b91c1c; font-weight: bold; }
        .medium { background-color: #fffbeb; color: #b45309; }
        .low { background-color: #f0fdf4; color: #166534; }
        .unknown { background-color: #f3f4f6; color: #6b7280; }
        .summary-box { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.07); margin: 20px 0; }
    </style>
</head>
<body>
<h1>🛡️ Azure Cybersecurity Posture Assessment</h1>
<div class='summary-box'>
    <p><strong>Subscription ID:</strong> $SubscriptionId</p>
    <p><strong>Tenant ID:</strong> $TenantId</p>
    <p><strong>Assessment Time:</strong> $timestamp</p>
    <p><strong>Log Analytics Workspaces:</strong> $($laWorkspaces.Count)</p>
    <p><strong>Resources Assessed:</strong> $($vms.Count) VMs, $($paaSFindings.Count) PaaS, $($networkFindings.Count) Network</p>
</div>
"@

# Identity
$html += "<h2>1. Identity & Access (Entra ID)</h2><table><tr><th>Check</th><th>Risk</th><th>Details</th><th>Resource</th></tr>"
foreach ($f in $identityFindings) {
    $html += "<tr><td>$($f.Check)</td><td $($colorMap[$f.Status])>$($f.Status)</td><td>$($f.Details)</td><td>-</td></tr>"
}
$html += "</table>"

# Compute
$html += "<h2>2. Compute (IaaS)</h2><table><tr><th>Resource</th><th>Check</th><th>Risk</th><th>Details</th></tr>"
$html += ConvertTo-HtmlRow -list $computeFindings
$html += "</table>"

# PaaS
$html += "<h2>3. Platform (PaaS)</h2><table><tr><th>Resource</th><th>Check</th><th>Risk</th><th>Details</th></tr>"
$html += ConvertTo-HtmlRow -list $paaSFindings
$html += "</table>"

# Network
$html += "<h2>4. Network</h2><table><tr><th>Resource</th><th>Check</th><th>Risk</th><th>Details</th></tr>"
$html += ConvertTo-HtmlRow -list $networkFindings
$html += "</table>"

# Defender
$html += "<h2>5. Defender for Cloud</h2><table><tr><th>Resource</th><th>Check</th><th>Risk</th><th>Details</th></tr>"
$html += ConvertTo-HtmlRow -list $defenderFindings
$html += "</table>"

# Governance
$html += "<h2>6. Governance & Monitoring</h2><table><tr><th>Resource</th><th>Check</th><th>Risk</th><th>Details</th></tr>"
$html += ConvertTo-HtmlRow -list $govFindings
$html += "</table>"

$html += @"
<h2>📌 Notes</h2>
<div class='summary-box'>
    <ul>
        <li><strong>High</strong>: Critical risk — immediate remediation recommended.</li>
        <li><strong>Medium</strong>: Best-practice gap — should be addressed in next cycle.</li>
        <li><strong>Low</strong>: Compliant or low-impact finding.</li>
        <li>This assessment uses <b>Reader + Microsoft Graph Reader</b> permissions — no changes made.</li>
        <li>Patch data sourced from <b>all Log Analytics workspaces</b> in the subscription.</li>
    </ul>
</div>
</body>
</html>
"@

$reportPath = "Azure-Cybersecurity-Assessment-$(Get-Date -Format 'yyyyMMdd-HHmm').html"
$html | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "[+] Assessment complete!" -ForegroundColor Green
Write-Host "📄 Report saved: $reportPath" -ForegroundColor Cyan
Write-Host "💡 Open in browser to view full security posture." -ForegroundColor Yellow