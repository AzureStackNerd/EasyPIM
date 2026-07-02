<#
.SYNOPSIS
Extends Azure resource role PIM assignments (eligible and active) that are declared in an EasyPIM orchestrator
configuration and are expiring within a threshold (default 14 days).
.DESCRIPTION
Loads an EasyPIM orchestrator configuration (file or Key Vault), lists the live eligible and active Azure resource
role assignments per configured scope, keeps those that are both declared in the configuration AND expiring within
-ThresholdDays, then submits an ARM AdminExtend request for each (via Update-PIMAzureResource*Assignment). Admin
extension requires no approval, so this is safe to schedule unattended (pipeline/runbook).

The new end date is set to now + the role policy maximum assignment duration (clamped to the policy). If a role
policy allows permanent assignment but defines no maximum duration, the assignment is skipped with a note
recommending a permanent assignment instead. Assignments that exist in Azure but are not declared in the
configuration are never touched.

v1 supports Azure resource roles only. Entra directory roles and PIM-for-Groups are not yet supported.
.PARAMETER ConfigFilePath
Path to the JSON/JSONC orchestrator configuration file.
.PARAMETER KeyVaultName
Key Vault holding the configuration secret (alternative to -ConfigFilePath).
.PARAMETER SecretName
Key Vault secret name that stores the configuration.
.PARAMETER TenantId
Target tenant GUID. Falls back to $env:tenantid.
.PARAMETER SubscriptionId
Target subscription GUID. Falls back to $env:subscriptionid.
.PARAMETER ThresholdDays
Extend assignments expiring within this many days. Default 14 (matching PIM's own notification window).
.EXAMPLE
Invoke-EasyPIMAssignmentRenewal -ConfigFilePath .\pim-config-azure.jsonc -TenantId $t -SubscriptionId $s -WhatIf
Preview which declared, expiring Azure assignments would be extended.
.EXAMPLE
Invoke-EasyPIMAssignmentRenewal -ConfigFilePath .\pim-config-azure.jsonc -TenantId $t -SubscriptionId $s
Extend all declared Azure assignments expiring within 14 days.
.LINK
https://github.com/kayasax/EasyPIM
#>
function Invoke-EasyPIMAssignmentRenewal {
    [CmdletBinding(DefaultParameterSetName = 'FilePath', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'FilePath')]
        [string]$ConfigFilePath,
        [Parameter(Mandatory = $true, ParameterSetName = 'KeyVault')]
        [string]$KeyVaultName,
        [Parameter(Mandatory = $true, ParameterSetName = 'KeyVault')]
        [string]$SecretName,
        [Parameter()][string]$TenantId,
        [Parameter()][string]$SubscriptionId,
        [Parameter()][ValidateRange(1, 365)][int]$ThresholdDays = 14
    )

    Write-SectionHeader -Message "EasyPIM Assignment Renewal (threshold: $ThresholdDays days)"

    if (-not $TenantId) { $TenantId = $env:tenantid }
    if (-not $SubscriptionId) { $SubscriptionId = $env:subscriptionid }

    $summary = [pscustomobject]@{
        FoundExpiring = 0
        Extended      = 0
        Skipped       = 0
        Details       = @()
    }

    # 1. Load + normalize config
    $config = if ($PSCmdlet.ParameterSetName -eq 'KeyVault') {
        Get-EasyPIMConfiguration -KeyVaultName $KeyVaultName -SecretName $SecretName
    } else {
        Get-EasyPIMConfiguration -ConfigFilePath $ConfigFilePath
    }
    $processed = Initialize-EasyPIMAssignments -Config $config

    if (-not $processed.Assignments -or -not ($processed.Assignments.PSObject.Properties.Name -contains 'AzureRoles') -or -not $processed.Assignments.AzureRoles) {
        Write-Host "No Azure role assignments declared in configuration; nothing to renew." -ForegroundColor Yellow
        return $summary
    }

    $now = (Get-Date).ToUniversalTime()
    $cutoff = $now.AddDays($ThresholdDays)

    foreach ($roleBlock in $processed.Assignments.AzureRoles) {
        $roleName = $roleBlock.RoleName; if (-not $roleName) { $roleName = $roleBlock.roleName }
        $scope    = $roleBlock.Scope;    if (-not $scope)    { $scope = $roleBlock.scope }
        if (-not $roleName -or -not $scope) { continue }

        # Pre-fetch live assignments once per scope
        $liveEligible = @()
        $liveActive   = @()
        try { $liveEligible = @(Get-PIMAzureResourceEligibleAssignment -tenantID $TenantId -subscriptionID $SubscriptionId -scope $scope -ErrorAction SilentlyContinue) } catch { Write-Verbose "[Renewal] eligible fetch failed for ${scope}: $($_.Exception.Message)" }
        try { $liveActive   = @(Get-PIMAzureResourceActiveAssignment   -tenantID $TenantId -subscriptionID $SubscriptionId -scope $scope -ErrorAction SilentlyContinue) } catch { Write-Verbose "[Renewal] active fetch failed for ${scope}: $($_.Exception.Message)" }

        # Read policy once per role/scope
        $policy = $null
        try { $policy = Get-PIMAzureResourcePolicy -tenantID $TenantId -scope $scope -rolename $roleName } catch { Write-Verbose "[Renewal] policy fetch failed for $roleName@${scope}: $($_.Exception.Message)" }

        foreach ($a in ($roleBlock.assignments | Where-Object { $_ })) {
            $principalId = $a.principalId
            $isActive = ($a.assignmentType -match 'Active')

            # Match against live assignments of the same kind
            $liveSet = if ($isActive) { $liveActive } else { $liveEligible }
            $match = $liveSet | Where-Object {
                $_.PrincipalId -eq $principalId -and $_.RoleName -eq $roleName -and $_.ScopeId -eq $scope
            } | Select-Object -First 1
            if (-not $match) { continue }  # declared but not currently live -> New-EasyPIMAssignments handles creation, not us

            # Skip permanent / not-expiring
            if ($match.endDateTime -eq 'permanent' -or [string]::IsNullOrWhiteSpace($match.endDateTime)) { continue }
            $end = $null
            try { $end = [datetime]::Parse($match.endDateTime).ToUniversalTime() } catch { continue }
            if ($end -gt $cutoff) { continue }

            $summary.FoundExpiring++
            $ctx = "Azure/$roleName@$scope/$principalId [$($a.assignmentType)]"

            # Compute new end date from policy max
            $maxDurationIso = if ($isActive) { $policy.MaximumActiveAssignmentDuration } else { $policy.MaximumEligibleAssignmentDuration }
            $allowPermanent = if ($isActive) { $policy.AllowPermanentActiveAssignment } else { $policy.AllowPermanentEligibleAssignment }

            if ([string]::IsNullOrWhiteSpace($maxDurationIso)) {
                $reason = if ("$allowPermanent" -eq 'true') { "policy allows permanent (no max duration) - consider a permanent assignment to remove the need to extend" } else { "no maximum duration in policy" }
                Write-Host "  SKIP  $ctx : $reason" -ForegroundColor Yellow
                $summary.Skipped++
                $summary.Details += [pscustomobject]@{ Context = $ctx; Action = 'Skipped'; Reason = $reason }
                continue
            }

            $maxTs = $null
            try { $maxTs = [System.Xml.XmlConvert]::ToTimeSpan($maxDurationIso) } catch { }
            if ($null -eq $maxTs) {
                Write-Host "  SKIP  $ctx : could not parse policy max duration '$maxDurationIso'" -ForegroundColor Yellow
                $summary.Skipped++
                $summary.Details += [pscustomobject]@{ Context = $ctx; Action = 'Skipped'; Reason = "unparsable max duration '$maxDurationIso'" }
                continue
            }
            $newEnd = ($now.Add($maxTs)).ToString("yyyy-MM-ddTHH:mm:ssZ")
            if ("$allowPermanent" -eq 'true') {
                Write-Host "  NOTE  $ctx : policy allows permanent; extending to policy max ($maxDurationIso). A permanent assignment would remove the need to extend." -ForegroundColor DarkCyan
            }

            if ($WhatIfPreference) {
                Write-Host "  What if: Extend $ctx to $newEnd" -ForegroundColor Cyan
                $summary.Details += [pscustomobject]@{ Context = $ctx; Action = 'PlannedExtend'; NewEnd = $newEnd }
                continue
            }

            $params = @{
                tenantID       = $TenantId
                subscriptionID = $SubscriptionId
                scope          = $scope
                rolename       = $roleName
                principalID    = $principalId
                newEndDateTime = $newEnd
            }
            try {
                if ($isActive) { Update-PIMAzureResourceActiveAssignment @params }
                else           { Update-PIMAzureResourceEligibleAssignment @params }
                Write-Host "  EXTENDED  $ctx -> $newEnd" -ForegroundColor Green
                $summary.Extended++
                $summary.Details += [pscustomobject]@{ Context = $ctx; Action = 'Extended'; NewEnd = $newEnd }
            } catch {
                Write-Host "  FAILED  $ctx : $($_.Exception.Message)" -ForegroundColor Red
                $summary.Skipped++
                $summary.Details += [pscustomobject]@{ Context = $ctx; Action = 'Failed'; Reason = $_.Exception.Message }
            }
        }
    }

    Write-Host ""
    Write-Host "Renewal summary: FoundExpiring=$($summary.FoundExpiring) Extended=$($summary.Extended) Skipped=$($summary.Skipped)" -ForegroundColor Cyan
    return $summary
}
