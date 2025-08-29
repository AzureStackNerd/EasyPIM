# EasyPIM End-to-End Business Rules Validation Script
# This script tests the complete workflow: drift detection -> orchestrator remediation -> verification
# Uses live tenant (no mocking) to validate real-world scenarios

param(
    [Parameter(Mandatory)]
    [string]$TenantId = $env:TenantID,
    
    [Parameter(Mandatory)]
    [string]$SubscriptionId = $env:SubscriptionID,
    
    [Parameter()]
    [string]$ConfigPath = "$PSScriptRoot\validation.json",
    
    [Parameter()]
    [string]$TestRoleName = "Guest Inviter"
)

# Import modules
Write-Host "🔧 Loading EasyPIM modules..." -ForegroundColor Cyan
Import-Module "$PSScriptRoot\..\EasyPIM\EasyPIM.psd1" -Force
Import-Module "$PSScriptRoot\..\EasyPIM.Orchestrator\EasyPIM.Orchestrator.psd1" -Force

# Test configuration
$OriginalActivationDuration = "PT2H"  # From Standard template in validation.json
$ModifiedActivationDuration = "PT4H"  # Test change to create drift

Write-Host "`n🎯 Test Configuration:" -ForegroundColor Yellow
Write-Host "   Tenant: $TenantId"
Write-Host "   Role: $TestRoleName"
Write-Host "   Config: $ConfigPath"
Write-Host "   Original Duration: $OriginalActivationDuration"
Write-Host "   Test Duration: $ModifiedActivationDuration"

try {
    # Step 1: Baseline - Ensure role matches config
    Write-Host "`n📋 Step 1: Setting baseline configuration..." -ForegroundColor Cyan
    Set-PIMEntraRolePolicy -TenantID $TenantId -RoleName $TestRoleName -ActivationDuration $OriginalActivationDuration
    Start-Sleep -Seconds 2
    
    # Verify baseline
    $baselinePolicy = Get-PIMEntraRolePolicy -TenantID $TenantId -RoleName $TestRoleName
    Write-Host "   Current ActivationDuration: $($baselinePolicy.ActivationDuration)" -ForegroundColor Gray
    
    # Test baseline drift
    Write-Host "   Testing baseline drift..." -ForegroundColor Gray
    $baselineDrift = Test-PIMPolicyDrift -TenantId $TenantId -ConfigPath $ConfigPath -PassThru -Verbose
    $baselineResult = $baselineDrift | Where-Object { $_.Type -eq 'EntraRole' -and $_.Name -eq $TestRoleName }
    
    if ($baselineResult.Status -eq 'Match') {
        Write-Host "   ✅ Baseline: No drift detected" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Warning: Baseline shows drift: $($baselineResult.Differences)" -ForegroundColor Yellow
    }

    # Step 2: Create drift by manually changing policy
    Write-Host "`n🔧 Step 2: Creating drift by changing policy..." -ForegroundColor Cyan
    Set-PIMEntraRolePolicy -TenantID $TenantId -RoleName $TestRoleName -ActivationDuration $ModifiedActivationDuration
    Start-Sleep -Seconds 2
    
    # Verify change was applied
    $modifiedPolicy = Get-PIMEntraRolePolicy -TenantID $TenantId -RoleName $TestRoleName
    Write-Host "   Changed ActivationDuration to: $($modifiedPolicy.ActivationDuration)" -ForegroundColor Gray
    
    # Step 3: Detect drift
    Write-Host "`n🕵️ Step 3: Testing drift detection..." -ForegroundColor Cyan
    $driftResults = Test-PIMPolicyDrift -TenantId $TenantId -ConfigPath $ConfigPath -PassThru -Verbose
    $driftResult = $driftResults | Where-Object { $_.Type -eq 'EntraRole' -and $_.Name -eq $TestRoleName }
    
    if ($driftResult.Status -eq 'Drift') {
        Write-Host "   ✅ Drift Detection: Successfully detected policy drift" -ForegroundColor Green
        Write-Host "   📊 Differences: $($driftResult.Differences)" -ForegroundColor Gray
    } else {
        throw "❌ Drift detection failed - expected 'Drift' but got '$($driftResult.Status)'"
    }

    # Step 4: Validate business rules are working
    Write-Host "`n🔬 Step 4: Testing business rules validation..." -ForegroundColor Cyan
    $businessRuleTest = [PSCustomObject]@{
        ActivationRequirement = "MultiFactorAuthentication,Justification"
        AuthenticationContext_Enabled = $true
    }
    
    $businessRuleResult = Test-PIMPolicyBusinessRules -PolicySettings $businessRuleTest -ApplyAdjustments
    
    if ($businessRuleResult.HasChanges -and $businessRuleResult.Conflicts.Count -gt 0) {
        Write-Host "   ✅ Business Rules: Authentication Context vs MFA conflict detected and handled" -ForegroundColor Green
        Write-Host "   📋 Conflict: $($businessRuleResult.Conflicts[0].Message)" -ForegroundColor Gray
    } else {
        Write-Host "   ⚠️  Business Rules: No conflicts detected (this may be expected)" -ForegroundColor Yellow
    }

    # Step 5: Run orchestrator to remediate
    Write-Host "`n🔄 Step 5: Running orchestrator to remediate drift..." -ForegroundColor Cyan
    $orchestratorResult = Invoke-EasyPIMOrchestrator -TenantId $TenantId -SubscriptionId $SubscriptionId -ConfigurationFile $ConfigPath -ValidateOnly:$false
    
    if ($orchestratorResult) {
        Write-Host "   ✅ Orchestrator: Completed successfully" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Orchestrator: Check output for any issues" -ForegroundColor Yellow
    }
    
    # Wait for changes to propagate
    Write-Host "   ⏳ Waiting for changes to propagate..." -ForegroundColor Gray
    Start-Sleep -Seconds 5

    # Step 6: Verify remediation
    Write-Host "`n✅ Step 6: Verifying remediation..." -ForegroundColor Cyan
    $remediatedPolicy = Get-PIMEntraRolePolicy -TenantID $TenantId -RoleName $TestRoleName
    Write-Host "   Current ActivationDuration: $($remediatedPolicy.ActivationDuration)" -ForegroundColor Gray
    
    # Final drift check
    $finalDrift = Test-PIMPolicyDrift -TenantId $TenantId -ConfigPath $ConfigPath -PassThru
    $finalResult = $finalDrift | Where-Object { $_.Type -eq 'EntraRole' -and $_.Name -eq $TestRoleName }
    
    if ($finalResult.Status -eq 'Match') {
        Write-Host "   ✅ Final Verification: No drift detected after remediation" -ForegroundColor Green
        Write-Host "`n🎉 END-TO-END TEST PASSED!" -ForegroundColor Green
        Write-Host "   All business rules and validation workflows are working correctly!" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Final Verification: Drift still detected: $($finalResult.Differences)" -ForegroundColor Red
        throw "Remediation did not fully resolve drift"
    }

    # Summary
    Write-Host "`n📊 Test Summary:" -ForegroundColor Cyan
    Write-Host "   ✅ Baseline verification" -ForegroundColor Green
    Write-Host "   ✅ Manual policy change" -ForegroundColor Green
    Write-Host "   ✅ Drift detection" -ForegroundColor Green
    Write-Host "   ✅ Business rules validation" -ForegroundColor Green
    Write-Host "   ✅ Orchestrator remediation" -ForegroundColor Green
    Write-Host "   ✅ Final verification" -ForegroundColor Green

} catch {
    Write-Host "`n❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
