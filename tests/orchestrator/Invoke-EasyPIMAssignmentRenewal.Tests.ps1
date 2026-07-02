$OrchestratorPath = Join-Path $PSScriptRoot "..\..\EasyPIM.Orchestrator\EasyPIM.Orchestrator.psd1"
Import-Module (Join-Path $PSScriptRoot "..\..\EasyPIM\EasyPIM.psd1") -Force
Import-Module $OrchestratorPath -Force

Describe "Invoke-EasyPIMAssignmentRenewal" -Tag 'Unit' {

    BeforeEach {
        $script:extendCalls = @()

        # Config: one eligible Reader assignment declared at /subscriptions/sub1
        $script:cfg = [PSCustomObject]@{
            Assignments = [PSCustomObject]@{
                AzureRoles = @(
                    [PSCustomObject]@{
                        RoleName = "Reader"
                        Scope    = "/subscriptions/sub1"
                        assignments = @(
                            [PSCustomObject]@{ principalId = "11111111-1111-1111-1111-111111111111"; assignmentType = "Eligible" }
                        )
                    }
                )
            }
        }

        Mock -ModuleName EasyPIM.Orchestrator Get-EasyPIMConfiguration { return $script:cfg }
        # Intentionally NOT mocking Initialize-EasyPIMAssignments: the real normalizer must run
        # so the function exercises the normalized flat arrays ($processed.AzureRoles / .AzureRolesActive).

        # One live eligible assignment expiring in 5 days (inside the 14-day window)
        Mock -ModuleName EasyPIM.Orchestrator Get-PIMAzureResourceEligibleAssignment {
            return @([PSCustomObject]@{
                PrincipalId = "11111111-1111-1111-1111-111111111111"
                RoleName    = "Reader"
                ScopeId     = "/subscriptions/sub1"
                Status      = "Provisioned"
                endDateTime = (Get-Date).ToUniversalTime().AddDays(5).ToString("yyyy-MM-ddTHH:mm:ssZ")
                id          = "/subscriptions/sub1/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/inst-guid"
            })
        }
        Mock -ModuleName EasyPIM.Orchestrator Get-PIMAzureResourceActiveAssignment { return @() }

        Mock -ModuleName EasyPIM.Orchestrator Get-PIMAzureResourcePolicy {
            return [PSCustomObject]@{
                MaximumEligibleAssignmentDuration = "P365D"
                AllowPermanentEligibleAssignment  = "false"
                MaximumActiveAssignmentDuration   = "P30D"
                AllowPermanentActiveAssignment    = "false"
            }
        }

        Mock -ModuleName EasyPIM.Orchestrator Update-PIMAzureResourceEligibleAssignment {
            param($tenantID, $subscriptionID, $scope, $principalID, $rolename, $newEndDateTime, $justification)
            $script:extendCalls += [PSCustomObject]@{ role = $rolename; principal = $principalID; newEnd = $newEndDateTime }
        }
        Mock -ModuleName EasyPIM.Orchestrator Update-PIMAzureResourceActiveAssignment {}
    }

    It "Extends an eligible assignment expiring within the threshold" {
        $result = Invoke-EasyPIMAssignmentRenewal -ConfigFilePath "dummy.json" `
            -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "sub1"

        $script:extendCalls.Count | Should -Be 1
        $script:extendCalls[0].role | Should -Be "Reader"
        $result.Extended | Should -Be 1
        $result.FoundExpiring | Should -Be 1
    }

    It "Does not call the core extend cmdlet under -WhatIf" {
        $result = Invoke-EasyPIMAssignmentRenewal -ConfigFilePath "dummy.json" `
            -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "sub1" -WhatIf

        $script:extendCalls.Count | Should -Be 0
        $result.FoundExpiring | Should -Be 1
    }

    It "Skips assignments not expiring within the threshold" {
        Mock -ModuleName EasyPIM.Orchestrator Get-PIMAzureResourceEligibleAssignment {
            return @([PSCustomObject]@{
                PrincipalId = "11111111-1111-1111-1111-111111111111"
                RoleName    = "Reader"
                ScopeId     = "/subscriptions/sub1"
                Status      = "Provisioned"
                endDateTime = (Get-Date).ToUniversalTime().AddDays(90).ToString("yyyy-MM-ddTHH:mm:ssZ")
                id          = "inst-guid"
            })
        }

        $result = Invoke-EasyPIMAssignmentRenewal -ConfigFilePath "dummy.json" `
            -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "sub1"

        $script:extendCalls.Count | Should -Be 0
        $result.FoundExpiring | Should -Be 0
    }

    It "Ignores live assignments not declared in config" {
        Mock -ModuleName EasyPIM.Orchestrator Get-PIMAzureResourceEligibleAssignment {
            return @([PSCustomObject]@{
                PrincipalId = "99999999-9999-9999-9999-999999999999"  # not in config
                RoleName    = "Reader"
                ScopeId     = "/subscriptions/sub1"
                Status      = "Provisioned"
                endDateTime = (Get-Date).ToUniversalTime().AddDays(5).ToString("yyyy-MM-ddTHH:mm:ssZ")
                id          = "inst-guid"
            })
        }

        $result = Invoke-EasyPIMAssignmentRenewal -ConfigFilePath "dummy.json" `
            -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "sub1"

        $script:extendCalls.Count | Should -Be 0
        $result.FoundExpiring | Should -Be 0
    }
}
