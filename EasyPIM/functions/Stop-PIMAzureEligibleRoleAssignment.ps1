<#
    .Synopsis
    Stops an active PIM Azure role assignment.
    .Description
    Submits a request to stop (deactivate) an active PIM Azure role assignment for the specified principal at the given scope. Returns the API response object on success.
    .Parameter tenantID
    EntraID tenant ID (Mandatory)
    .Parameter principalId
    The object ID of the principal to deactivate the role for (Mandatory, must be a valid GUID)
    .Parameter roleName
    The name of the Azure role to deactivate (Mandatory)
    .Parameter scope
    The scope at which to deactivate the role (Mandatory, must be a valid Azure resource scope)
    .Parameter duration
    The duration for the deactivation request in ISO 8601 format (optional, default: PT1H)
    .Parameter justification
    The justification for the role deactivation request (optional, default: "Deactivating role")
    .Example
    PS> Stop-PIMAzureEligibleRoleAssignment -tenantID $tid -principalId $pid -roleName "Contributor" -scope "/subscriptions/$sub"

    Stops the active PIM role assignment for the specified principal with Contributor role at the subscription scope.
    .Example
    PS> Stop-PIMAzureEligibleRoleAssignment -tenantID $tid -principalId $pid -roleName "Reader" -scope "/subscriptions/$sub" -justification "Maintenance completed"

    Stops with custom justification.
    .Link
    https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles#deactivate-a-role-assignment
    .Notes
    Author: Loïc MICHEL, Remco Vermeer
    Homepage: https://github.com/kayasax/EasyPIM
#>

function Stop-PIMAzureEligibleRoleAssignment {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter()]
        [String]
        $tenantID,
        [Parameter()]
        [String]
        $principalId,
        [Parameter(Mandatory = $true)]
        [String]
        $roleName,
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -match '^/(subscriptions|providers/Microsoft\.Management/managementGroups)/') {
                $true
            } else {
                throw "Scope must be a valid Azure resource scope starting with /subscriptions/ or /providers/Microsoft.Management/managementGroups/"
            }
        })]
        [String]
        $scope,
        [ValidateScript({
            try {
                [Xml.XmlConvert]::ToTimeSpan($_) | Out-Null
                $true
            } catch {
                throw "Duration must be a valid ISO 8601 duration format (e.g., PT1H, PT30M)."
            }
        })]
        [String]
        $duration = "PT1H",
        [String]
        $justification = "Deactivating role"
    )

    try {
        if (-not (Get-AzContext -ErrorAction SilentlyContinue) ) {
            throw "No Az context found. Please connect to Azure using Connect-AzAccount."
        }

        if (-not $tenantID) {
            $tenantID = (Get-AzContext).Tenant.Id
            Write-Verbose "Using tenantID from current Az context: $tenantID"
        }
        if (-not $principalId) {
            $ctx = Get-AzContext
            $accountId = $ctx.Account.Id
            if ($accountId.Split('@')[1] -eq $tenantID) {
                $clientId = $accountId.Split('@')[0]
                $sp = Get-AzADServicePrincipal -ApplicationId $clientId
                $principalId = $sp.Id

            } else {
                $principalId = (Get-AzContext).Account.ExtendedProperties['HomeAccountId'].Split('.')[0]
            }
        }
        if ($principalId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            throw "principalId must be a valid GUID."
        }

        $script:tenantID = $tenantID
        $armEndpoint = Get-PIMAzureEnvironmentEndpoint -EndpointType 'ARM'

        # Fetch role definition ID
        $roleDefinitionId = (Get-AzRoleDefinition -Name "$roleName" -Scope "$scope").id
        if ($null -eq $roleDefinitionId) {
            throw "Role definition $roleName not found at scope $scope"
        }
        $restURI = "$armEndpoint/$scope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01-preview"
        Write-Verbose "Checking for existing active assignments for principalId $principalId with role $roleName at scope $scope"
        $response = Invoke-ARM -restURI $restURI -method get
        $roleActiveAssignment = $response.value.properties | Where-Object { $_.AssignmentType -eq "activated" -and $_.principalId -eq "$principalId" -and $_.roleDefinitionId.Split("/")[-1] -eq "$roleDefinitionId" -and $_.scope -eq "$scope" } | Select-Object -First 1
        if ($roleActiveAssignment) {
            $currentTime = (Get-Date -AsUTC)
            $starttimePlus5Min = $roleActiveAssignment.startDateTime.AddMinutes(5)
            if  ($currentTime -lt $starttimePlus5Min) {
                Write-Warning "The role assignment was started less than 5 minutes ago. Deactivation may fail due to PIM constraints."
                $timeDifference = $starttimePlus5Min - $currentTime
                Write-Warning "Waiting for $($timeDifference.TotalSeconds + 10) seconds before proceeding with deactivation..."
                Start-Sleep -Seconds ($timeDifference.TotalSeconds + 10)

            }
            $reqId = (New-Guid).Guid
            $restURI = "$($armEndpoint.TrimEnd('/'))$scope/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($reqId)?api-version=2020-10-01-preview"
            $linkedRoleEligibilityScheduleId = $roleActiveAssignment.linkedRoleEligibilityScheduleInstanceId.Split("/")[-1]
            $roleDefinitionResourceId = $roleActiveAssignment.roleDefinitionId

            # Build the request body as a nested custom object
            $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            $body = [PSCustomObject]@{
                properties = @{
                    principalId                     = "$principalId"
                    roleDefinitionId                = "$roleDefinitionResourceId"
                    requestType                     = "SelfDeactivate"
                    linkedRoleEligibilityScheduleId = "$linkedRoleEligibilityScheduleId"
                    justification                   = "$justification"
                    scheduleInfo                    = @{
                        startDateTime = $now
                        expiration    = @{
                            type     = "AfterDuration"
                            duration = $duration
                        }
                    }
                }
            }
            $jsonBody = $body | ConvertTo-Json -Depth 10
            $response = Invoke-ARM -restURI $restURI -method put -body $jsonBody
            if ($response) {
                Write-Verbose "Role assignment schedule request deactivated successfully."
                return $response
            }
            else {
                Write-Warning "Failed to deactivate role assignment schedule request."
                return
            }
        }
        else {
            Write-Warning "No active assignment found for principalId $principalId with role $roleName at scope $scope"
            return
        }

    }
    catch {
        MyCatch $_
    }
}
