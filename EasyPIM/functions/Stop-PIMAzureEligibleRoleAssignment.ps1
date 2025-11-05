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
        [Parameter(Mandatory = $true)]
        [String]
        $tenantID,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
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
