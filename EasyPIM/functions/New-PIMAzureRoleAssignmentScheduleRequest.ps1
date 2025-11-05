<#
    .Synopsis
    Creates a new PIM Azure role assignment schedule request.
    .Description
    Submits a request to schedule a PIM Azure role assignment for an eligible principal at the specified scope. Returns the API response object on success.
    .Parameter tenantID
    EntraID tenant ID (Mandatory)
    .Parameter principalId
    The object ID of the principal to assign the role to (Mandatory)
    .Parameter roleName
    The name of the Azure role to assign (Mandatory)
    .Parameter scope
    The scope at which to assign the role (Mandatory)
    .Parameter duration
    The duration of the assignment in ISO 8601 format (optional, default: PT1H)
    .Parameter justification
    The justification for the role activation request (optional, default: "Activating role for planned maintenance")
    .Example
    PS> New-PIMAzureRoleAssignmentScheduleRequest -tenantID $tid -principalId $pid -roleName "Contributor" -scope "/subscriptions/$sub"

    Creates a new PIM role assignment schedule request for the specified principal with Contributor role at the subscription scope.
    .Example
    PS> New-PIMAzureRoleAssignmentScheduleRequest -tenantID $tid -principalId $pid -roleName "Reader" -scope "/subscriptions/$sub" -duration "PT2H" -justification "Emergency access needed"

    Creates a request with custom duration and justification.
    .Link
    https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles
    .Notes
    Author: Loïc MICHEL, Remco Vermeer
    Homepage: https://github.com/kayasax/EasyPIM
#>

function New-PIMAzureRoleAssignmentScheduleRequest {
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
        $justification = "Activating role for planned maintenance"
    )

    try {
        $script:tenantID = $tenantID

        $armEndpoint = Get-PIMAzureEnvironmentEndpoint -EndpointType 'ARM'

        # Fetch role definition ID
        $roleDefinitionId = (Get-AzRoleDefinition -Name "$roleName" -Scope "$scope").id
        if ($null -eq $roleDefinitionId) {
            throw "Role definition $roleName not found at scope $scope"
        }
        $roleDefinitionResourceId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$roleDefinitionId"

        $restURI = "$armEndpoint/providers/Microsoft.Management/managementGroups/asn/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01-preview"
        Write-Verbose "Checking for existing active assignments for principalId $principalId with role $roleName at scope $scope"
        $response = Invoke-ARM -restURI $restURI -method get
        $roleActiveAssignment = $response.value.properties | Where-Object { $_.AssignmentType -eq "activated" -and $_.principalId -eq "$principalId" -and $_.roleDefinitionId.Split("/")[-1] -eq "$roleDefinitionId" -and $_.scope -eq "$scope" } | Select-Object -First 1
        if ($roleActiveAssignment) {
            $currentDateTimeUTC = Get-Date -AsUTC
            $endTimeUTC = $roleActiveAssignment.endDateTime
            if ($roleActiveAssignment.endDateTime -lt $currentDateTimeUTC.AddHours(2)) {
                Write-Warning "An active assignment already exists for principalId $principalId with role $roleName at scope $scope until $($endTimeUTC) (UTC)"
                return
            }
            Write-Warning "An active assignment already exists for principalId $principalId with role $roleName at scope $scope"
            return
        }

        $roleEligibilityAssignment = Get-PIMAzureResourceEligibleAssignment -tenantID $tenantId -principalId $principalId -scope $scope | Where-Object { $_.RoleName -eq "$roleName" } | Select-Object -First 1
        if ($null -eq $roleEligibilityAssignment) {
            throw "No eligible assignment found for principalId $principalId with role $roleName at scope $scope"
        }
        $linkedRoleEligibilityScheduleId = $roleEligibilityAssignment.Id.Split("/")[-1]


        $reqId = (New-Guid).Guid
        $restURI = "$($armEndpoint.TrimEnd('/'))$scope/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($reqId)?api-version=2020-10-01-preview"

        # Build the request body as a nested custom object
        $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $body = [PSCustomObject]@{
            properties = @{
                principalId                     = "$principalId"
                roleDefinitionId                = "$roleDefinitionResourceId"
                requestType                     = "SelfActivate"
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
            Write-Verbose "Role assignment schedule request created successfully."
        }
        return $response

    }
    catch {
        MyCatch $_
    }
}
