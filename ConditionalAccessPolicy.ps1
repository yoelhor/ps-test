function Add-ConditionalAccessPolicy {

    param (
        $PolicyName,
        $AppId
    )

    # Define the conditional access policy
    $params =  @{
        templateId =  $undefinedVariable
        displayName = $PolicyName
        state = "enabled"
        sessionControls =  $undefinedVariable
        conditions =  @{
            userRiskLevels =  @()
            signInRiskLevels =  @(
                "high"
                "medium"
            )
            clientAppTypes =  @(
                "all"
            )
            platforms =  $undefinedVariable
            locations =  $undefinedVariable
            times =  $undefinedVariable
            deviceStates =  $undefinedVariable
            devices =  $undefinedVariable
            clientApplications =  $undefinedVariable
            applications =  @{
                includeApplications =  @(
                    $AppId
                )
                excludeApplications =  @()
                includeUserActions =  @()
                includeAuthenticationContextClassReferences =  @()
                applicationFilter =  $undefinedVariable
            }
            users =  @{
                includeUsers =  @(
                    "All"
                )
                excludeUsers =  @()
                includeGroups =  @()
                excludeGroups =  @()
                includeRoles =  @()
                excludeRoles =  @()
                includeGuestsOrExternalUsers =  $undefinedVariable
                excludeGuestsOrExternalUsers =  $undefinedVariable
            }
        }
        grantControls =  @{
            operator = "OR"
            builtInControls =  @(
                "mfa"
            )
            customAuthenticationFactors =  @()
            termsOfUse =  @()
            authenticationStrength =  $undefinedVariable
        }
    }

    # Try to find the policy by name
    $ca = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$PolicyName'"

    # Create or update the conditional access policy
    if ($null -ne $ca ) {

        # Check the existence of multiple policies with the same name.
        if ($ca.Count -gt 1 ) {
            $policyCount = $ca.Count
            Write-Error -Message  "The operation could not be completed because $policyCount '$PolicyName' policies found in the directory."
            return    
        }

        Write-Host "Updating policy " $ca.Id
        Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId  $ca.Id -BodyParameter $params
        Write-Host "The conditional access policy has been successfully update"
    } else {
        Write-Host "Creating new policy"
        New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $params | Format-List
        Write-Host "The conditional access policy has been successfully created"
    }
}

