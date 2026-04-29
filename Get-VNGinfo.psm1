function Get-VpnInfoReport {
    <#
    .SYNOPSIS
    Generates a Markdown report for an Azure VPN gateway.

    .DESCRIPTION
    Collects VPN gateway details, site-to-site connection settings, IKE/IPsec policies,
    NAT mappings, and NAT-to-connection usage relationships, then writes the result to
    a Markdown file.

    .PARAMETER ResourceGroupName
    The resource group that contains the virtual network gateway and related resources.

    .PARAMETER VirtualNetworkGatewayName
    The name of the virtual network gateway to inspect.

    .PARAMETER OutputPath
    The output Markdown file path. Defaults to .\AzureVPN.md.

    .PARAMETER IncludeSharedKey
    If set, includes connection shared keys in the report. Otherwise shared keys are hidden.

    .EXAMPLE
    Get-VpnInfoReport -ResourceGroupName "rg-lfs-connectivity" -VirtualNetworkGatewayName "vpngw-lfs-centralus" -OutputPath ".\vpngw-lfs-centralus.md"

    Generates the report with shared keys hidden.

    .EXAMPLE
    Get-VpnInfoReport -ResourceGroupName "rg-lfs-connectivity" -VirtualNetworkGatewayName "vpngw-lfs-centralus" -OutputPath ".\vpngw-lfs-centralus.md" -IncludeSharedKey

    Generates the report and includes shared keys.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$VirtualNetworkGatewayName,

        [Parameter()]
        [string]$OutputPath = ".\AzureVPN.md",

        [Parameter()]
        [switch]$IncludeSharedKey
    )

    $requiredModules = @('Az.Accounts', 'Az.Network')
    foreach ($module in $requiredModules) {
        if ($null -eq (Get-Module -Name $module -ErrorAction SilentlyContinue)) {
            Write-Host "Importing module: $module" -ForegroundColor Yellow
            try {
                Import-Module -Name $module -ErrorAction Stop
            }
            catch {
                Write-Host "Warning: Could not import $module. Some functionality may not work." -ForegroundColor Yellow
            }
        }
    }

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $context) {
        Write-Host "Warning: Not authenticated to Azure. Please run: Connect-AzAccount" -ForegroundColor Yellow
    }
    else {
        Write-Host "Authenticated as: $($context.Account.Id) in subscription: $($context.Subscription.Name)" -ForegroundColor Green
    }

    Write-Host "Fetching VPN Gateway: $VirtualNetworkGatewayName from RG: $ResourceGroupName"
    $vng = Get-AzVirtualNetworkGateway -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkGatewayName
    Write-Host "VNG fetched: $($vng.Name) - SKU: $($vng.Sku.Name)" -ForegroundColor Green

    Write-Host "Fetching NAT Rules..."
    $natRules = Get-AzVirtualNetworkGatewayNatRule -ResourceGroupName $ResourceGroupName -VirtualNetworkGatewayName $VirtualNetworkGatewayName
    Write-Host "NAT Rules found: $($natRules.Count)"

    Write-Host "Fetching Connections..."
    $connections = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $ResourceGroupName
    Write-Host "Connections found: $($connections.Count)"

    Write-Host "Fetching Local Network Gateways..."
    $lngs = Get-AzLocalNetworkGateway -ResourceGroupName $ResourceGroupName
    Write-Host "Local Network Gateways found: $($lngs.Count)"

    $doc = @()
    $doc += "# Azure VPN Configuration"
    $doc += "## Gateway: $($vng.Name)"
    $doc += "- SKU: $($vng.Sku.Name)"
    $doc += "- VPN Type: $($vng.VpnType)"

    # Build lookup maps for local gateways by both full resource ID and gateway name.
    $lngMap = @{}
    $lngByName = @{}
    foreach ($lng in $lngs) {
        $lngName = $lng.Id.Split('/')[-1]

        $lngInfo = [PSCustomObject]@{
            Name            = $lngName
            PeerIp          = $lng.GatewayIpAddress
            AddressPrefixes = ($lng.LocalNetworkAddressSpace.AddressPrefixes -join ', ')
        }

        $lngMap[$lng.Id.ToLowerInvariant()] = $lngInfo
        $lngByName[$lngName.ToLowerInvariant()] = $lngInfo
    }

    # Reverse index: NAT rule name -> list of connections that reference it.
    $natRuleUsage = @{}

    $doc += "`n## Connections"
    foreach ($connectionSummary in $connections) {
        $conn = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $ResourceGroupName -Name $connectionSummary.Name

        if ($conn.VirtualNetworkGateway1.Id -eq $vng.Id) {
            $lngInfo = $null
            $connLngId = if ($conn.LocalNetworkGateway2) { $conn.LocalNetworkGateway2.Id } else { $null }

            if ($connLngId) {
                $lngInfo = $lngMap[$connLngId.ToLowerInvariant()]

                if ($null -eq $lngInfo) {
                    $connLngName = $connLngId.Split('/')[-1]
                    $lngInfo = $lngByName[$connLngName.ToLowerInvariant()]
                }
            }

            if ($null -eq $lngInfo) {
                $lngInfo = [PSCustomObject]@{
                    Name            = 'Unknown'
                    PeerIp          = 'Unknown'
                    AddressPrefixes = 'Unknown'
                }
            }

            $doc += "### $($conn.Name)"
            $doc += "- Type: $($conn.ConnectionType)"
            $doc += "- Local Network Gateway: $($lngInfo.Name)"
            $doc += "- Peer IP (On-Prem): $($lngInfo.PeerIp)"
            $doc += "- Address Space: $($lngInfo.AddressPrefixes)"
            $doc += "- Routing Weight: $($conn.RoutingWeight)"
            $doc += "- Connection Protocol: $($conn.ConnectionProtocol)"
            $doc += "- Use Policy-Based Traffic Selectors: $($conn.UsePolicyBasedTrafficSelectors)"
            if ($IncludeSharedKey) {
                $doc += "- Shared Key: $(Get-AzVirtualNetworkGatewayConnectionSharedKey -ResourceGroupName $ResourceGroupName -Name $conn.Name).Value"
            }
            else {
                $doc += "- Shared Key: [hidden]"
            }

            if ($conn.IpsecPolicies -and $conn.IpsecPolicies.Count -gt 0) {
                $doc += "- IKE/IPsec Policies:"
                $policyNumber = 1
                foreach ($policy in $conn.IpsecPolicies) {
                    $doc += "  - Policy $policyNumber"
                    $doc += "    - IKE Phase 1: Encryption=$($policy.IkeEncryption), Integrity=$($policy.IkeIntegrity), DH Group=$($policy.DhGroup)"
                    $doc += "    - IKE Phase 2 (IPsec): Encryption=$($policy.IpsecEncryption), Integrity=$($policy.IpsecIntegrity), PFS Group=$($policy.PfsGroup), SA Lifetime(s)=$($policy.SALifeTimeSeconds), SA Data Size(KB)=$($policy.SADataSizeKilobytes)"
                    $policyNumber++
                }
            }
            else {
                $doc += "- IKE/IPsec Policies: Default Azure policy (no custom IpsecPolicy configured on this connection)"
            }

            # Collect ingress NAT bindings from multiple property shapes across Az versions.
            $ingressNatRuleItems = @()
            if ($null -ne $conn.IngressNatRules) {
                $ingressNatRuleItems += $conn.IngressNatRules
            }
            if ($null -ne $conn.IngressNatRule) {
                $ingressNatRuleItems += $conn.IngressNatRule
            }
            if ($ingressNatRuleItems.Count -eq 0 -and $conn.IngressNatRulesText) {
                try {
                    $ingressNatRuleItems += (ConvertFrom-Json -InputObject $conn.IngressNatRulesText)
                }
                catch {
                }
            }

            $ingressNatRuleNames = @(
                $ingressNatRuleItems |
                Where-Object { $null -ne $_ } |
                ForEach-Object {
                    $natRuleId = if ($null -ne $_.PSObject.Properties['Id']) { $_.Id } else { [string]$_ }
                    if ($natRuleId) {
                        $natRuleId.Split('/')[-1]
                    }
                } |
                Where-Object { $_ }
            )
            if ($ingressNatRuleNames.Count -gt 0) {
                $doc += "- Ingress NAT: $($ingressNatRuleNames -join ', ')"

                foreach ($ingressNatRuleName in $ingressNatRuleNames) {
                    if ($null -eq $natRuleUsage[$ingressNatRuleName]) {
                        $natRuleUsage[$ingressNatRuleName] = @()
                    }

                    $natRuleUsage[$ingressNatRuleName] += "$($conn.Name) (Ingress)"
                }
            }

            # Collect egress NAT bindings from multiple property shapes across Az versions.
            $egressNatRuleItems = @()
            if ($null -ne $conn.EgressNatRules) {
                $egressNatRuleItems += $conn.EgressNatRules
            }
            if ($null -ne $conn.EgressNatRule) {
                $egressNatRuleItems += $conn.EgressNatRule
            }
            if ($egressNatRuleItems.Count -eq 0 -and $conn.EgressNatRulesText) {
                try {
                    $egressNatRuleItems += (ConvertFrom-Json -InputObject $conn.EgressNatRulesText)
                }
                catch {
                }
            }

            $egressNatRuleNames = @(
                $egressNatRuleItems |
                Where-Object { $null -ne $_ } |
                ForEach-Object {
                    $natRuleId = if ($null -ne $_.PSObject.Properties['Id']) { $_.Id } else { [string]$_ }
                    if ($natRuleId) {
                        $natRuleId.Split('/')[-1]
                    }
                } |
                Where-Object { $_ }
            )
            if ($egressNatRuleNames.Count -gt 0) {
                $doc += "- Egress NAT: $($egressNatRuleNames -join ', ')"

                foreach ($egressNatRuleName in $egressNatRuleNames) {
                    if ($null -eq $natRuleUsage[$egressNatRuleName]) {
                        $natRuleUsage[$egressNatRuleName] = @()
                    }

                    $natRuleUsage[$egressNatRuleName] += "$($conn.Name) (Egress)"
                }
            }
        }
    }

    $doc += "`n## NAT Rules"
    foreach ($rule in $natRules) {
        $doc += "### $($rule.Name)"
        $doc += "- Type: $($rule.VirtualNetworkGatewayNatRulePropertiesType)"
        $doc += "- Mode: $($rule.Mode)"

        if ($null -ne $natRuleUsage[$rule.Name] -and $natRuleUsage[$rule.Name].Count -gt 0) {
            $doc += "- Used By Connections: $($natRuleUsage[$rule.Name] -join ', ')"
        }
        else {
            $doc += "- Used By Connections: None"
        }

        $internalMappings = @((($rule.InternalMappingsText | ConvertFrom-Json).AddressSpace))
        $externalMappings = @((($rule.ExternalMappingsText | ConvertFrom-Json).AddressSpace))

        $doc += "- Mappings (Internal -> External):"
        $maxMappings = [Math]::Max($internalMappings.Count, $externalMappings.Count)
        for ($i = 0; $i -lt $maxMappings; $i++) {
            $internal = if ($i -lt $internalMappings.Count) { $internalMappings[$i] } else { "N/A" }
            $external = if ($i -lt $externalMappings.Count) { $externalMappings[$i] } else { "N/A" }
            $doc += "  - $internal -> $external"
        }
    }

    $doc | Out-File -FilePath $OutputPath
    Write-Host "Report written to: $OutputPath" -ForegroundColor Green
}

function Get-ExpressRouteInfoReport {
    <#
    .SYNOPSIS
    Generates a Markdown report for an Azure ExpressRoute circuit.

    .DESCRIPTION
    Collects ExpressRoute circuit properties, service provider details, SKU/bandwidth,
    provisioning state, and all peering configurations. The report includes a dedicated
    Azure Private Peering section with key BGP session details.

    .PARAMETER ResourceGroupName
    The resource group that contains the ExpressRoute circuit.

    .PARAMETER ExpressRouteCircuitName
    The name of the ExpressRoute circuit to inspect.

    .PARAMETER OutputPath
    The output Markdown file path. Defaults to .\AzureExpressRoute.md.

    .PARAMETER IncludeSharedKey
    If set, includes peering shared keys in the report. Otherwise shared keys are hidden.

    .EXAMPLE
    Get-ExpressRouteInfoReport -ResourceGroupName "rg-lfs-connectivity" -ExpressRouteCircuitName "erc-lfs-centralus" -OutputPath ".\erc-lfs-centralus.md"

    Generates the report for the specified ExpressRoute circuit.

    .EXAMPLE
    Get-ExpressRouteInfoReport -ResourceGroupName "rg-lfs-connectivity" -ExpressRouteCircuitName "erc-lfs-centralus" -OutputPath ".\erc-lfs-centralus.md" -IncludeSharedKey

    Generates the report and includes shared keys.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$ExpressRouteCircuitName,

        [Parameter()]
        [string]$OutputPath = ".\AzureExpressRoute.md",

        [Parameter()]
        [switch]$IncludeSharedKey
    )

    $requiredModules = @('Az.Accounts', 'Az.Network')
    foreach ($module in $requiredModules) {
        if ($null -eq (Get-Module -Name $module -ErrorAction SilentlyContinue)) {
            Write-Host "Importing module: $module" -ForegroundColor Yellow
            try {
                Import-Module -Name $module -ErrorAction Stop
            }
            catch {
                Write-Host "Warning: Could not import $module. Some functionality may not work." -ForegroundColor Yellow
            }
        }
    }

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $context) {
        Write-Host "Warning: Not authenticated to Azure. Please run: Connect-AzAccount" -ForegroundColor Yellow
    }
    else {
        Write-Host "Authenticated as: $($context.Account.Id) in subscription: $($context.Subscription.Name)" -ForegroundColor Green
    }

    Write-Host "Fetching ExpressRoute circuit: $ExpressRouteCircuitName from RG: $ResourceGroupName"
    $circuit = Get-AzExpressRouteCircuit -ResourceGroupName $ResourceGroupName -Name $ExpressRouteCircuitName
    Write-Host "ExpressRoute circuit fetched: $($circuit.Name) - SKU: $($circuit.Sku.Tier)/$($circuit.Sku.Family)" -ForegroundColor Green

    $peerings = @()
    if ($null -ne $circuit.Peerings) {
        $peerings = @($circuit.Peerings)
    }

    Write-Host "Peerings found: $($peerings.Count)"

    $doc = @()
    $doc += "# Azure ExpressRoute Configuration"
    $doc += "## Circuit: $($circuit.Name)"
    $doc += "- Resource Group: $ResourceGroupName"
    $doc += "- Location: $($circuit.Location)"
    if ($IncludeSharedKey) {
                $doc += "- Service Key: $($circuit.ServiceKey)"
            }
            else {
                $doc += "- Service Key: [not for public use]"
            }
    $doc += "- Service Provider Name: $($circuit.ServiceProviderProperties.ServiceProviderName)"
    $doc += "- Peering Location: $($circuit.ServiceProviderProperties.PeeringLocation)"
    $doc += "- Bandwidth (Mbps): $($circuit.ServiceProviderProperties.BandwidthInMbps)"
    $doc += "- SKU: Tier=$($circuit.Sku.Tier), Family=$($circuit.Sku.Family), Name=$($circuit.Sku.Name)"
    $doc += "- Circuit Provisioning State: $($circuit.CircuitProvisioningState)"
    $doc += "- Service Provider Provisioning State: $($circuit.ServiceProviderProvisioningState)"
    $doc += "- Provisioning State: $($circuit.ProvisioningState)"
    $doc += "- Allow Classic Operations: $($circuit.AllowClassicOperations)"

    $authorizations = @()
    if ($null -ne $circuit.Authorizations) {
        $authorizations = @($circuit.Authorizations)
    }

    $doc += "`n## Authorizations"
    if ($authorizations.Count -gt 0) {
        foreach ($authorization in $authorizations) {
            $doc += "### $($authorization.Name)"
            $doc += "- Id: $($authorization.Id)"
            if ($authorization.AuthorizationUseStatus) {
                $doc += "- Use Status: $($authorization.AuthorizationUseStatus)"
            }
        }
    }
    else {
        $doc += "- None"
    }

    $nonPrivatePeerings = @($peerings | Where-Object { $_.PeeringType -ne 'AzurePrivatePeering' })
    $privatePeerings = @($peerings | Where-Object { $_.PeeringType -eq 'AzurePrivatePeering' })

    $doc += "`n## Peerings"
    if ($nonPrivatePeerings.Count -eq 0) {
        $doc += "- None"
    }
    else {
        foreach ($peering in $nonPrivatePeerings) {
            $doc += "### $($peering.PeeringType)"
            $doc += "- Name: $($peering.Name)"
            $doc += "- Azure ASN: $($peering.AzureASN)"
            $doc += "- Peer ASN: $($peering.PeerASN)"
            $doc += "- VLAN Id: $($peering.VlanId)"
            $doc += "- Primary Peer Address Prefix: $($peering.PrimaryPeerAddressPrefix)"
            $doc += "- Secondary Peer Address Prefix: $($peering.SecondaryPeerAddressPrefix)"
            $doc += "- IPv6 Primary Peer Address Prefix: $($peering.Ipv6PeeringConfig.PrimaryPeerAddressPrefix)"
            $doc += "- IPv6 Secondary Peer Address Prefix: $($peering.Ipv6PeeringConfig.SecondaryPeerAddressPrefix)"
            if ($IncludeSharedKey) {
                $doc += "- Shared Key: $($peering.SharedKey)"
            }
            else {
                $doc += "- Shared Key: [not for public use]"
            }
            $doc += "- State: $($peering.State)"
            $doc += "- Provisioning State: $($peering.ProvisioningState)"

            if ($peering.MicrosoftPeeringConfig -and $peering.MicrosoftPeeringConfig.AdvertisedPublicPrefixes) {
                $doc += "- Microsoft Peering Advertised Public Prefixes: $($peering.MicrosoftPeeringConfig.AdvertisedPublicPrefixes -join ', ')"
            }
        }
    }

    $doc += "`n## Azure Private Peering"
    if ($privatePeerings.Count -eq 0) {
        $doc += "- Azure Private Peering is not configured on this circuit."
    }
    else {
        foreach ($privatePeering in $privatePeerings) {
            $doc += "### $($privatePeering.Name)"
            $doc += "- Peering Type: $($privatePeering.PeeringType)"
            $doc += "- State: $($privatePeering.State)"
            $doc += "- Provisioning State: $($privatePeering.ProvisioningState)"
            $doc += "- VLAN Id: $($privatePeering.VlanId)"
            $doc += "- Peer ASN: $($privatePeering.PeerASN)"
            $doc += "- Primary Peer Address Prefix: $($privatePeering.PrimaryPeerAddressPrefix)"
            $doc += "- Secondary Peer Address Prefix: $($privatePeering.SecondaryPeerAddressPrefix)"
            $doc += "- IPv6 Primary Peer Address Prefix: $($privatePeering.Ipv6PeeringConfig.PrimaryPeerAddressPrefix)"
            $doc += "- IPv6 Secondary Peer Address Prefix: $($privatePeering.Ipv6PeeringConfig.SecondaryPeerAddressPrefix)"
            If($null -eq $($privatePeering.SharedKey)) {
                $doc += "- Shared Key: [not configured]"
            } elseif ($IncludeSharedKey) {
                $doc += "- Shared Key: $($privatePeering.SharedKey)"
            } else {
                $doc += "- Shared Key: [not for public use]"
            }
            $doc += "- Azure ASN: $($privatePeering.AzureASN)"
        }
    }

    $doc | Out-File -FilePath $OutputPath
    Write-Host "Report written to: $OutputPath" -ForegroundColor Green
}

