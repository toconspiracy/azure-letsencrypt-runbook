#######################################################################################
# Script that renews a Let's Encrypt certificate for an Azure Application Gateway
# Pre-requirements:
#      - Have a storage account in which the folder path has been created: 
#        '/.well-known/acme-challenge/', to put here the Let's Encrypt DNS check files

#      - Add "Path-based" rule in the Application Gateway with this configuration: 
#           - Path: '/.well-known/acme-challenge/*'
#           - Check the configure redirection option
#           - Choose redirection type: permanent
#           - Choose redirection target: External site
#           - Target URL: <Blob public path of the previously created storage account>
#                - Example: 'https://test.blob.core.windows.net/public'
#      - For execution on Azure Automation: Import 'AzureRM.profile', 'AzureRM.Network' 
#        and 'ACMESharp' modules in Azure
#
#      UPDATE 2019-11-27
#      - Due to deprecation of ACMEv1, a new script is required to use ACMEv2.
#        The module to use is called ACME-PS.
#
#      UPDATE 2020-09-03
#      - Migrated to Az modules.
#        Following modules are needed now: Az.Accounts, Az.Network, Az.Storage
#
#######################################################################################

Param(
    [string[]]$DomainsJSON,
    [string]$EmailAddress,
    [string]$STResourceGroupName,
    [string]$storageName,
    [string]$storageContainerName,
    [string]$kvlName,
    [string]$kvlCertificateName,
)

$Domains = ConvertFrom-Json -InputObject $DomainsJSON

Connect-AzAccount -Identity
Get-ChildItem -Path $env:TEMP -Include *.* -File -Recurse | foreach { $_.Delete()}

# Create a state object and save it to the harddrive
Write-Output "Step 5"
$state = New-ACMEState -Path $env:TEMP
#$serviceName = 'LetsEncrypt'
$serviceName = 'LetsEncrypt-Staging'

# Fetch the service directory and save it in the state
Write-Output "Step 6"
Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru;

# Get the first anti-replay nonce
Write-Output "Step 7"
New-ACMENonce $state;

# Create an account key. The state will make sure it's stored.
Write-Output "Step 8"
New-ACMEAccountKey $state -PassThru;

# Register the account key with the acme service. The account key will automatically be read from the state
Write-Output "Step 9"
New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS;

# Load an state object to have service directory and account keys available
Write-Output "Step 10"
$state = Get-ACMEState -Path $env:TEMP;

# It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example
Write-Output "Step 11"
New-ACMENonce $state -PassThru;

# Create the identifier for the DNS name
Write-Output "Step 12"
$dnsIdentifiers = $Domains | ForEach-Object { New-ACMEIdentifier $_ };

# Create the order object at the ACME service.
Write-Output "Step 13"
$order = New-ACMEOrder $state -Identifiers $dnsIdentifiers;

# Fetch the authorizations for that order
Write-Output "Step 14"
$authorizations = @(Get-ACMEAuthorization -State $state -Order $order);

foreach($authz in $authorizations) {
    # Select a challenge to fullfill
    # Select a challenge to fullfill
    Write-Output "Step 15"
    $challenge = Get-ACMEChallenge $state $authZ "http-01";

    # Inspect the challenge data
    Write-Output "Step 16"
    $challenge.Data;

    # Create the file requested by the challenge
    Write-Output "Step 17"
    $fileName = $env:TMP + '\' + $challenge.Token;
    Set-Content -Path $fileName -Value $challenge.Data.Content -NoNewline;

    Write-Output "Step 18"
    $blobName = ".well-known/acme-challenge/" + $challenge.Token
    Write-Output "Step 18.1"
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $STResourceGroupName -Name $storageName
    Write-Output "Step 18.2"
    $ctx = $storageAccount.Context
    Write-Output "Step 18.3"
    Set-AzStorageBlobContent -File $fileName -Container $storageContainerName -Context $ctx -Blob $blobName

    # Signal the ACME server that the challenge is ready
    Write-Output "Step 19"
    $challenge | Complete-ACMEChallenge $state;
}


# Wait a little bit and update the order, until we see the states
Write-Output "Step 20"
while($order.Status -notin ("ready","invalid")) {
    Start-Sleep -Seconds 10;
    $order | Update-ACMEOrder $state -PassThru;
}

# Should the order get invalid, use Get-ACMEAuthorizationError to list error details.
Write-Output "Step 21"
if($order.Status -ieq ("invalid")) {
    $order | Get-ACMEAuthorizationError -State $state;
    throw "Order was invalid";
}

# We should have a valid order now and should be able to complete it
# Therefore we need a certificate key
Write-Output "Step 22"
$certKey = New-ACMECertificateKey -Path "$env:TEMP\$domain.key.xml";

# Complete the order - this will issue a certificate singing request
Write-Output "Step 23"
Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;

# Now we wait until the ACME service provides the certificate url
Write-Output "Step 24"
while(-not $order.CertificateUrl) {
    Start-Sleep -Seconds 15
    $order | Update-Order $state -PassThru
}

# As soon as the url shows up we can create the PFX
Write-Output "Step 25"
$password = ConvertTo-SecureString -String "Passw@rd123***" -Force -AsPlainText
Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$domain.pfx" -Password $password;

# Delete blob to check DNS
Write-Output "Step 26"
Remove-AzStorageBlob -Container $storageContainerName -Context $ctx -Blob $blobName

### IMPORT CERTIFICATE INTO KEYVAULT ###
Write-Output "Step 27"
Import-AzKeyVaultCertificate -VaultName $kvlName -Name $kvlCertificateName -FilePath "$env:TEMP\$domain.pfx" -Password $password