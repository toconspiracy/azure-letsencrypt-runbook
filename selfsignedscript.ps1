param(
  [string] [Parameter(Mandatory=$true)] $vaultName,
  [string] [Parameter(Mandatory=$true)] $certificateName1,
  [string] [Parameter(Mandatory=$false)] $certificateName2,
  [string] [Parameter(Mandatory=$true)] $subjectName
)

$ErrorActionPreference = 'Stop'
$DeploymentScriptOutputs = @{}

if ($certificateName2 -eq 'notRequired') {
    $certificates =@($certificateName1)
}else{
    $certificates =@($certificateName1, $certificateName2)
}

ForEach ($certificateName In $certificates) {
  $existingCert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $certificateName

    if ($existingCert) {

        Write-Host 'Certificate $certificateName in vault $vaultName is already present.'

        $DeploymentScriptOutputs['certThumbprint'] = $existingCert.Thumbprint
        $existingCert | Out-String
    }
    else {
        $policy = New-AzKeyVaultCertificatePolicy -SubjectName $subjectName -IssuerName Self -ValidityInMonths 12 -Verbose

        # private key is added as a secret that can be retrieved in the ARM template
        Add-AzKeyVaultCertificate -VaultName $vaultName -Name $certificateName -CertificatePolicy $policy -Verbose

        $newCert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $certificateName

        # it takes a few seconds for KeyVault to finish
        $tries = 0
        do {
        Write-Host 'Waiting for certificate creation completion...'
        Start-Sleep -Seconds 10
        $operation = Get-AzKeyVaultCertificateOperation -VaultName $vaultName -Name $certificateName
        $tries++

        if ($operation.Status -eq 'failed')
        {
            throw 'Creating certificate $certificateName in vault $vaultName failed with error $($operation.ErrorMessage)'
        }

        if ($tries -gt 120)
        {
            throw 'Timed out waiting for creation of certificate $certificateName in vault $vaultName'
        }
        } while ($operation.Status -ne 'completed')

        $DeploymentScriptOutputs['certThumbprint'] = $newCert.Thumbprint
        $newCert | Out-String
    }
}