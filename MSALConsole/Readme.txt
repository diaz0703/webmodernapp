$cert = New-SelfSignedCertificate `
    -KeyExportPolicy Exportable `
    -Subject CN=ClientCredsCert `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -KeyUsage DigitalSignature `
    -NotBefore (Get-Date).AddMonths($startValidInMonth) `
    -NotAfter (Get-Date).AddMonths($startValidInMonth+24) `
    -CertStoreLocation "Cert:\CurrentUser\My"
[string]$pfxPwdPlain = "password"
$pfxPwd = ConvertTo-SecureString -String $pfxPwdPlain -Force -AsPlainText
$pfxPath = ".\Cert.pfx"
$cert | Export-PfxCertificate -FilePath $pfxPath -Password $pfxPwd
$pkcs12=[Convert]::ToBase64String([System.IO.File]::ReadAllBytes((get-childitem -path $pfxPath).FullName))
$base64Cert = $([Convert]::ToBase64String($cert.Export('Cert'), [System.Base64FormattingOptions]::InsertLineBreaks))
Set-Content -Path ".\Cert.cer" -Value $base64Cert