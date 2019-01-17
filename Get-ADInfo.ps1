import-module activedirectory
$ds=Get-Date -format yyyyMMdd
$of = -join(".\", $ds , "_ad_users.txt")     
$Results = Get-ADUser -filter * -Properties SamAccountName,Name,DisplayName,Description,CannotChangePassword,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,PasswordExpired,PasswordLastSet,Enabled,AccountLockoutTime,LockedOut,AccountExpirationDate,LastLogonDate,logonhours,LogonWorkstations,Created,EmailAddress,LastBadPasswordAttempt,DistinguishedName
$Results | export-csv -delimiter "`t" -NoTypeInformation -path $of
$of = -join(".\", $ds , "_ad_users.clean.txt")
$Results | select SamAccountName,DisplayName,Description,@{N='Status';E={null}},@{N='PWCompliance';E={null}},@{N='PWWeak';E={null}},PasswordExpired,@{N='PWAge';E={null}},PasswordLastSet,PasswordNeverExpires,AccountExpirationDate,Enabled,LockedOut,AccountLockoutTime,LastLogonDate,Created,surname,givenname,EmailAddress,LastBadPasswordAttempt,DistinguishedName,Name,CannotChangePassword | export-csv -delimiter "`t" -NoTypeInformation -path $of

$of = -join(".\", $ds , "_ad_pwpolicy.txt") 
Get-ADDefaultDomainPasswordPolicy  | Out-file $of
$of = -join(".\", $ds , "_ad_groups.txt")
$Groups = Get-ADGroup -Filter '*' -Properties * 
$Results = foreach( $Group in $Groups ){ Get-ADGroupMember -Identity $Group | foreach { [pscustomobject]@{ GroupName = $Group.samaccountname; Category=$Group.GroupCategory; GroupScope=$Group.GroupScope; CN=$Group.DistinguishedName; Desc=$Description; Member = $_.Name; MemberType=$_.objectclass}}}
$Results | export-csv -delimiter "`t" -NoTypeInformation -path $of