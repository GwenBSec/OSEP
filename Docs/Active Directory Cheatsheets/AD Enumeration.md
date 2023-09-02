### PowerView 
Users, Groups in Domain 
```
Get-DomainUser
Get-DomainUser | select -ExpandProperty cn
Get-DomainUser -Properties samaccountname,logonCount
Get-DomainUser -Identity student1
Get-DomainUser -Identity student1 -Properties *

Get-DomainGroup | select Name 
Get-DomainGroup -Domain
Get-DomainGroup *admin*
Get-DomainGroup "Domain Admins"
Get-DomainGroup -UserName "student1"
```
Group Membership 
```
Get-NetGroupMember -GroupName 'Domain Admins'
Get-NetGroupMember -GroupName 'Domain Admins' -Domain $domain
Get-NetLocalGroup -ComputerName $name
Get-NetLocalGroupMember -ComputerName $name -GroupName Administrators
```
Computers in Domain 
```
Get-DomainComputer | select Name
Get-DomainComputer -OperatingSystem "*Server 2022*"
Get-LoggedonLocal -ComputerName dcorp-adminsrv
Get-LastLoggedOn -ComputerName dcorp-adminsrv

