# AD_REMED


## Restreindre les permissions des machines sur l'éditer de leurs attributs msDS-KeyCredentialLink (Attaque shadowCredentials)

```
dsacls "OU=Computers,DC=example,DC=com" /D "SELF:WP;msDS-KeyCredentialLink"
```

AUDIT DE l'atrribut: https://www.blackhillsinfosec.com/enable-auditing-of-changes-to-msds-keycredentiallink/

## Restreindre les permissions sur d'ajout d'une entrée DNS par les users du domaine

```
dsacls "DC=votre-domaine,DC=com" /D "Domain Users:CC;dnsNode"
```

## Restreindre les permissions sur l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity (attaque RBCD)

View -> Advanced Features
-> OU Computer -> Properties -> Security -> SELF, Advanced -> Permissions ->  Add -> Select a principal -> SELF (Enter the object name to select)

Puis:

- Type: Deny
- Applies to: This object and all descendant objects
- Permissions:

![image](https://github.com/user-attachments/assets/97fa0717-4cfe-4ec7-b63b-47bf4341a8db)


Poc:

```
# rbcd.py -delegate-from 'qcs' -delegate-to 'aisicomputer$' -dc-ip "192.168.56.101" -action write "test.fr"/"aisicomputer$":'PASSWORD' 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[-] Could not modify object, the server reports insufficient rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

## Activer le SMB signing via GPO

```
New-GPO -Name "SMB Signing Policy" | New-GPLink -Target "OU=Computers,DC=example,DC=com"
Set-GPRegistryValue -Name "SMB Signing Policy" -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWORD -Value 1
Set-GPRegistryValue -Name "SMB Signing Policy" -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWORD -Value 1
```

### Désactivation de la stack IPV6 via GPO

```
New-GPO -Name "Désactiver IPv6" -Comment "GPO pour désactiver IPv6 en modifiant la clé DisabledComponents" -Domain "votre-domaine.com"
New-GPLink -Name "Désactiver IPv6" -Target "OU=Computers,DC=votre-domaine,DC=com"
Set-GPRegistryValue -Name "Désactiver IPv6" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisabledComponents" -Type DWORD -Value 0xFF
```


### Désactivation NetBios

```
# Créer une nouvelle GPO pour désactiver LLMNR et mDNS
$GPO = New-GPO -Name "Désactiver LLMNR et mDNS" -Comment "GPO pour désactiver LLMNR et mDNS"

# Lier la GPO à une OU (remplacez par le chemin de votre OU)
New-GPLink -Name "Désactiver LLMNR et mDNS" -Target "OU=Computers,DC=example,DC=com"

# Désactiver LLMNR en modifiant la clé de registre via la GPO
Set-GPRegistryValue -Name "Désactiver LLMNR et mDNS" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWORD -Value 0

# Désactiver mDNS en modifiant la clé de registre EnableMDNS via la GPO
Set-GPRegistryValue -Name "Désactiver LLMNR et mDNS" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -ValueName "EnableMDNS" -Type DWORD -Value 0

```

### Désactivation NetBios

```
New-GPO -Name "Désactiver NetBIOS"
New-GPLink -Name "Désactiver NetBIOS" -Target "OU=Computers,DC=example,DC=com"
New-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\tcpip_*" -ValueName "NetbiosOptions" -Type DWord -Value 2

```



### Configurer l'attribut ms-DS-MachineAccountQuota = 0

```
Set-ADDomain -Identity "DC=test,DC=fr" -Replace @{"ms-DS-MachineAccountQuota"="0"}
```





