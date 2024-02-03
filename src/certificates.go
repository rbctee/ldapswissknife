package main

import (
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

func manageCertificates(s []string) {
	if len(s) == 1 {
		usage([]string{"certificates"})
		return
	}

	if checkCommand(s[1], "certificates") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		listCertificates()
	}
}

func listCertificates() {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", ldapServer))
	if err != nil {
		ErrorLog.Printf("[!] Failed to connect to remote LDAP server 'ldap://%s:389'.\n\tError: %s\n", ldapServer, err)
		return
	}
	defer l.Close()

	err = l.Bind(ldapUsername, ldapPassword)
	if err != nil {
		ErrorLog.Printf("[!] Failed to authenticate with remote LDAP server using %s:%s.\n\tError: %s\n", ldapUsername, ldapPassword, err)
		return
	}

	certTemplatesBaseDN := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + ldapBaseDN
	sr, err := l.SearchWithPaging(&ldap.SearchRequest{
		BaseDN:       certTemplatesBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
	}, 1000)

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	if len(sr.Entries) > 0 {
		fmt.Println("List of certificate templates:")

		for _, entry := range sr.Entries {
			fmt.Printf("- %s\n", entry.GetEqualFoldAttributeValue("name"))

			certNameFlag, err := strconv.Atoi(entry.GetEqualFoldAttributeValue("msPKI-Certificate-Name-Flag"))
			if err != nil {
				ErrorLog.Printf("Failed to parse value of property 'userAccountControl'\n")
			}
			fmt.Printf("\tCan supply arbtitrary SAN: %t\n", certNameFlag%2 == 1)

			keyExtendedUsage := entry.GetEqualFoldAttributeValues("pKIExtendedKeyUsage")
			fmt.Printf("\tPKI Extended Usage: %s\n", keyExtendedUsage)
			fmt.Printf("\t\tAllow authentication: %t\n", checkEkuEnableAuth(keyExtendedUsage))

			certEnrollmentFlag, err := strconv.Atoi(entry.GetEqualFoldAttributeValue("msPKI-Enrollment-Flag"))
			if err != nil {
				ErrorLog.Printf("Failed to parse value of property 'msPKI-Enrollment-Flag'\n")
			}
			certRequiresApproval := (certEnrollmentFlag & (1 << (2 - 1))) == 1
			fmt.Printf("\tRequire approval: %t\n", certRequiresApproval)

			requireAuthorizedSignature := true
			v := entry.GetEqualFoldAttributeValue("msPKI-RA-Signature")
			if v == "0" || v == "" {
				requireAuthorizedSignature = false
			}

			fmt.Printf("\tRequire authorized signature: %t\n", requireAuthorizedSignature)
		}
	} else {
		fmt.Println("No certificate templates found")
	}
}

/*
Check if the array of EKU (Extended Key Usage) values allows authentication, such as:
- Client Authentication (OID 1.3.6.1.5.5.7.3.2)
- PKINIT Client Authentication (1.3.6.1.5.2.3.4)
- Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)
- Any Purpose (OID 2.5.29.37.0)
- no EKU (SubCA)

Based on this:
https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
*/
func checkEkuEnableAuth(ekus []string) bool {
	if len(ekus) == 0 {
		return true
	}

	if len(ekus) == 1 && ekus[0] == "" {
		return true
	}

	for _, eku := range ekus {
		switch eku {
		case "1.3.6.1.5.5.7.3.2":
			return true
		case "1.3.6.1.5.2.3.4":
			return true
		case "1.3.6.1.4.1.311.20.2.2":
			return true
		case "2.5.29.37.0":
			return true
		}
	}

	return false
}
