package main

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func manageGPOs(s []string) {
	if len(s) == 1 {
		usage([]string{"gpos"})
		return
	}

	if checkCommand(s[1], "help") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		listGPOs()
	}
}

func listGPOs() {
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

	sr, err := l.SearchWithPaging(&ldap.SearchRequest{
		BaseDN:       ldapBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=groupPolicyContainer)",
	}, 1000)

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	if len(sr.Entries) > 0 {
		fmt.Println("List of Group Policy objects:")

		for _, entry := range sr.Entries {
			fmt.Printf("- %s:\n", entry.GetEqualFoldAttributeValue("displayName"))
			fmt.Printf("\tPath: %s\n", entry.GetEqualFoldAttributeValue("gPCFileSysPath"))
			fmt.Printf("\tDistinguished name: %s\n", entry.GetEqualFoldAttributeValue("distinguishedName"))
		}
	} else {
		fmt.Println("No Group Policy objects found")
	}
}
