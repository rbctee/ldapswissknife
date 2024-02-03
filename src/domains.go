package main

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func manageDomains(s []string) {
	if len(s) == 1 {
		usage([]string{"domains"})
		return
	}

	if checkCommand(s[1], "domains") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		listDomains()
	}
}

func listDomains() {
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

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:       ldapBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=domain)",
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	if len(sr.Entries) > 0 {
		fmt.Println("List of domains:")

		for _, entry := range sr.Entries {
			fmt.Printf("- %s:\n", strings.ToUpper(entry.GetEqualFoldAttributeValue("name")))
			fmt.Printf("\tDistinguished name: %s\n", entry.GetEqualFoldAttributeValue("distinguishedName"))
			fmt.Printf("\tMachine Account quota: %s\n", entry.GetEqualFoldAttributeValue("ms-DS-MachineAccountQuota"))

			sidString := convertBinToSid(entry.GetEqualFoldAttributeValue("objectSid"))
			fmt.Printf("\tSID: %s\n", sidString)

			fmt.Printf("\tForest functional level: %s\n", entry.GetEqualFoldAttributeValue("msDS-Behavior-Version"))
		}
	} else {
		fmt.Println("No domains found")
	}
}
