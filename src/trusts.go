package main

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func manageTrusts(s []string) {
	if len(s) == 1 {
		usage([]string{"trusts"})
		return
	}

	if checkCommand(s[1], "trusts") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		listTrusts()
	}
}

func listTrusts() {
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
		Filter:       "(objectClass=trustedDomain)",
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	if len(sr.Entries) > 0 {
		fmt.Printf("List of domain trusts:\n")
		for _, entry := range sr.Entries {
			for _, v := range entry.Attributes {
				fmt.Printf("%s: %s\n", v.Name, v.Values)
			}
		}
	} else {
		fmt.Printf("No domain trusts found\n")
	}

}
