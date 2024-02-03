package main

import (
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

func manageUsers(s []string) {
	if len(s) == 1 {
		usage([]string{"users"})
		return
	}

	if checkCommand(s[1], "help") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		listUsers()
	}
}

func listUsers() {
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
		Filter:       "(objectClass=User)",
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	if len(sr.Entries) > 0 {
		fmt.Println("List of users")

		for _, entry := range sr.Entries {
			fmt.Printf("- %s\n", entry.GetEqualFoldAttributeValue("sAMAccountName"))
			fmt.Printf("\tDistinguished name: %s\n", entry.DN)
			fmt.Printf("\tUser principal name (UPN): %s\n", entry.GetEqualFoldAttributeValue("userPrincipalName"))

			userAccountControl, err := strconv.Atoi(entry.GetEqualFoldAttributeValue("userAccountControl"))
			if err != nil {
				ErrorLog.Printf("Failed to parse value of property 'userAccountControl'\n")
			}

			userEnabled := (userAccountControl & (1 << (2 - 1))) == 0
			fmt.Printf("\tEnabled: %t\n", userEnabled)

			userDescription := entry.GetEqualFoldAttributeValue("description")
			if userDescription != "" {
				fmt.Printf("\tDescription: %s\n", userDescription)
			}

			sidString := convertBinToSid(entry.GetEqualFoldAttributeValue("objectSid"))
			fmt.Printf("\tSID: %s\n", sidString)

			userGroups := entry.GetEqualFoldAttributeValues("memberof")
			if len(userGroups) > 0 {
				fmt.Println("\tMember of these groups:")
				for _, g := range userGroups {
					fmt.Printf("\t\t- %s\n", g)
				}
			}
		}
	} else {
		fmt.Println("No users found")
	}

}
