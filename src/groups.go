package main

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func manageGroups(s []string) {
	if len(s) == 1 {
		usage([]string{"groups"})
		return
	}

	if checkCommand(s[1], "groups") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		listGroups()
	}
}

func listGroups() {
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
		Filter:       "(objectClass=group)",
	}, 1000)

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	if len(sr.Entries) > 0 {
		fmt.Println("List of groups:")

		for _, entry := range sr.Entries {
			fmt.Printf("- %s:\n", entry.GetEqualFoldAttributeValue("cn"))
			fmt.Printf("\tDistinguished name: %s\n", entry.GetEqualFoldAttributeValue("distinguishedName"))
			sidString := convertBinToSid(entry.GetEqualFoldAttributeValue("objectSid"))
			fmt.Printf("\tSID: %s\n", sidString)

			memberValues := entry.GetEqualFoldAttributeValues("member")
			if len(memberValues) > 0 {
				fmt.Printf("\tMembers of the group:\n")
				for _, v := range memberValues {
					fmt.Printf("\t\t- %s\n", v)
				}
			}

			memberOfValues := entry.GetEqualFoldAttributeValues("memberof")
			if len(memberOfValues) > 0 {
				fmt.Printf("\tMember of:\n")
				for _, v := range memberOfValues {
					fmt.Printf("\t\t- %s\n", v)
				}
			}

		}
	} else {
		fmt.Println("No groups found")
	}
}
