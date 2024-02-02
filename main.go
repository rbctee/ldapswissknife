package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var (
	WarningLog *log.Logger
	InfoLog    *log.Logger
	ErrorLog   *log.Logger

	ldapServer   string
	ldapUsername string
	ldapPassword string
	ldapBaseDN   string
)

type SID struct {
	RevisionLevel     int
	SubAuthorityCount int
	Authority         int
	SubAuthorities    []int
	RelativeID        *int
}

func main() {
	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	WarningLog = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)

	ls := flag.String("server", "", "LDAP Server DNS/IP Address")
	lu := flag.String("username", "", "LDAP username for authentication")
	lp := flag.String("password", "", "LDAP password for authentication")

	flag.Parse()

	if *ls == "" {
		flag.Usage()
		return
	}
	ldapServer = *ls

	if *lu == "" {
		flag.Usage()
		return
	}
	ldapUsername = *lu

	if *lp == "" {
		flag.Usage()
		return
	}
	ldapPassword = *lp

	err := getBaseDN()
	if err != nil {
		fmt.Println(err)
		return
	}

	menu()
}

func checkCommand(str1 string, str2 string) bool {
	return strings.EqualFold(str1, str2)
}

func menu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n> ")
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)

		s := strings.Split(text, " ")

		if checkCommand(s[0], "help") {
			usage([]string{})
		} else if checkCommand(s[0], "exit") {
			return
		} else if checkCommand(s[0], "quit") {
			return
		} else if checkCommand(s[0], "users") {
			manageUsers(s)
		} else if checkCommand(s[0], "computers") {
			manageComputers(s)
		} else if checkCommand(s[0], "gpos") {
			manageGPOs(s)
		} else if checkCommand(s[0], "groups") {
			manageGroups(s)
		}
	}

}

func manageGroups(s []string) {
	if len(s) == 1 {
		usage([]string{"groups"})
		return
	}

	if checkCommand(s[1], "groups") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		fmt.Printf("List of groups:\n")
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

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:       ldapBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=group)",
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	for _, entry := range sr.Entries {
		fmt.Printf("- %s:\n", entry.GetEqualFoldAttributeValue("cn"))
		fmt.Printf("\tDistinguished name: %s\n", entry.GetEqualFoldAttributeValue("distinguishedName"))
		sidString := convertBinToSid(entry.GetEqualFoldAttributeValue("objectSid"))
		fmt.Printf("\tSID: %s\n", sidString)
	}
}

/*
Code taken from:
https://github.com/bwmarrin/go-objectsid/blob/master/main.go
*/
func convertBinToSid(sidBytes string) string {
	var sid SID
	sid.RevisionLevel = int(sidBytes[0])
	sid.SubAuthorityCount = int(sidBytes[1]) & 0xFF

	for i := 2; i <= 7; i++ {
		sid.Authority = sid.Authority | int(sidBytes[i])<<(8*(5-(i-2)))
	}

	var offset = 8
	var size = 4
	for i := 0; i < sid.SubAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(sidBytes[offset+k])&0xFF)<<(8*k)
		}
		sid.SubAuthorities = append(sid.SubAuthorities, subAuthority)
		offset += size
	}

	s := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.Authority)
	for _, v := range sid.SubAuthorities {
		s += fmt.Sprintf("-%d", v)
	}
	return s
}

func manageGPOs(s []string) {
	if len(s) == 1 {
		usage([]string{"gpos"})
		return
	}

	if checkCommand(s[1], "help") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		fmt.Printf("List of Group Policy Objects:\n")
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

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:       ldapBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=groupPolicyContainer)",
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	for _, entry := range sr.Entries {
		fmt.Printf("- %s:\n", entry.GetEqualFoldAttributeValue("displayName"))
		fmt.Printf("\tPath: %s\n", entry.GetEqualFoldAttributeValue("gPCFileSysPath"))
		fmt.Printf("\tDistinguished name: %s\n", entry.GetEqualFoldAttributeValue("distinguishedName"))
	}
}

func manageComputers(s []string) {
	if len(s) == 1 {
		usage([]string{"computers"})
		return
	}

	if checkCommand(s[1], "help") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		fmt.Printf("List of computers:\n")
		listComputers()
	}
}

func getBaseDN() (err error) {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", ldapServer))
	if err != nil {
		return fmt.Errorf("failed to connect to remote LDAP server 'ldap://%s:389': %s", ldapServer, err)
	}
	defer l.Close()

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:       "",
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(supportedLDAPVersion=*)",
	})

	if err != nil {
		return fmt.Errorf("error while performing search: %s", err)
	}

	if len(sr.Entries) < 1 {
		return fmt.Errorf("error while retrieving the base DN of the domain")
	}

	ldapBaseDN = sr.Entries[0].GetEqualFoldAttributeValue("defaultNamingContext")
	return nil
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
		Attributes:   []string{"dn", "cn", "objectClass"},
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetEqualFoldAttributeValue("cn"))
	}
}

func manageUsers(s []string) {
	if len(s) == 1 {
		usage([]string{"users"})
		return
	}

	if checkCommand(s[1], "help") {
		usage(s)
	} else if checkCommand(s[1], "list") {
		fmt.Printf("List of users:\n")
		listUsers()
	}
}

func listComputers() {
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
		Filter:       "(objectClass=Computer)",
		Attributes:   []string{"dn", "cn", "objectClass"},
	})

	if err != nil {
		ErrorLog.Printf("Error while performing search: %s\n", err)
		return
	}

	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetEqualFoldAttributeValue("cn"))
	}
}

func usage(s []string) {
	if len(s) == 0 {
		fmt.Printf("Available commands:\n\n")
		fmt.Println("computers\t\t\tManage computers")
		fmt.Println("gpos\t\t\t\tManage Group Policy objects")
		fmt.Println("groups\t\t\t\tManage groups")
		fmt.Println("users\t\t\t\tManage users")
		return
	}

	if checkCommand(s[0], "users") {
		if len(s) == 1 {
			fmt.Printf("Usage: users COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}

	} else if checkCommand(s[0], "computers") {
		if len(s) == 1 {
			fmt.Printf("Usage: computers COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}
	} else if checkCommand(s[0], "gpos") {
		if len(s) == 1 {
			fmt.Printf("Usage: gpos COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}
	} else if checkCommand(s[0], "groups") {
		if len(s) == 1 {
			fmt.Printf("Usage: groups COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}
	}
}
