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

	ldapServer        string
	ldapUsername      string
	ldapPassword      string
	distinguishedName string
)

func main() {
	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	WarningLog = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)

	ls := flag.String("server", "", "LDAP Server DNS/IP Address")
	lu := flag.String("username", "", "LDAP username for authentication")
	lp := flag.String("password", "", "LDAP password for authentication")
	dn := flag.String("dn", "", "Distinguished Name (DN) of the domain")

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

	if *dn == "" {
		flag.Usage()
		return
	}
	distinguishedName = *dn

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
		}
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

	searchRequest := ldap.NewSearchRequest(
		distinguishedName, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=User))",             // The filter to apply
		[]string{"dn", "cn", "objectClass"}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
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

	searchRequest := ldap.NewSearchRequest(
		distinguishedName, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=Computer))",         // The filter to apply
		[]string{"dn", "cn", "objectClass"}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
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
		fmt.Println("users\t\t\t\tManage users")
		fmt.Println("computers\t\t\tManage computers")
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
	}
}
