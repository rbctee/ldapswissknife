package main

import (
    "fmt"
    "flag"
    "os"
    "log"
    "github.com/go-ldap/ldap/v3"
)

func main() {
    fmt.Printf("[+] LDAP Swiss Knife\n")

    ldap_server := flag.String("server", "", "LDAP Server DNS/IP Address")
    ldap_username := flag.String("username", "", "LDAP username for authentication")
    ldap_password := flag.String("password", "", "LDAP password for authentication")
	
	flag.Parse()
	// ldap.Logger = log.New(os.Stdout, "[LDAP] ", log.LstdFlags)

	if *ldap_server == "" {
		flag.Usage()
		return
	}

	if *ldap_username == "" {
		flag.Usage()
		return
	}

	if *ldap_password == "" {
		flag.Usage()
		return
	}

	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", *ldap_server))
	if err != nil {
		fmt.Printf(fmt.Sprintf("[!] Failed to connect to remote LDAP server 'ldap://%s:389'.\n\tError: %s\n", *ldap_server, err))
		os.Exit(1)
	}
	defer l.Close()

	err = l.Bind(*ldap_username, *ldap_password)
	if err != nil {
		fmt.Printf(fmt.Sprintf("[!] Failed to authenticate with remote LDAP server using %s:%s.\n\tError: %s\n", *ldap_username, *ldap_password, err))
		os.Exit(2)
	}

	searchRequest := ldap.NewSearchRequest(
		"dc=vuln,dc=local", // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=*))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
}
