package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

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
