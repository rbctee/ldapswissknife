package main

import (
	"fmt"
	"log"

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
