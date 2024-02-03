package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

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
		} else if checkCommand(s[0], "computers") {
			manageComputers(s)
		} else if checkCommand(s[0], "domains") {
			manageDomains(s)
		} else if checkCommand(s[0], "exit") {
			return
		} else if checkCommand(s[0], "gpos") {
			manageGPOs(s)
		} else if checkCommand(s[0], "groups") {
			manageGroups(s)
		} else if checkCommand(s[0], "quit") {
			return
		} else if checkCommand(s[0], "trusts") {
			manageTrusts(s)
		} else if checkCommand(s[0], "users") {
			manageUsers(s)
		}
	}

}

func usage(s []string) {
	if len(s) == 0 {
		fmt.Printf("Available commands:\n\n")
		fmt.Println("computers\t\t\tManage computers")
		fmt.Println("domains\t\t\t\tManage domains")
		fmt.Println("gpos\t\t\t\tManage Group Policy objects")
		fmt.Println("groups\t\t\t\tManage groups")
		fmt.Println("trusts\t\t\t\tManage domain trusts")
		fmt.Println("users\t\t\t\tManage users")
		return
	}

	if checkCommand(s[0], "computers") {
		if len(s) == 1 {
			fmt.Printf("Usage: computers COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}
	} else if checkCommand(s[0], "domains") {
		if len(s) == 1 {
			fmt.Printf("Usage: domains COMMAND\n\n")
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
	} else if checkCommand(s[0], "trusts") {
		if len(s) == 1 {
			fmt.Printf("Usage: trusts COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}
	} else if checkCommand(s[0], "users") {
		if len(s) == 1 {
			fmt.Printf("Usage: users COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("list")
			return
		}
	}
}
