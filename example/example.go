package main

import (
	"fmt"
	"os"

	"github.com/nayarsystems/nxgo"
	nuc "github.com/nayarsystems/nxusercheck"
)

func main() {
	checks := []*nuc.UsersCheck{
		{
			Prefix:    "test.myuser",
			Templates: []string{"test.mytemplate"},
			Permissions: &nuc.Permissions{
				ByPrefix: nuc.P{
					"test.mypath1": {
						"@task.push":   true,
						"@task.pull":   true,
						"@user.list":   true,
						"@user.delete": false,
					},
				},
				OnPrefixes: nuc.P{
					"@user.list": {
						"test.mypath2": true,
						"test.mypath3": true,
					},
				},
			},
			Tags: &nuc.Tags{
				ByPrefix: nuc.T{
					"test.mypath1": {
						"tag1": []interface{}{"value1", "value2"},
						"tag2": 123,
					},
				},
				OnPrefixes: nuc.T{
					"tagA": {
						"test.mypath2": map[string]interface{}{"a": "b"},
						"test.mypath3": "value",
					},
				},
			},
		},
	}

	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <nexus> <user> <pass>\n", os.Args[0])
		return
	}

	nxconn, err := nxgo.Dial(os.Args[1], nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer nxconn.Close()

	_, err = nxconn.Login(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for _, c := range checks {
		checkErr, err := c.Check(nxconn)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		if checkErr != nil {
			fmt.Println(checkErr.Error())
		} else {
			fmt.Printf("User %s passed all checks\n", c.Prefix)
		}
	}
}
