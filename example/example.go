package main

import (
	"log"

	"os"

	"github.com/nayarsystems/nxgo"
	nuc "github.com/nayarsystems/nxusercheck"
)

func main() {
	checks := []*nuc.UsersCheck{
		{
			User:      "test.myuser",
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

	nxconn, err := nxgo.Dial(os.Args[1], nil)
	if err != nil {
		log.Fatalf(err.Error())
	}
	defer nxconn.Close()

	_, err = nxconn.Login(os.Args[2], os.Args[3])
	if err != nil {
		log.Fatalf(err.Error())
	}

	for _, c := range checks {
		checkErr, err := c.Check(nxconn, &nuc.CheckOpts{
			TemplatesExactMatch: true,
		})
		if err != nil {
			log.Fatalf(err.Error())
		}
		if checkErr != nil {
			log.Printf(checkErr.Error())
		}
	}
}
