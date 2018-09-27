package main

import (
	"fmt"
	"os"

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

	apply := false
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s nexus user pass [apply]\n", os.Args[0])
		os.Exit(1)
	} else if len(os.Args) >= 5 && os.Args[4] == "apply" {
		apply = true
	}

	var out string
	var err error
	if apply {
		out, err = nuc.Apply(checks, os.Args[1], os.Args[2], os.Args[3])
	} else {
		out, err = nuc.Check(checks, os.Args[1], os.Args[2], os.Args[3])
	}
	if out != "" {
		fmt.Println(out)
	}
	if err != nil {
		os.Exit(1)
	}
}
