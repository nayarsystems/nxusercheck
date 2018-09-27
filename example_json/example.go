package main

import (
	"fmt"
	"os"

	nuc "github.com/nayarsystems/nxusercheck"
)

func main() {
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
		out, err = nuc.ApplyFileNexus("example.json", os.Args[1], os.Args[2], os.Args[3])
	} else {
		out, err = nuc.CheckFileNexus("example.json", os.Args[1], os.Args[2], os.Args[3])
	}
	if out != "" {
		fmt.Println(out)
	}
	if err != nil {
		os.Exit(1)
	}
}
