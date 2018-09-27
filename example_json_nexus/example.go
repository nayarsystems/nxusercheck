package main

import (
	"fmt"
	"os"

	nuc "github.com/nayarsystems/nxusercheck"
)

func main() {
	apply := false
	if len(os.Args) >= 2 && os.Args[1] == "apply" {
		apply = true
	}

	var out string
	var err error
	if apply {
		out, err = nuc.ApplyFile("example.json")
	} else {
		out, err = nuc.CheckFile("example.json")
	}
	if out != "" {
		fmt.Println(out)
	}
	if err != nil {
		os.Exit(1)
	}
}
