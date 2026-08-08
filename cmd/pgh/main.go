package main

import (
	"os"

	"github.com/cli/cli/v2/internal/pghcmd"
)

func main() {
	os.Exit(pghcmd.Main())
}
