package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bjhaid/corehole/internal/app"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return app.PrintUsage(os.Stdout)
	}

	switch args[0] {
	case "serve":
		return app.Serve(context.Background(), args[1:])
	case "version":
		_, err := fmt.Fprintln(os.Stdout, app.Version())
		return err
	default:
		return app.PrintUsage(os.Stdout)
	}
}
