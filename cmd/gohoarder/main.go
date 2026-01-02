package main

import (
	"fmt"
	"os"

	"github.com/lukaszraczylo/gohoarder/cmd/gohoarder/commands"
	"github.com/lukaszraczylo/gohoarder/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gohoarder",
	Short: "Universal package cache proxy",
	Long: `GoHoarder is a universal pass-through cache proxy for package managers.
Supports npm, pip, and Go modules with transparent caching, security scanning, and multi-backend storage.`,
	Version: version.Version,
}

func init() {
	// Add commands
	rootCmd.AddCommand(commands.ServeCmd)
	rootCmd.AddCommand(commands.VersionCmd)

	// Set version template
	rootCmd.SetVersionTemplate(fmt.Sprintf(
		"GoHoarder %s\nGit Commit: %s\nBuilt: %s\nGo Version: %s\nPlatform: %s\n",
		version.Version,
		version.GitCommit,
		version.BuildTime,
		version.GoVersion,
		"GOOS/GOARCH",
	))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
