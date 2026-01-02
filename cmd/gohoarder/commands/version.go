package commands

import (
	"fmt"

	json "github.com/goccy/go-json"
	"github.com/lukaszraczylo/gohoarder/internal/version"
	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
)

// VersionCmd displays version information
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  "Display detailed version information about GoHoarder",
	Run: func(cmd *cobra.Command, args []string) {
		info := version.Get()

		if jsonOutput {
			data, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
				return
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "GoHoarder %s\n", info.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "Git Commit: %s\n", info.GitCommit)
			fmt.Fprintf(cmd.OutOrStdout(), "Built: %s\n", info.BuildTime)
			fmt.Fprintf(cmd.OutOrStdout(), "Go Version: %s\n", info.GoVersion)
			fmt.Fprintf(cmd.OutOrStdout(), "Platform: %s\n", info.Platform)
		}
	},
}

func init() {
	VersionCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output version information as JSON")
}
