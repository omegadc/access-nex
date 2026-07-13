package cli

// Admin-related CLI commands: promote/demote users and view the audit log.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/omegadc/access-nex/internal/store"
)

var userPromoteCmd = &cobra.Command{
	Use:   "promote",
	Short: "Grant a user admin rights (access to /admin)",
	RunE:  func(cmd *cobra.Command, args []string) error { return setAdmin(cmd, true) },
}

var userDemoteCmd = &cobra.Command{
	Use:   "demote",
	Short: "Revoke a user's admin rights",
	RunE:  func(cmd *cobra.Command, args []string) error { return setAdmin(cmd, false) },
}

func setAdmin(cmd *cobra.Command, admin bool) error {
	username, _ := cmd.Flags().GetString("username")
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if err := st.SetUserAdmin(username, admin); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("user %s not found", username)
		}
		return err
	}
	verb := "granted to"
	event := "admin_promoted"
	if !admin {
		verb = "revoked from"
		event = "admin_demoted"
	}
	st.Audit(event, "", "", "", username+" (via CLI)")
	fmt.Printf("✓ Admin rights %s '%s'\n", verb, username)
	return nil
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show the most recent audit log entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		entries, err := st.ListAudit(limit)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Println("Audit log is empty")
			return nil
		}
		fmt.Printf("\n%-21s %-24s %-32s %-16s %s\n", "Time", "Event", "Subject", "IP", "Detail")
		fmt.Println(strings.Repeat("-", 120))
		for _, e := range entries {
			fmt.Printf("%-21s %-24s %-32s %-16s %s\n",
				e.At.Format(time.RFC3339), e.Event, trunc(e.Subject, 31), e.IP, e.Detail)
		}
		fmt.Println()
		return nil
	},
}
