package cli

// Group/role management. Membership is exposed as the "groups" claim in ID
// tokens and userinfo for clients that request the "groups" scope — e.g.
// Portainer's OAuth team auto-assignment reads a claim like this to place
// users into teams automatically on login.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/omegadc/access-nex/internal/store"
)

var groupCmd = &cobra.Command{Use: "group", Short: "Manage groups/roles (exposed via the \"groups\" claim)"}

var groupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		desc, _ := cmd.Flags().GetString("description")
		if name == "" {
			return fmt.Errorf("name is required")
		}
		if _, err := st.CreateGroup(name, desc); err != nil {
			return err
		}
		fmt.Printf("✓ Group '%s' created\n", name)
		return nil
	},
}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups and their members",
	RunE: func(cmd *cobra.Command, args []string) error {
		groups, err := st.ListGroups()
		if err != nil {
			return err
		}
		if len(groups) == 0 {
			fmt.Println("No groups found")
			return nil
		}
		fmt.Printf("\n%-24s %-30s %s\n", "Name", "Description", "Members")
		fmt.Println(strings.Repeat("-", 100))
		for _, g := range groups {
			members, err := st.ListGroupMembers(g.Name)
			if err != nil {
				return err
			}
			fmt.Printf("%-24s %-30s %s\n", g.Name, g.Description, strings.Join(members, ", "))
		}
		fmt.Println()
		return nil
	},
}

var groupDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			return fmt.Errorf("name is required")
		}
		if err := st.DeleteGroup(name); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("group %s not found", name)
			}
			return err
		}
		fmt.Printf("✓ Group '%s' deleted\n", name)
		return nil
	},
}

var groupAddMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a user to a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		group, _ := cmd.Flags().GetString("group")
		username, _ := cmd.Flags().GetString("username")
		if group == "" || username == "" {
			return fmt.Errorf("--group and --username are required")
		}
		if err := st.AddGroupMember(group, username); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("group or user not found")
			}
			return err
		}
		fmt.Printf("✓ '%s' added to group '%s'\n", username, group)
		return nil
	},
}

var groupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a user from a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		group, _ := cmd.Flags().GetString("group")
		username, _ := cmd.Flags().GetString("username")
		if group == "" || username == "" {
			return fmt.Errorf("--group and --username are required")
		}
		if err := st.RemoveGroupMember(group, username); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("group, user, or membership not found")
			}
			return err
		}
		fmt.Printf("✓ '%s' removed from group '%s'\n", username, group)
		return nil
	},
}
