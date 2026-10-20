// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	plussessions "github.com/authelia/authelia/v4/internal/plus/sessions"
)

// authelia-plus: logging a user out of every session from the command line.

func newStorageUserPlusSessionsCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "sessions",
		Short: "Manage user sessions",
		Long:  "Manage user sessions.\n\nThis subcommand allows revoking the sessions of a user.",
		Args:  cobra.NoArgs,

		DisableAutoGenTag: true,
	}

	cmd.AddCommand(newStorageUserPlusSessionsRevokeCmd(ctx))

	return cmd
}

func newStorageUserPlusSessionsRevokeCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "revoke <username>",
		Short: "Revoke every session of a user",
		Long: `Revoke every session of a user.

This subcommand logs a user out everywhere: every running instance rejects their sessions within a few seconds, and
revokes the OpenID Connect 1.0 grants of those sessions shortly after. The username is matched case insensitively.`,
		Example: `authelia storage user sessions revoke john
authelia storage user sessions revoke john --config config.yml`,
		RunE: ctx.StorageUserPlusSessionsRevokeRunE,
		Args: cobra.ExactArgs(1),

		DisableAutoGenTag: true,
	}

	return cmd
}

// StorageUserPlusSessionsRevokeRunE is the RunE for the authelia storage user sessions revoke command.
func (ctx *CmdCtx) StorageUserPlusSessionsRevokeRunE(cmd *cobra.Command, args []string) (err error) {
	defer func() {
		if err := ctx.providers.StorageProvider.Close(); err != nil {
			panic(err)
		}
	}()

	if err = ctx.CheckSchema(); err != nil {
		return storageWrapCheckSchemaErr(err)
	}

	store, ok := ctx.providers.StorageProvider.(plussessions.Store)
	if !ok {
		return fmt.Errorf("the storage provider does not support user sessions")
	}

	count, err := plussessions.RevokeUser(ctx, store, args[0], ctx.GetClock().Now())
	if err != nil {
		return fmt.Errorf("failed to revoke the sessions of user '%s': %w", args[0], err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully revoked %d sessions of user '%s'\n", count, args[0])

	return nil
}
