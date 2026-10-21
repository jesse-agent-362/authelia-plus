// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"context"
	"fmt"
	"io"
	"time"

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
revokes the OpenID Connect 1.0 grants of those sessions shortly after. The username is matched exactly, case and all,
so it must be the username the user logs in as.`,
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

	return runStorageUserPlusSessionsRevoke(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), store, args[0], ctx.GetClock().Now())
}

func runStorageUserPlusSessionsRevoke(ctx context.Context, w, errW io.Writer, store plussessions.Store, username string, now time.Time) (err error) {
	count, err := plussessions.RevokeUser(ctx, store, username, now)
	if err != nil {
		return fmt.Errorf("failed to revoke the sessions of user '%s': %w", username, err)
	}

	_, _ = fmt.Fprintf(w, "Successfully revoked %d sessions of user '%s'\n", count, username)

	if count == 0 {
		_, _ = fmt.Fprintf(errW, "Warning: no sessions of user '%s' were revoked. The username is matched exactly, so check its case and spelling against the username the user logs in as\n", username)
	}

	return nil
}
