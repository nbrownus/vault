package command

import (
	"fmt"
	"strings"
)

// DeleteCommand is a Command that puts data into the Vault.
type DeleteCommand struct {
	Meta
}

func (c *DeleteCommand) Run(args []string) int {
	flags := c.Meta.FlagSet("delete", FlagSetDefault)
	flags.Usage = func() { c.Ui.Error(c.Help()) }
	if err := flags.Parse(args); err != nil {
		return 1
	}

	args = flags.Args()
	if len(args) != 1 {
		c.Ui.Error("delete expects one argument")
		flags.Usage()
		return 1
	}

	path := args[0]

	client, err := c.Client()
	if err != nil {
		c.Ui.Error(fmt.Sprintf(
			"Error initializing client: %s", err))
		return 2
	}

	if _, err := client.Logical().Delete(path); err != nil {
		c.Ui.Error(fmt.Sprintf(
			"Error deleting '%s': %s", path, err))
		return 1
	}

	c.Ui.Output(fmt.Sprintf("Success! Deleted '%s'", path))
	return 0
}

func (c *DeleteCommand) Synopsis() string {
	return "Delete operation on secrets in Vault"
}

func (c *DeleteCommand) Help() string {
	helpText := `
Usage: vault delete [options] path

  Delete data (secrets or configuration) from Vault.

  Delete sends a delete operation request to the given path. The
  behavior of the delete is determined by the backend at the given
  path. For example, deleting "aws/policy/ops" will delete the "ops"
  policy for the AWS backend. Use "vault help" for more details on
  whether delete is supported for a path and what the behavior is.

General Options:

  -address=addr           The address of the Vault server.

  -ca-cert=path           Path to a PEM encoded CA cert file to use to
                          verify the Vault server SSL certificate.

  -ca-path=path           Path to a directory of PEM encoded CA cert files
                          to verify the Vault server SSL certificate. If both
                          -ca-cert and -ca-path are specified, -ca-path is used.

  -tls-skip-verify        Do not verify TLS certificate. This is highly
                          not recommended. This is especially not recommended
                          for unsealing a vault.

`
	return strings.TrimSpace(helpText)
}
