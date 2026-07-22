package exp

import (
	"certman/app/cmd/cert/exp/bundle"
	"certman/app/cmd/cert/exp/chain"
)

type ExportCmd struct {
	Cert   CertCmd          `cmd:"" help:""`
	Chain  chain.ChainCmd   `cmd:"" help:""`
	Bundle bundle.BundleCmd `cmd:"" help:""`
}
