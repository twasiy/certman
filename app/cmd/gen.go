package cmd

type GenCmd struct {
	CA   CACmd      `cmd:"" help:"Generates CA Certificate."`
	ICA  InterCACmd `cmd:"" help:"Generates Intermediate CA Certificate."`
	Leaf LeafCmd    `cmd:"" help:"Generates Leaf Certificate."`
}
