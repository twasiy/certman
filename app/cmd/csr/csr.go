package csr

type CSRCmd struct {
	Generate  GenerateCmd `cmd:"" help:""`
	List      ListCmd     `cmd:"" help:""`
	Read      ReadCmd     `cmd:"" help:""`
	Inspect   InspectCmd  `cmd:"" help:""`
	VerifyCmd VerifyCmd   `cmd:"" help:""`
	Sign      SignCmd     `cmd:"" help:""`
	Export    ExportCmd   `cmd:"" help:""`
}
