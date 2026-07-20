package crl

type CrlCmd struct {
	Generate GenerateCmd `cmd:"" help:""`
	List     ListCmd     `cmd:"" help:""`
	Read     ReadCmd     `cmd:"" help:""`
	Verify   VerifyCmd   `cmd:"" help:""`
	Inspect  InspectCmd  `cmd:"" help:""`
	Export   ExportCmd   `cmd:"" help:""`
}
