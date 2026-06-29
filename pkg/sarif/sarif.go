package sarif

import "time"

// Report is copy of golang.org/x/vuln/internal/sarif.Log.
type Report struct {
	// Version should always be "2.1.0"
	Version string `json:"version,omitempty"`

	// Schema should always be "https://json.schemastore.org/sarif-2.1.0.json"
	Schema string `json:"$schema,omitempty"`

	// Runs describes executions of static analysis tools. For govulncheck,
	// there will be only one run object.
	Runs []Run `json:"runs,omitempty"`
}

// Run summarizes results of a single invocation of a static analysis tool,
// in this case govulncheck.
type Run struct {
	Tool Tool `json:"tool,omitempty"`
	// Results contain govulncheck findings. There should be exactly one
	// Result per a detected use of an OSV.
	Results []Result `json:"results"`
}

// Tool captures information about govulncheck analysis that was run.
type Tool struct {
	Driver Driver `json:"driver,omitempty"`
}

// Driver provides details about the govulncheck binary being executed.
type Driver struct {
	// Name is "govulncheck"
	Name string `json:"name,omitempty"`
	// Version is the govulncheck version
	Version string `json:"semanticVersion,omitempty"`
	// InformationURI points to the description of govulncheck tool
	InformationURI string `json:"informationUri,omitempty"`
	// Properties are govulncheck run metadata, such as vuln db, Go version, etc.
	Properties Config `json:"properties,omitempty"`

	Rules []Rule `json:"rules"`
}

type Config struct {
	// ProtocolVersion specifies the version of the JSON protocol.
	ProtocolVersion string `json:"protocol_version"`

	// ScannerName is the name of the tool, for example, govulncheck.
	//
	// We expect this JSON format to be used by other tools that wrap
	// govulncheck, which will have a different name.
	ScannerName string `json:"scanner_name,omitempty"`

	// ScannerVersion is the version of the tool.
	ScannerVersion string `json:"scanner_version,omitempty"`

	// DB is the database used by the tool, for example,
	// vuln.go.dev.
	DB string `json:"db,omitempty"`

	// LastModified is the last modified time of the data source.
	DBLastModified *time.Time `json:"db_last_modified,omitempty"`

	// GoVersion is the version of Go used for analyzing standard library
	// vulnerabilities.
	GoVersion string `json:"go_version,omitempty"`

	// ScanLevel instructs govulncheck to analyze at a specific level of detail.
	// Valid values include module, package and symbol.
	ScanLevel string `json:"scan_level,omitempty"`

	// ScanMode instructs govulncheck how to interpret the input and
	// what to do with it. Valid values are source, binary, query,
	// and extract.
	ScanMode string `json:"scan_mode,omitempty"`
}

// Rule corresponds to the static analysis rule/analyzer that
// produces findings. For govulncheck, rules are OSVs.
type Rule struct {
	// ID is OSV.ID
	ID               string      `json:"id,omitempty"`
	ShortDescription Description `json:"shortDescription,omitempty"`
	FullDescription  Description `json:"fullDescription,omitempty"`
	Help             Description `json:"help,omitempty"`
	HelpURI          string      `json:"helpUri,omitempty"`
	// Properties contain OSV.Aliases (CVEs and GHSAs) as tags.
	// Consumers of govulncheck SARIF can use these tags to filter
	// results.
	Properties RuleTags `json:"properties,omitempty"`
}

// RuleTags defines properties.tags.
type RuleTags struct {
	Tags []string `json:"tags"`
}

// Description is a text in its raw or markdown form.
type Description struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// Result is a set of govulncheck findings for an OSV. For call stack
// mode, it will contain call stacks for the OSV. There is exactly
// one Result per detected OSV. Only findings at the most precise
// detected level appear in the Result. For instance, if there are
// symbol findings for an OSV, those findings will be in the Result,
// but not the package and module level findings for the same OSV.
type Result struct {
	// RuleID is the Rule.ID/OSV producing the finding.
	RuleID string `json:"ruleId,omitempty"`
	// Level is one of "error", "warning", and "note".
	Level string `json:"level,omitempty"`
	// Message explains the overall findings.
	Message Description `json:"message,omitempty"`
	// Locations to which the findings are associated. Always
	// a single location pointing to the first line of the go.mod
	// file. The path to the file is "go.mod".
	Locations []Location `json:"locations,omitempty"`
	// CodeFlows summarize call stacks produced by govulncheck.
	CodeFlows []CodeFlow `json:"codeFlows,omitempty"`
	// Stacks encode call stacks produced by govulncheck.
	Stacks []Stack `json:"stacks,omitempty"`
}

// CodeFlow summarizes a detected offending flow of information in terms of
// code locations. More precisely, it can contain several related information
// flows, keeping them together. In govulncheck, those can be all call stacks
// for, say, a particular symbol or package.
type CodeFlow struct {
	// ThreadFlows is effectively a set of related information flows.
	ThreadFlows []ThreadFlow `json:"threadFlows"`
	Message     Description  `json:"message,omitempty"`
}

// ThreadFlow encodes an information flow as a sequence of locations.
// For govulncheck, it can encode a call stack.
type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations,omitempty"`
}

type ThreadFlowLocation struct {
	// Module is module information in the form <module-path>@<version>.
	// <version> can be empty when the module version is not known as
	// with, say, the source module analyzed.
	Module string `json:"module,omitempty"`
	// Location also contains a Message field.
	Location Location `json:"location,omitempty"`
}

// Stack is a sequence of frames and can encode a govulncheck call stack.
type Stack struct {
	Message Description `json:"message,omitempty"`
	Frames  []Frame     `json:"frames"`
}

// Frame is effectively a module location. It can also contain thread and
// parameter info, but those are not needed for govulncheck.
type Frame struct {
	// Module is module information in the form <module-path>@<version>.
	// <version> can be empty when the module version is not known as
	// with, say, the source module analyzed.
	Module   string   `json:"module,omitempty"`
	Location Location `json:"location,omitempty"`
}

// Location is currently a physical location annotated with a message.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation,omitempty"`
	Message          Description      `json:"message,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           Region           `json:"region,omitempty"`
}

// ArtifactLocation is a path to an offending file.
type ArtifactLocation struct {
	// URI is a path relative to URIBaseID.
	URI string `json:"uri,omitempty"`
	// URIBaseID is offset for URI, one of %SRCROOT%, %GOROOT%,
	// and %GOMODCACHE%.
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region is a target region within a file.
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

const (
	SrcRootID              = "%SRCROOT%"
	GoModLocationURI       = "go.mod"
	GoModLocationStartLine = 1
)
