package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/mabrarov/govulncheck-sarif-finding-location/pkg/sarif"
)

var (
	reportFile = flag.String("report", "", "path to file with govulncheck SARIF report")
	moduleFile = flag.String("gomod", "", "path to go.mod file")
	outFile    = flag.String("out", "", "path to output file")
)

func main() {
	os.Exit(runMain())
}

func runMain() int {
	flag.Parse()

	if reportFile == nil || *reportFile == "" {
		// TODO: log error
		return 1
	}
	if moduleFile == nil || *moduleFile == "" {
		// TODO: log error
		return 1
	}
	if outFile == nil || *outFile == "" {
		// TODO: log error
		return 1
	}

	report, err := loadReport(*reportFile)
	if err != nil {
		// TODO: log error
		return 1
	}

	moduleLocations, err := getModuleLocations(*moduleFile)
	if err != nil {
		// TODO: log error
		return 1
	}

	for runIdx := range report.Runs {
		run := &report.Runs[runIdx]
		for resultIdx := range run.Results {
			result := &run.Results[resultIdx]
			module, found := getResultCauseModule(result)
			if !found {
				continue
			}

			if strings.HasPrefix(module, goStdModulePrefix) {
				if line, found := moduleLocations[goStdModulePath]; found {
					setResultLocationLine(result, line)
				}
				continue
			}

			if line, found := moduleLocations[module]; found {
				setResultLocationLine(result, line)
			}
		}
	}

	err = saveReport(report, *outFile)
	if err != nil {
		// TODO: log error
		return 1
	}

	return 0
}

const (
	moduleVersionDelim      = "@"
	goStdModulePath         = "stdlib"
	goStdModulePrefix       = goStdModulePath + moduleVersionDelim
	moduleResultLocationURI = "go.mod"
)

func loadReport(filename string) (*sarif.Report, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open govulncheck SARIF file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	var report sarif.Report
	err = json.NewDecoder(file).Decode(&report)
	if err != nil {
		return nil, fmt.Errorf("decode govulncheck SARIF file: %w", err)
	}

	return &report, nil
}

func saveReport(report *sarif.Report, filename string) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("open output SARIF file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(report)
	if err != nil {
		return fmt.Errorf("encode output SARIF file: %w", err)
	}

	return nil
}

func getModuleLocations(moduleFile string) (map[string]*modfile.Line, error) {
	moduleFileContent, err := os.ReadFile(moduleFile)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	parsedModule, err := modfile.ParseLax(moduleFile, moduleFileContent, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	requiredModuleCount := len(parsedModule.Require)
	moduleLocations := make(map[string]*modfile.Line, requiredModuleCount+1)
	if parsedModule.Go != nil && parsedModule.Go.Syntax != nil {
		moduleLocations[goStdModulePath] = parsedModule.Go.Syntax
	}

	for _, requireDirective := range parsedModule.Require {
		if requireDirective == nil {
			continue
		}
		if requireDirective.Syntax == nil {
			continue
		}
		moduleURI := requireDirective.Mod.Path + moduleVersionDelim + requireDirective.Mod.Version
		moduleLocations[moduleURI] = requireDirective.Syntax
	}

	return moduleLocations, nil
}

func getResultCauseModule(result *sarif.Result) (string, bool) {
	if len(result.CodeFlows) == 0 {
		return "", false
	}

	for _, codeFlow := range result.CodeFlows {
		threadFlowCount := len(codeFlow.ThreadFlows)
		if threadFlowCount == 0 {
			continue
		}

		threadFlow := codeFlow.ThreadFlows[threadFlowCount-1]
		locationCount := len(threadFlow.Locations)
		if locationCount == 0 {
			continue
		}

		location := threadFlow.Locations[locationCount-1]
		return location.Module, true
	}

	return "", false
}

func setResultLocationLine(result *sarif.Result, line *modfile.Line) {
	for i := range result.Locations {
		location := &result.Locations[i]
		if location.PhysicalLocation.ArtifactLocation.URI != moduleResultLocationURI {
			continue
		}
		location.PhysicalLocation.Region.StartLine = line.Start.Line
		return
	}
}
