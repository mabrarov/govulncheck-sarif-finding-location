package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"golang.org/x/mod/modfile"
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

	report, err := sarif.Open(*reportFile)
	if err != nil {
		// TODO: log error
		return 1
	}

	moduleLocations, err := getModuleLocations(*moduleFile)
	if err != nil {
		// TODO: log error
		return 1
	}

	for _, run := range report.Runs {
		if run == nil {
			continue
		}
		for _, result := range run.Results {
			if result == nil {
				continue
			}

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

	err = report.WriteFile(*outFile)
	if err != nil {
		// TODO: log error
		return 1
	}

	return 0
}

const (
	goStdModulePath         = "stdlib"
	moduleResultLocationURI = "go.mod"
)

var goStdModulePrefix = goStdModulePath + "@"

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
		moduleURI := fmt.Sprintf("%s@%s", requireDirective.Mod.Path, requireDirective.Mod.Version)
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
		if threadFlow == nil {
			continue
		}

		locationCount := len(threadFlow.Locations)
		if locationCount == 0 {
			continue
		}

		location := threadFlow.Locations[locationCount-1]
		if location == nil {
			continue
		}
		if location.Module == nil {
			continue
		}

		return *location.Module, true
	}

	return "", false
}

func setResultLocationLine(result *sarif.Result, line *modfile.Line) {
	for _, location := range result.Locations {
		if location == nil {
			continue
		}
		if location.PhysicalLocation == nil {
			continue
		}
		if location.PhysicalLocation.ArtifactLocation == nil {
			continue
		}
		if location.PhysicalLocation.ArtifactLocation.URI == nil {
			continue
		}
		if location.PhysicalLocation.Region == nil {
			continue
		}
		if *location.PhysicalLocation.ArtifactLocation.URI != moduleResultLocationURI {
			continue
		}
		location.PhysicalLocation.Region.StartLine = &line.Start.Line
		location.PhysicalLocation.Region.StartColumn = &line.Start.LineRune
		location.PhysicalLocation.Region.ByteOffset = line.Start.Byte
		return
	}
}
