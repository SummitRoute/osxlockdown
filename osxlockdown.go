package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Version of osxlockdown
const Version = "0.9"

// Color-coded messages
const (
	PASSED  = "\033[32mPASSED \033[39m"
	FIXED   = "\033[34mFIXED  \033[39m"
	FAILED  = "\033[31mFAILED \033[39m"
	SKIPPED = "\033[33mSKIPPED\033[39m"
)

// ConfigRule is a container for each individual rule
type ConfigRule struct {
	Title            string `yaml:"title"`
	CheckCommand     string `yaml:"check_command"`
	FixCommand       string `yaml:"fix_command"`
	Enabled          bool   `yaml:"enabled"`
	AllowRemediation *bool  `yaml:"allow_remediation"`
}

// ShouldRemediate returns true if the rule is allowed to be remediated
func (c ConfigRule) ShouldRemediate() bool {
	return c.FixCommand != "" && (c.AllowRemediation == nil || *c.AllowRemediation)
}

// Check returns true if the audit passed, or command was successful.  If
// debug is true, it will also print the command, any output, and any errors
// which may have occurred.
func (c ConfigRule) Check(debug bool) bool {
	if debug {
		fmt.Printf("==> Check: %s", c.CheckCommand)
	}
	return c.exec(c.CheckCommand, debug)

}

// Fix tries to fix the issue, and then rechecks it with recheck.  Debug has
// the same meaning as for Check().  The value returned is the vaule from
// Check().
func (c ConfigRule) Fix(debug bool) bool {
	if debug {
		fmt.Printf("==> Fix: %s", c.FixCommand)
	}
	c.exec(c.FixCommand, debug)
	return c.Check(debug)
}

// exec runs cmd, and returns true if the command executed successfully.  If
// debug is true, it will also print the command, any output, and any errors
// which may have occurred
func (c ConfigRule) exec(cmd string, debug bool) bool {
	o, err := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
	if debug {
		if 0 != len(o) {
			fmt.Printf("%s", o)
		}
		if nil != err {
			fmt.Printf("Error: %v\n", err)
		}
	}
	return nil == err

}

// ReadConfigRules reads our yaml file
func ReadConfigRules(configFile string) ([]ConfigRule, error) {
	ruleFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var crs []ConfigRule
	err = yaml.Unmarshal(ruleFile, &crs)
	if err != nil {
		return nil, err
	}
	return crs, nil
}

// SystemInfo holds system information
type SystemInfo struct {
	SerialNumber string
	HardwareUUID string
}

// GetCommandOutput runs a command and returns it's output
func GetCommandOutput(cmd string) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// GetSystemInfo collects information about the system
func GetSystemInfo() (sysinfo SystemInfo, err error) {
	if sysinfo.SerialNumber, err = GetCommandOutput("system_profiler SPHardwareDataType | grep \"Serial Number\" | cut -d: -f2"); nil != err {
		return
	}
	if sysinfo.HardwareUUID, err = GetCommandOutput("system_profiler SPHardwareDataType | grep \"Hardware UUID\" | cut -d: -f2"); nil != err {
		return
	}
	return sysinfo, err
}

// CalculateScore returns the compliance score for this system
func CalculateScore(ruleCount int, failCount int) int {
	if ruleCount == 0 {
		return 0
	}
	return int(float64(ruleCount-failCount) / float64(ruleCount) * 100.0)
}

func main() {

	hideSummary := flag.Bool("hide_summary", false, "Disables printing the summary")
	hidePasses := flag.Bool("hide_passes", false, "Disables printing the rules that passed")
	remediate := flag.Bool("remediate", false, "Implements fixes for failed checks. WARNING: Beware this may break things.")
	version := flag.Bool("version", false, "Prints the script's version and exits")
	commandFile := flag.String("commands_file", "commands.yaml", "YAML file containing the commands and configuration")
	debug := flag.Bool("debug", false, "Prints command output and other debugging messages")

	flag.Parse()

	// Debugging output
	pd := func(string, ...interface{}) (int, error) { return 0, nil }
	if *debug {
		pd = fmt.Printf
	}

	// Print the script's version and exit
	if *version {
		fmt.Printf("osxlockdown %s\n", Version)
		return
	}

	// Check OS version to make sure we will work
	osVersion, err := GetCommandOutput("system_profiler SPSoftwareDataType | grep \"System Version\" | cut -d: -f2")
	bad := ""
	if nil != err {
		bad = fmt.Sprintf("ERROR: Unable to determine OS Version: %v\n", err)
	}
	if !strings.Contains(osVersion, "OS X 10.11") {
		bad = "ERROR: Unsupported OS.  "
	}
	if "" != bad {
		fmt.Fprintf(os.Stderr, "%sThis tool was meant to be used only on OSX 10.11 (El Capitan)\n", bad)
		return
	}
	pd("Correct OS Version detected\n")

	// Read our command/config file
	ConfigRules, err := ReadConfigRules(*commandFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read config file: %v\n", err)
		return
	}

	// Make sure we actually have rules
	if 0 == len(ConfigRules) {
		fmt.Fprintf(os.Stderr, "No rules found in config file %v", *commandFile)
		return
	}
	pd("Read %v rules from %v", len(ConfigRules), *commandFile)

	// Run commands and print results
	ruleCount := 0
	failCount := 0

	for _, rule := range ConfigRules {
		// Skip disabled rules
		if !rule.Enabled {
			fmt.Printf("[%s] %s\n", SKIPPED, rule.Title)
			continue
		}
		pd("=> %s\n", rule.Title)

		// Note we've found another rule
		ruleCount++

		resultText := PASSED
		if !rule.Check(*debug) {
			resultText = FAILED
			// Audit failed, check if we can remediate
			if *remediate && rule.ShouldRemediate() {
				// Try to remediate
				if rule.Fix(*debug) {
					resultText = FIXED
				}
			}
		}

		// Note Failures
		if FAILED == resultText {
			failCount++
		}

		if PASSED != resultText || !*hidePasses {
			fmt.Printf("[%s] %s\n", resultText, rule.Title)
		}
	}

	// Print summary
	if !*hideSummary {
		fmt.Printf("-------------------------------------------------------------------------------\n")
		fmt.Printf("osxlockdown %s\n", Version)
		fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02T15:04:05-07:00"))
		sysinfo, err := GetSystemInfo()
		if nil != err {
			fmt.Printf("Unable to determine Serial Number or Hardware UUID: %v", err)
		} else {
			fmt.Printf("SerialNumber: %s\nHardwareUUID: %s\n", sysinfo.SerialNumber, sysinfo.HardwareUUID)
		}
		/* Warn user if there was no actual checking */
		if 0 == ruleCount {
			fmt.Printf("No enabled rules found in config file %v\n", *commandFile)
		} else {
			fmt.Printf("Final Score %d%%; Pass rate: %d/%d\n",
				CalculateScore(ruleCount, failCount),
				(ruleCount - failCount), ruleCount)
		}
	}
}
