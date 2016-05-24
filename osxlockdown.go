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
var Version = "0.9"

// ConfigRule is a container for each individual rule
type ConfigRule struct {
	Title            string `yaml:"title"`
	CheckCommand     string `yaml:"check_command"`
	FixCommand       string `yaml:"fix_command"`
	Enabled          bool   `yaml:"enabled"`
	AllowRemediation *bool  `yaml:"allow_remediation"`
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

// RunCommand returns true if the audit passed, or command was successful
func RunCommand(cmd string) bool {
	_, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false
	}

	return true
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

// AllowRemediation returns true if the rule is allowed to be remediated
func AllowRemediation(configRule ConfigRule) bool {
	return configRule.FixCommand != "" && (configRule.AllowRemediation == nil || *configRule.AllowRemediation)
}

func main() {

	hideSummary := flag.Bool("hide_summary", false, "Disables printing the summary")
	hidePasses := flag.Bool("hide_passes", false, "Disables printing the rules that passed")
	remediate := flag.Bool("remediate", false, "Implements fixes for failed checks. WARNING: Beware this may break things.")
	version := flag.Bool("version", false, "Prints the script's version and exits")
	commandFile := flag.String("commands_file", "commands.yaml", "YAML file containing the commands and configuration")

	flag.Parse()

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
		fmt.Fprintf(os.Stderr, "%sThis tool was meant to be used only on OSX 10.11 (El Capitan)", bad)
		return
	}

	// Read our command/config file
	ConfigRules, err := ReadConfigRules(*commandFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read config file: %v\n", err)
		return
	}

	// Run commands and print results
	ruleCount := 0
	failCount := 0

	for _, rule := range ConfigRules {
		// Skip disabled rules
		if !rule.Enabled {
			continue
		}
		checkCommand := rule.CheckCommand
		ruleCount++

		result := RunCommand(checkCommand)

		resultText := "\033[32mPASSED\033[39m"
		if !result {
			// Audit failed, check if we can remediate
			if *remediate && AllowRemediation(rule) {
				// Remediate
				fixCommand := rule.FixCommand
				RunCommand(fixCommand)
				// Check our fix worked
				result = RunCommand(checkCommand)
				if result {
					resultText = "\033[34mFIXED \033[39m"
				}
			}

			if !result {
				failCount++
				resultText = "\033[31mFAILED\033[39m"
			}
		}

		if !result || !*hidePasses {
			fmt.Printf("[%s] %s\n", resultText, rule.Title)
		}
	}

	// Print summary
	if !*hideSummary {
		fmt.Printf("-------------------------------------------------------------------------------\n")
		fmt.Printf("osxlockdown %s\n", Version)
		t := time.Now()
		fmt.Printf("Date: %s\n", t.Format("2006-01-02T15:04:05-07:00"))
		sysinfo, err := GetSystemInfo()
		if nil != err {
			fmt.Printf("Unable to determine Serial Number or Hardware UUID: %v", err)
		} else {
			fmt.Printf("SerialNumber: %s\nHardwareUUID: %s\n", sysinfo.SerialNumber, sysinfo.HardwareUUID)
		}
		fmt.Printf("Final Score %d%%; Pass rate: %d/%d\n",
			CalculateScore(ruleCount, failCount),
			(ruleCount - failCount), ruleCount)
	}
}
