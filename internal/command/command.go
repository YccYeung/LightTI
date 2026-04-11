package command

import (
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
)

var scriptingRuntimes = map[string]bool{
    "python": true, "python3": true, "python2": true,
    "java": true, "javaw": true,
    "node": true, "nodejs": true,
    "ruby": true, "ruby3": true,
    "php": true,
    "perl": true,
    "powershell": true, "pwsh": true,
    "bash": true, "sh": true, "zsh": true, "fish": true,
    "rscript": true,
    "go": true,
}

var windowsBinaries = map[string]bool{
    // execution
    "whoami": true, "cmd": true, "powershell": true, "pwsh": true,
    "wscript": true, "cscript": true, "mshta": true,
    "rundll32": true, "regsvr32": true, "msiexec": true,
    // download
    "certutil": true, "bitsadmin": true,
    // recon
    "ipconfig": true, "netstat": true, "tasklist": true,
    "systeminfo": true, "net": true, "nltest": true,
	"hostname": true, "quser": true, "qwinsta": true,
    // lateral movement
    "psexec": true, "wmic": true, "at": true, "schtasks": true,
	// privilege escalation
	"runas": true,
	// registry
	"reg": true, "regedit": true,
	// network
	"netsh": true, "arp": true, "route": true, "ping": true, "tracert": true,
	// file ops  
	"xcopy": true, "robocopy": true, "icacls": true, "attrib": true,
	// scripting
	"forfiles": true, "makecab": true,
}

var unixBinaries = map[string]bool{
    // execution
    "bash": true, "sh": true, "zsh": true, "dash": true,
    // download
    "curl": true, "wget": true, "tftp": true,
    // recon
    "whoami": true, "id": true, "uname": true, "ifconfig": true,
    "netstat": true, "ps": true, "find": true,
    // network
    "nc": true, "ncat": true, "netcat": true, "nmap": true,
    "ssh": true, "scp": true,
    // file ops
    "awk": true, "sed": true, "grep": true, "cat": true,
	// privilege escalation
	"chmod": true, "chown": true, "chattr": true,
	"sudo": true, "su": true,
}

//go:embed data/lolbas.json
var localLolbasData		[]byte
//go:embed data/gtfobins.json
var localGtfobinData	[]byte

var lolbasDB LOLBasDB
var lolbasMap map[string]LOLBasEntry
var gtfobinsDB GTFOBinsDB

type CommandResult struct {
	RawCommand		string
	ParsedCommand 	ParsedCommand
	LOLBasResult	*LOLBasResult
	GTFOBinsResult	*GTFOBinsResult	
}

type ParsedCommand struct {
	FullPath    string
	OS          string
    Executable  string
    Args        []string
}

type LOLBasDB []LOLBasEntry

type GTFOBinsDB struct {
	Executables map[string]GTFOBinsEntry `json:"executables"`
}

type LOLBasEntry struct {
    Name        string          `json:"Name"`
    Description string          `json:"Description"`
    Commands    []LOLBasCommand `json:"Commands"`
}

type LOLBasCommand struct {
    MitreID  	string `json:"MitreID"`
    Usecase  	string `json:"Usecase"`
    Category 	string `json:"Category"`
	Privilege 	string `json:"Privileges"`
}

type LOLBasResult struct {
    Name        string
    Description string
    MITRE       []string
    Usecases    []string
    Categories  []string
	Privileges	[]string
}

type GTFOBinsEntry struct {
    Functions 	map[string][]GTFOBinsFunction `json:"functions"`
}

type GTFOBinsFunction struct {
	Code      string 				`json:"code"`
    Comment   string 				`json:"comment"`
	Contexts map[string]interface{} `json:"contexts"`
}

type GTFOBinsResult struct {
    Functions []string
	Contexts  map[string]interface{}
	Examples  map[string]string 
    Comments  map[string]string 
}

func CommandParser(command string) *ParsedCommand {

	parser := &ParsedCommand{}
	// Extract the first segemant of the command
	firstSeg := strings.Split(command, " ")[0]
	firstSegLower := strings.ToLower(firstSeg)
	// Extract OS information based on command structure
	if strings.Contains(firstSegLower, "c:\\") || strings.Contains(firstSeg, "\\") {
		parser.OS = "windows"
	} else if strings.HasPrefix(firstSeg, "/") {
		parser.OS = "unix"
	} else if !strings.Contains(firstSeg, "/") && !strings.Contains(firstSeg, "\\") {
		if scriptingRuntimes[firstSegLower] {
			parser.OS = "universal (programming language)"
		} else if windowsBinaries[firstSegLower] {
			parser.OS = "windows"
		} else if unixBinaries[firstSegLower] {
			parser.OS = "unix"
		} else {
			parser.OS = "universal (system binary)"
		}
	}

	// Parse for executable filename
	executable := filepath.Base(firstSeg)
	executable = strings.TrimSuffix(executable, ".exe")
	executable = strings.TrimSuffix(executable, ".EXE")
	parser.Executable = executable

	// Parse for arguments
	arguments := strings.Split(command, " ")[1:]
	parser.Args = arguments

	// Parse for full path
	parser.FullPath = firstSeg

	return  parser
}

func LookupBinary(executable string, os string) (*LOLBasResult, *GTFOBinsResult) {

	var LOLBasSearch 	LOLBasResult 
	var GTFOBinsSearch 	GTFOBinsResult

	var lolbasResult 	*LOLBasResult
	var gtfobinsResult 	*GTFOBinsResult

	if (os == "windows" || strings.Contains(os, "universal")) {
		entry, found := lolbasMap[strings.ToLower(executable)]
		if found {
			LOLBasSearch.Name = entry.Name
			LOLBasSearch.Description = entry.Description
			for _, subEntry := range entry.Commands {
				LOLBasSearch.MITRE = append(LOLBasSearch.MITRE, subEntry.MitreID)
				LOLBasSearch.Usecases = append(LOLBasSearch.Usecases, subEntry.Usecase)
				LOLBasSearch.Categories = append(LOLBasSearch.Categories, subEntry.Category)
				LOLBasSearch.Privileges = append(LOLBasSearch.Privileges, subEntry.Privilege)
			}
			lolbasResult = &LOLBasSearch
		}
	} 
	if (os == "unix" || strings.Contains(os, "universal")) {
		processedExe := strings.ToLower(executable)
		processedExe = strings.TrimSuffix(processedExe, ".exe")
		entry, found := gtfobinsDB.Executables[processedExe]
		if found {
			GTFOBinsSearch.Contexts = map[string]interface{}{}
			GTFOBinsSearch.Examples = make(map[string]string)
			GTFOBinsSearch.Comments = make(map[string]string)
			for functionName, functions := range entry.Functions {
				if len(functions) > 0 {
					GTFOBinsSearch.Functions = append(GTFOBinsSearch.Functions, functionName)
					GTFOBinsSearch.Contexts[functionName] = functions[0].Contexts
					GTFOBinsSearch.Examples[functionName] = functions[0].Code 
					GTFOBinsSearch.Comments[functionName] = functions[0].Comment
				}
			}
			gtfobinsResult = &GTFOBinsSearch
		}
	}

	return lolbasResult, gtfobinsResult
}

func init() {
	json.Unmarshal(localLolbasData, &lolbasDB);
	json.Unmarshal(localGtfobinData, &gtfobinsDB);

	lolbasMap = make(map[string]LOLBasEntry)
	for _, entry := range lolbasDB {
		lolbasMap[strings.ToLower(entry.Name)] = entry
	}
}