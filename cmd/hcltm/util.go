package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func prettyBool(in bool) string {
	if in {
		return "Yes"
	}
	return "No"
}

func prettyBoolFromString(in string) bool {
	if in == "Yes" {
		return true
	}
	return false
}

// findHclFiles iterates through a list of files or folders
// looking for .hcl files
// currently it does this recursively through folders too
func findHclFiles(files []string) []string {
	out := []string{}
	recurse := true // @TODO potentially in the future we may make this an argument / flag
	for _, file := range files {
		info, err := os.Stat(file)
		if !os.IsNotExist(err) {
			if !info.IsDir() {
				if filepath.Ext(file) == ".hcl" {
					out = append(out, file)
				}
			} else {
				if recurse {
					re_err := filepath.Walk(file, func(path string, re_info os.FileInfo, err error) error {
						if !re_info.IsDir() && filepath.Ext(path) == ".hcl" {
							out = append(out, path)
						}
						return nil
					})
					if re_err != nil {
						panic(re_err) // @TODO - handle this error better
					}
				}
			}
		}
	}
	return out
}

func configFileLocation() (string, error) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return "", errors.New("Can't find home directory")
	}

	return filepath.Join(homeDir, ".hcltmrc"), nil
}

func validateFilename(filename string) error {
	reg := regexp.MustCompile("[^a-zA-Z0-9_-]+")
	validFilename := reg.ReplaceAllString(filename, "")

	if filename != validFilename {
		return fmt.Errorf("Provided filename contains illegal characters")
	}

	return nil
}

// createOrValidateFolder is used for creating or validating
// an output folder. This is used when a command needs to
// output files into a folder
func createOrValidateFolder(folder string, overwrite bool) error {
	info, err := os.Stat(folder)

	if os.IsNotExist(err) {

		// Need to create the directory
		err = os.Mkdir(folder, 0755)
		if err != nil {
			return fmt.Errorf("Error creating directory: %s", err)
		}
	} else {
		if !info.IsDir() {
			// The outdir exists but isn't a directory
			return fmt.Errorf("You're trying to output to a file that exists and isn't a directory")
		} else {
			if !overwrite {
				return fmt.Errorf("Won't overwrite content in the '%s' folder, to overwrite contents provide the -overwrite option", folder)
			}
		}
	}

	return nil
}

func outfilePath(outDir, tmName, file, ext string) string {
	reg := regexp.MustCompile("[^a-zA-Z0-9]+")
	processedTmname := strings.ToLower(reg.ReplaceAllString(tmName, ""))

	processedFile := filepath.Base(file)
	processedFile = strings.TrimSuffix(processedFile, filepath.Ext(processedFile))

	return fmt.Sprintf("%s/%s-%s%s", outDir, processedFile, processedTmname, ext)

}

type GlobalCmdOptions struct {
	flagDebug  bool
	flagConfig string
}

func (g *GlobalCmdOptions) GetFlagset(name string) *flag.FlagSet {
	flagSet := flag.NewFlagSet(name, flag.ExitOnError)
	flagSet.BoolVar(&g.flagDebug, "debug", false, "Enable debug output")
	flagSet.StringVar(&g.flagConfig, "config", "", "Optional config file")
	return flagSet
}
