// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// This is a slightly modified version of the RHEL OVAL parser from the
// clair project

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	// Before this RHSA, it deals only with RHEL <= 4.
	firstConsideredRHEL = 5

	// RHSA to start from
	firstRHSA = 20170000

	ovalURI        = "https://www.redhat.com/security/data/oval/"
	rhsaFilePrefix = "com.redhat.rhsa-"
	updaterFlag    = "rhelUpdater"
)

var (
	ignoredCriterions = []string{
		" is signed with Red Hat ",
		" Client is installed",
		" Workstation is installed",
		" ComputeNode is installed",
	}

	rhsaRegexp = regexp.MustCompile(`com.redhat.rhsa-(\d+).xml`)
)

type oval struct {
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	References  []reference `xml:"metadata>reference"`
	Criteria    criteria    `xml:"criteria"`
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
}

type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*criteria `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
}

type criterion struct {
	Comment string `xml:"comment,attr"`
}

func cacheRHEL() error {
	vs, err := fetchRHEL()
	if err != nil {
		return err
	}
	opath := path.Join(cfg.cacheDir, "rheldata")
	buf, err := json.Marshal(vs)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(opath, buf, 0644)
	if err != nil {
		return err
	}
	return nil
}

func fetchRHEL() (resp vulnsrc.UpdateResponse, err error) {
	r, err := http.Get(ovalURI)
	if err != nil {
		return resp, commonerr.ErrCouldNotDownload
	}

	// Get the list of RHSAs that we have to process.
	var rhsaList []int
	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		r := rhsaRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			rhsaNo, _ := strconv.Atoi(r[1])
			if rhsaNo > firstRHSA {
				rhsaList = append(rhsaList, rhsaNo)
			}
		}
	}

	for _, rhsa := range rhsaList {
		// Download the RHSA's XML file.
		r, err := http.Get(ovalURI + rhsaFilePrefix + strconv.Itoa(rhsa) + ".xml")
		if err != nil {
			return resp, commonerr.ErrCouldNotDownload
		}

		// Parse the XML.
		vs, err := parseRHSA(r.Body)
		if err != nil {
			return resp, err
		}

		// Collect vulnerabilities.
		for _, v := range vs {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}
	}

	// Set the flag if we found anything.
	if len(rhsaList) > 0 {
		resp.FlagName = updaterFlag
		resp.FlagValue = strconv.Itoa(rhsaList[len(rhsaList)-1])
	}

	return resp, nil
}

func parseRHSA(ovalReader io.Reader) (vulnerabilities []database.VulnerabilityWithAffected, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		err = commonerr.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		pkgs := toFeatures(definition.Criteria)
		if len(pkgs) > 0 {
			vulnerability := database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name:        name(definition),
					Link:        link(definition),
					Severity:    severity(definition),
					Description: description(definition),
				},
			}
			for _, p := range pkgs {
				vulnerability.Affected = append(vulnerability.Affected, p)
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return
}

func getCriterions(node criteria) [][]criterion {
	// Filter useless criterions.
	var criterions []criterion
	for _, c := range node.Criterions {
		ignored := false

		for _, ignoredItem := range ignoredCriterions {
			if strings.Contains(c.Comment, ignoredItem) {
				ignored = true
				break
			}
		}

		if !ignored {
			criterions = append(criterions, c)
		}
	}

	if node.Operator == "AND" {
		return [][]criterion{criterions}
	} else if node.Operator == "OR" {
		var possibilities [][]criterion
		for _, c := range criterions {
			possibilities = append(possibilities, []criterion{c})
		}
		return possibilities
	}

	return [][]criterion{}
}

func getPossibilities(node criteria) [][]criterion {
	if len(node.Criterias) == 0 {
		return getCriterions(node)
	}

	var possibilitiesToCompose [][][]criterion
	for _, criteria := range node.Criterias {
		possibilitiesToCompose = append(possibilitiesToCompose, getPossibilities(*criteria))
	}
	if len(node.Criterions) > 0 {
		possibilitiesToCompose = append(possibilitiesToCompose, getCriterions(node))
	}

	var possibilities [][]criterion
	if node.Operator == "AND" {
		for _, possibility := range possibilitiesToCompose[0] {
			possibilities = append(possibilities, possibility)
		}

		for _, possibilityGroup := range possibilitiesToCompose[1:] {
			var newPossibilities [][]criterion

			for _, possibility := range possibilities {
				for _, possibilityInGroup := range possibilityGroup {
					var p []criterion
					p = append(p, possibility...)
					p = append(p, possibilityInGroup...)
					newPossibilities = append(newPossibilities, p)
				}
			}

			possibilities = newPossibilities
		}
	} else if node.Operator == "OR" {
		for _, possibilityGroup := range possibilitiesToCompose {
			for _, possibility := range possibilityGroup {
				possibilities = append(possibilities, possibility)
			}
		}
	}

	return possibilities
}

func toFeatures(criteria criteria) []database.AffectedFeature {
	// There are duplicates in Red Hat .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]database.AffectedFeature)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion database.AffectedFeature
			osVersion      int
			err            error
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") {
				const prefixLen = len("Red Hat Enterprise Linux ")
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
				if err != nil {
					fmt.Fprint(os.Stderr, "could not parse Red Hat release version from criterion comment\n")
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.FeatureName = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				version := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				err := versionfmt.Valid(rpm.ParserName, version)
				if err != nil {
					fmt.Fprint(os.Stderr, "could not parse package version. skipping")
				} else {
					featureVersion.AffectedVersion = version
					if version != versionfmt.MaxVersion {
						featureVersion.FixedInVersion = version
					}
					featureVersion.Namespace.VersionFormat = rpm.ParserName
				}
			}
		}

		if osVersion >= firstConsideredRHEL {
			// TODO(vbatts) this is where features need multiple labels ('centos' and 'rhel')
			featureVersion.Namespace.Name = "centos" + ":" + strconv.Itoa(osVersion)
		} else {
			continue
		}

		if featureVersion.Namespace.Name != "" && featureVersion.FeatureName != "" && featureVersion.AffectedVersion != "" && featureVersion.FixedInVersion != "" {
			featureVersionParameters[featureVersion.Namespace.Name+":"+featureVersion.FeatureName] = featureVersion
		} else {
			fmt.Fprintf(os.Stderr, "could not determine a valid package from criterions")
		}
	}

	// Convert the map to slice.
	var featureVersionParametersArray []database.AffectedFeature
	for _, fv := range featureVersionParameters {
		featureVersionParametersArray = append(featureVersionParametersArray, fv)
	}

	return featureVersionParametersArray
}

func description(def definition) (desc string) {
	// It is much more faster to proceed like this than using a Replacer.
	desc = strings.Replace(def.Description, "\n\n\n", " ", -1)
	desc = strings.Replace(desc, "\n\n", " ", -1)
	desc = strings.Replace(desc, "\n", " ", -1)
	return
}

func name(def definition) string {
	return strings.TrimSpace(def.Title[:strings.Index(def.Title, ": ")])
}

func link(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "RHSA" {
			link = reference.URI
			break
		}
	}

	return
}

func severity(def definition) database.Severity {
	switch strings.TrimSpace(def.Title[strings.LastIndex(def.Title, "(")+1 : len(def.Title)-1]) {
	case "Low":
		return database.LowSeverity
	case "Moderate":
		return database.MediumSeverity
	case "Important":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		fmt.Fprintf(os.Stderr, "could not determine vulnerability severity from: %s.", def.Title)
		return database.UnknownSeverity
	}
}
