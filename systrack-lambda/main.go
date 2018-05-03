package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/mozilla/scribe"
)

// pkgLogEnt describes the JSON structure we will recieve from the output source
type pkgLogEnt struct {
	Fields pkgLogEntFields `json:"fields"`
}

func (p *pkgLogEnt) validate() error {
	return p.Fields.validate()
}

// pkgLogEntFields includes the fields within the log structure we need for
// inspection
type pkgLogEntFields struct {
	PkgName    string `json:"pkgname"`
	PkgVersion string `json:"pkgversion"`
}

func (p *pkgLogEntFields) validate() error {
	if p.PkgName == "" {
		return errors.New("package entry had no package name")
	}
	if p.PkgVersion == "" {
		return errors.New("package entry had no package version")
	}
	return nil
}

type config struct {
	cacheDir    string // Cache directory for cache generation
	inputSample string // If set, read and process an input sample from path
	makeCache   bool   // If true, cache will be generated

	rhelData vulnsrc.UpdateResponse
}

var cfg config

func checkVuln(p pkgLogEnt) error {
	err := p.validate()
	if err != nil {
		// Don't treat as fatal but log it
		log.Printf("%v\n", err)
		return nil
	}
	// Check against RHEL/CentOS data
	for _, v := range cfg.rhelData.Vulnerabilities {
		for _, w := range v.Affected {
			if w.FeatureName != p.Fields.PkgName {
				continue
			}
			f, err := scribe.TestEvrCompare(scribe.EvropLessThan,
				w.FixedInVersion, p.Fields.PkgVersion)
			if err != nil {
				return err
			}
			if f {
				log.Printf("%v %v %v %v\n", p.Fields.PkgName, p.Fields.PkgVersion,
					v.Name, v.Link)
			}
		}
	}
	return nil
}

func handler(ctx context.Context, kinesisEvent events.KinesisEvent) error {
	for _, r := range kinesisEvent.Records {
		var p pkgLogEnt
		err := json.Unmarshal(r.Kinesis.Data, &p)
		if err != nil {
			return err
		}
		err = checkVuln(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	cfg.cacheDir = os.Getenv("CACHEDIR")
	if cfg.cacheDir == "" {
		log.Fatal("CACHEDIR must be set\n")
	}
	cfg.inputSample = os.Getenv("INPUTSAMPLE")
	if os.Getenv("MAKECACHE") != "" {
		// Cache mode, cache vulnerability data in the cache directory
		// and just exit
		err := cacheRHEL()
		if err != nil {
			log.Fatalf("%v\n", err)
		}
		os.Exit(0)
	}
	buf, err := ioutil.ReadFile(path.Join(cfg.cacheDir, "rheldata"))
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	err = json.Unmarshal(buf, &cfg.rhelData)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	// If in sample mode, just compare the sample data set against vulnerability
	// data in the cache
	if cfg.inputSample != "" {
		var le pkgLogEnt
		// Load a sample file, which should be mozlog entries with package
		// information, one log line per entry
		fd, err := os.Open(cfg.inputSample)
		if err != nil {
			log.Fatalf("%v\n", err)
		}
		defer fd.Close()
		scn := bufio.NewScanner(fd)
		for scn.Scan() {
			buf := scn.Text()
			err = json.Unmarshal([]byte(buf), &le)
			if err != nil {
				log.Fatalf("%v\n", err)
			}
			err = checkVuln(le)
			if err != nil {
				log.Fatalf("%v\n", err)
			}
		}
		if scn.Err() != nil {
			log.Fatalf("%v\n", scn.Err())
		}
	} else {
		lambda.Start(handler)
	}
}
