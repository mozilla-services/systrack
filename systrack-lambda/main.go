package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/mozilla/scribe"
)

// pkgLogEnt describes the JSON structure we will recieve from the output source
type pkgLogEnt struct {
	Hostname  string          `json:"Hostname"`
	Timestamp int64           `json:"Timestamp"`
	Time      time.Time       `json:"Time"`
	Fields    pkgLogEntFields `json:"Fields"`
}

func (p *pkgLogEnt) validate() error {
	return p.Fields.validate()
}

func (p *pkgLogEnt) toLogEntry(v database.VulnerabilityWithAffected) string {
	appname := "unknown"
	for _, x := range p.Fields.InstanceTags {
		e := strings.Split(x, "=")
		if len(e) != 2 {
			continue
		}
		if strings.ToLower(e[0]) == "app" {
			appname = e[1]
		}
	}
	return fmt.Sprintf("%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v",
		p.Time.Format("2006-01-02 15:04:05"), p.Hostname, p.Fields.InstanceID, p.Fields.InstanceType,
		p.Fields.AMI, p.Fields.PkgArch, p.Fields.PkgName, p.Fields.PkgVersion,
		v.Name, v.Severity, appname)
}

// pkgLogEntFields includes the fields within the log structure we need for
// inspection
type pkgLogEntFields struct {
	AMI          string   `json:"ami"`
	Dist         string   `json:"dist"`
	FQDN         string   `json:"fqdn"`
	InstanceID   string   `json:"instanceid"`
	InstanceType string   `json:"instancetype"`
	InstanceTags []string `json:"instancetags"`
	PkgArch      string   `json:"pkgarch"`
	PkgName      string   `json:"pkgname"`
	PkgVersion   string   `json:"pkgversion"`
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
	cacheDir     string // Cache directory for cache generation
	inputSample  string // If set, read and process an input sample from path
	makeCache    bool   // If true, cache will be generated
	outputStream string // Kinesis output stream

	rhelData vulnsrc.UpdateResponse
}

var cfg config

func kinesisWrite(dmap []string) error {
	log.Printf("attempting to write %v records to firehose\n", len(dmap))
	sess := session.Must(session.NewSession())
	k := firehose.New(sess, nil)
	obuf := make([]*firehose.Record, 0, 400)
	for i, v := range dmap {
		obuf = append(obuf, &firehose.Record{
			Data: []byte(v + "\n"),
		})
		if i != 0 && len(obuf)%400 == 0 {
			_, err := k.PutRecordBatch(&firehose.PutRecordBatchInput{
				DeliveryStreamName: &cfg.outputStream,
				Records:            obuf,
			})
			if err != nil {
				return err
			}
			obuf = obuf[:0]
		}
	}
	if len(obuf) != 0 {
		_, err := k.PutRecordBatch(&firehose.PutRecordBatchInput{
			DeliveryStreamName: &cfg.outputStream,
			Records:            obuf,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func checkVuln(p pkgLogEnt) error {
	err := p.validate()
	if err != nil {
		// Don't treat as fatal but log it
		log.Printf("%v\n", err)
		return nil
	}
	log.Printf("validating for %v (%v)\n", p.Fields.PkgName, p.Fields.PkgVersion)
	dmap := make([]string, 0)
	// Check against RHEL/CentOS data
	//
	// XXX This is WIP right now, but should check the submitted distribution
	// value
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
				s := p.toLogEntry(v)
				dmap = append(dmap, s)
			}
		}
	}
	if cfg.inputSample == "" && len(dmap) > 0 {
		err = kinesisWrite(dmap)
		if err != nil {
			return err
		}
	}
	return nil
}

func handler(ctx context.Context, kinesisEvent events.KinesisEvent) error {
	log.Printf("handler executing for %v records\n", len(kinesisEvent.Records))
	for _, r := range kinesisEvent.Records {
		var p pkgLogEnt
		err := json.Unmarshal(r.Kinesis.Data, &p)
		if err != nil {
			log.Printf("%v\n", err)
			continue
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
	cfg.outputStream = os.Getenv("OUTPUTSTREAM")
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
