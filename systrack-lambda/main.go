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

// pkgLogEnt describes the JSON structure we will recieve from the systrack command line
// tool
type pkgLogEnt struct {
	Hostname  string          `json:"Hostname"`
	Timestamp int64           `json:"Timestamp"`
	Time      time.Time       `json:"Time"`
	Fields    pkgLogEntFields `json:"Fields"`
}

func (p *pkgLogEnt) validate() error {
	if p.Hostname == "" {
		return errors.New("package entry had no hostname")
	}
	return p.Fields.validate()
}

// toLogEntry converts a pkgLogEnt that has been identified as vulnerable into the line format
// that will we push to firehose for storage in s3. v represents the vulnerability data applicable
// to the package.
func (p *pkgLogEnt) toLogEntry(v database.VulnerabilityWithAffected) string {
	appname := "unknown"
	// See if we can get the app name from the submitted instance tags
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
	if p.PkgArch == "" {
		return errors.New("package entry had no package arch")
	}
	if p.Dist == "" {
		return errors.New("package entry had no distribution identifier")
	}
	if p.FQDN == "" {
		p.FQDN = "unknown"
	}
	if p.AMI == "" {
		p.AMI = "unknown"
	}
	if p.InstanceID == "" {
		p.InstanceID = "unknown"
	}
	if p.InstanceType == "" {
		p.InstanceType = "unknown"
	}
	return nil
}

type config struct {
	cacheDir     string // Cache directory for cache generation
	inputSample  string // If set, read and process an input sample from path
	makeCache    bool   // If true, cache will be generated
	outputStream string // Kinesis Firehose output stream

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

func checkVuln(p pkgLogEnt) (ret []string, err error) {
	err = p.validate()
	if err != nil {
		// Don't treat as fatal but log it
		log.Printf("%v\n", err)
		return ret, nil
	}
	// Only centos:6 and centos:7 for now
	if !strings.HasPrefix(p.Fields.Dist, "centos:") {
		log.Printf("skipping unsupported dist %v for %v\n", p.Fields.Dist, p.Hostname)
		return ret, nil
	}
	log.Printf("check %v on %v (%v)\n", p.Fields.PkgName, p.Hostname, p.Fields.PkgVersion)
	for _, v := range cfg.rhelData.Vulnerabilities {
		for _, w := range v.Affected {
			if p.Fields.Dist != w.Namespace.Name {
				continue
			}
			if w.FeatureName != p.Fields.PkgName {
				continue
			}
			f, err := scribe.TestEvrCompare(scribe.EvropGreaterThan,
				w.FixedInVersion, p.Fields.PkgVersion)
			if err != nil {
				return ret, err
			}
			if f {
				ret = append(ret, p.toLogEntry(v))
			}
		}
	}
	return ret, nil
}

func handler(ctx context.Context, kinesisEvent events.KinesisEvent) error {
	log.Printf("handler executing for %v records\n", len(kinesisEvent.Records))
	var obuf []string
	for _, r := range kinesisEvent.Records {
		var p pkgLogEnt
		err := json.Unmarshal(r.Kinesis.Data, &p)
		if err != nil {
			// Don't treat this as fatal but log it
			log.Printf("%v\n", err)
			continue
		}
		s, err := checkVuln(p)
		if err != nil {
			return err
		}
		if len(s) > 0 {
			obuf = append(obuf, s...)
		}
	}
	if len(obuf) > 0 {
		err := kinesisWrite(obuf)
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

	if cfg.inputSample != "" {
		// If in sample mode, just compare the sample data set against vulnerability
		// data in the cache
		var (
			le     pkgLogEnt
			outbuf []string
		)
		// Load a sample file, which should be JSON mozlog entries with package
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
			lns, err := checkVuln(le)
			if err != nil {
				log.Fatalf("%v\n", err)
			}
			if len(lns) > 0 {
				outbuf = append(outbuf, lns...)
			}
		}
		if scn.Err() != nil {
			log.Fatalf("%v\n", scn.Err())
		}
		for _, x := range outbuf {
			log.Printf("%v\n", x)
		}
	} else {
		lambda.Start(handler)
	}
}
