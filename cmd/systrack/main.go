package main

import (
	"log"

	"github.com/mozilla/scribe"
	"github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

func main() {
	hook, err := mozlogrus.NewKinesisHook("secops-dumper")
	logger := logrus.New()
	logger.Hooks.Add(hook)
	logger.Formatter = &mozlogrus.MozLogFormatter{LoggerName: "secops-dumper", Type: "app.log"}

	fqdn := getHostname()
	issue, err := getSysInfo()
	if err != nil {
		log.Fatal(err)
	}
	dist, err := getDist()
	if err != nil {
		log.Fatal(err)
	}
	instanceid, instancetype, localip, ami, err := getAWSMetadata()
	if err != nil {
		log.Fatal(err)
	}
	tags, err := getInstanceTags(instanceid)
	if err != nil {
		log.Fatal(err)
	}
	// get a list of all system packages
	for _, pkg := range scribe.QueryPackages() {
		logger.WithFields(logrus.Fields{
			"fqdn":         fqdn,
			"dist":         dist,
			"issue":        issue,
			"instanceid":   instanceid,
			"instancetype": instancetype,
			"instancetags": tags,
			"localip":      localip,
			"ami":          ami,
			"pkgname":      pkg.Name,
			"pkgversion":   pkg.Version,
			"pkgtype":      pkg.Type,
			"pkgarch":      pkg.Arch,
		}).Info("package " + pkg.Name + " " + pkg.Version + " " + pkg.Type + " " + pkg.Arch)
	}
}
