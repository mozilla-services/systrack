package main

import (
	"log"

	"go.mozilla.org/systrack"

	"github.com/mozilla/scribe"
	"github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

func main() {
	var (
		p   systrack.PkgMsg
		err error
	)
	hook, err := mozlogrus.NewKinesisHook("secops-dumper")
	logger := logrus.New()
	logger.Hooks.Add(hook)
	logger.Formatter = &mozlogrus.MozLogFormatter{LoggerName: "systrack", Type: "pkg"}

	p.Fqdn = getHostname()
	p.Issue, err = getSysInfo()
	if err != nil {
		log.Fatal(err)
	}
	p.Dist, err = getDist()
	if err != nil {
		log.Fatal(err)
	}
	p.AwsInstanceID, p.AwsInstanceType, p.LocalIP, p.AwsAmiID, err = getAWSMetadata()
	if err != nil {
		log.Println("failed to retrieve AWS metadata, probably not an ec2 instance")
	} else {
		// we have aws metadata so also get the instance tags
		p.AwsInstanceTags, err = getInstanceTags(p.AwsInstanceID)
		if err != nil {
			log.Printf("failed to retrieve AWS instance tags with error: %v", err)
		}
	}
	// get a list of all system packages
	for _, pkg := range scribe.QueryPackages() {
		p.PkgName = pkg.Name
		p.PkgVersion = pkg.Version
		p.PkgType = pkg.Type
		p.PkgArch = pkg.Arch
		logger.WithFields(p.MarshalFields()).Info("package " + pkg.Name + " " + pkg.Version + " " + pkg.Type + " " + pkg.Arch)
	}
}
