package main

import (
	"log"
	"os"

	"github.com/evalphobia/logrus_kinesis"
	"github.com/mozilla/scribe"
	"github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

func init() {
	mozlogrus.Enable("secops-dumper")
}

func main() {
	hook, err := logrus_kinesis.New("secops-dumper", logrus_kinesis.Config{
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		Region:    os.Getenv("AWS_REGION"),
	})
	logger := logrus.New()
	logger.Formatter = &mozlogrus.MozLogFormatter{LoggerName: "secops-dumper", Type: "app.log"}
	logger.Hooks.Add(hook)

	//logger.Formatter(new(mozlogrus.MozLogFormatter{LoggerName: "secops-dumper"}))

	sysinfo, err := getSysInfo()
	if err != nil {
		log.Fatal(err)
	}
	logger.WithFields(logrus.Fields{
		"fqdn":    getHostname(),
		"sysinfo": sysinfo,
	}).Info("system informations retrieved successfully")

	// get a list of all system packages
	for _, pkg := range scribe.QueryPackages() {
		logger.WithFields(logrus.Fields{
			"pkgname":    pkg.Name,
			"pkgversion": pkg.Version,
			"pkgtype":    pkg.Type,
			"pkgarch":    pkg.Arch,
		}).Info("package " + pkg.Name + " " + pkg.Version + " " + pkg.Type + " " + pkg.Arch)
	}
}
