package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// getHostname first tries to get the hostname from the kernel by calling os.Hostname.
// If that fails, it tries to run the hostname command.
//
// We want to prefer the kernel hostname, but if the obtained FQDN from DNS
// has an initial component that matches the kernel hostname, use the FQDN
// instead since we get the full hostname that way.
func getHostname() string {
	var kernhosterr bool
	kernhostname, err := os.Hostname()
	if err == nil {
		// if we succeeded
		if strings.ContainsAny(kernhostname, ".") {
			return kernhostname
		}
	} else {
		kernhostname = "localhost"
		kernhosterr = true
	}
	fqdnhostbuf, err := exec.Command("hostname", "--fqdn").Output()
	if err != nil {
		return kernhostname
	}
	fqdnhost := string(fqdnhostbuf)
	fqdnhost = fqdnhost[0 : len(fqdnhost)-1]
	if kernhosterr {
		return fqdnhost
	}
	hcomp := strings.Split(fqdnhost, ".")
	if kernhostname == hcomp[0] {
		return fqdnhost
	}
	return kernhostname
}

// getSysVersion returns the version of the linux system
func getSysInfo() (sysinfo string, err error) {
	var err1 error
	sysinfo, err = getLSBRelease()
	if err != nil {
		sysinfo, err1 = getIssue()
		if err1 != nil {
			err = fmt.Errorf("failed to read sysinfo from lsb (err was %q) and issue (err was %q)", err.Error(), err1.Error())
		} else {
			err = nil
		}
	}
	return
}

// getLSBRelease reads the linux identity from lsb_release -a
func getLSBRelease() (desc string, err error) {
	path, err := exec.LookPath("lsb_release")
	if err != nil {
		return
	}
	out, err := exec.Command(path, "-i", "-r", "-c", "-s").Output()
	if err != nil {
		return
	}
	desc = fmt.Sprintf("%s", out[0:len(out)-1])
	desc = cleanString(desc)
	return
}

// getIssue parses /etc/issue and returns the first line
func getIssue() (string, error) {
	issue, err := ioutil.ReadFile("/etc/issue")
	if err != nil {
		return "", err
	}
	loc := bytes.IndexAny(issue, "\n")
	if loc < 2 {
		return "", fmt.Errorf("issue string not found")
	}
	return fmt.Sprintf("%s", issue[0:loc]), nil
}

// getDist parses various distribution files to find the distro version
func getDist() (string, error) {
	data, err := ioutil.ReadFile("/etc/centos-release")
	if err != nil {
		return "", nil
	}
	loc := bytes.IndexAny(data, "\n")
	if loc < 2 {
		return "", fmt.Errorf("issue string not found")
	}
	issue := fmt.Sprintf("%s", data[0:loc])
	if strings.HasPrefix(issue, "CentOS Linux release 5") {
		return "centos:5", nil
	}
	if strings.HasPrefix(issue, "CentOS Linux release 6") {
		return "centos:6", nil
	}
	if strings.HasPrefix(issue, "CentOS Linux release 7") {
		return "centos:7", nil
	}
	if strings.HasPrefix(issue, "CentOS Linux release 8") {
		return "centos:8", nil
	}
	return issue, nil
}

// cleanString removes spaces, quotes and newlines
func cleanString(str string) string {
	if len(str) < 1 {
		return str
	}
	if str[len(str)-1] == '\n' {
		str = str[0 : len(str)-1]
	}
	// remove heading whitespaces and quotes
	for {
		if len(str) < 2 {
			break
		}
		switch str[0] {
		case ' ', '"', '\'':
			str = str[1:len(str)]
		default:
			goto trailing
		}
	}
trailing:
	// remove trailing whitespaces, quotes and linebreaks
	for {
		if len(str) < 2 {
			break
		}
		switch str[len(str)-1] {
		case ' ', '"', '\'', '\r', '\n':
			str = str[0 : len(str)-1]
		default:
			goto exit
		}
	}
exit:
	// remove in-string linebreaks
	str = strings.Replace(str, "\n", " ", -1)
	str = strings.Replace(str, "\r", " ", -1)
	return str
}
