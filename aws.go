// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com [:alm]
package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

func getAWSMetadata() (instanceid, instancetype, localip, ami string, err error) {
	instanceid, err = awsFetchMeta("instance-id")
	if err != nil {
		return
	}
	instancetype, err = awsFetchMeta("instance-type")
	if err != nil {
		return
	}
	localip, err = awsFetchMeta("local-ipv4")
	if err != nil {
		return
	}
	ami, err = awsFetchMeta("ami-id")
	return
}

func awsFetchMeta(endpoint string) (result string, err error) {
	tr := &http.Transport{
		Dial: (&net.Dialer{Timeout: time.Second}).Dial,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://169.254.169.254:80/latest/meta-data/" + endpoint)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("invalid HTTP response code returned by metadata service: %v",
			resp.StatusCode)
		return
	}
	if resp.ContentLength == -1 || resp.ContentLength > 10240 {
		err = fmt.Errorf("invalid content length in response body")
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	result = string(body)
	return
}
