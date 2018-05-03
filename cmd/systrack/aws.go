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
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
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

func getAWSRegion() (region string, err error) {
	region, err = awsFetchMeta("placement/availability-zone")
	if err != nil {
		return
	}
	// trim the last character that represents the availability zone
	region = region[:len(region)-1]
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

func getInstanceTags(instanceid string) (tags []string, err error) {
	// do not read this code. it is unapologetically ugly.
	akey := os.Getenv("AWS_ACCESS_KEY_ID")
	skey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	origRegion := os.Getenv("AWS_REGION")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "")
	os.Setenv("AWS_ACCESS_KEY_ID", "")
	region, err := getAWSRegion()
	if err != nil {
		return
	}
	os.Setenv("AWS_REGION", region)
	defer func() {
		os.Setenv("AWS_ACCESS_KEY_ID", akey)
		os.Setenv("AWS_SECRET_ACCESS_KEY", skey)
		os.Setenv("AWS_REGION", origRegion)
	}()

	svc := ec2.New(session.New())
	input := &ec2.DescribeTagsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("resource-id"),
				Values: []*string{
					aws.String(instanceid),
				},
			},
		},
	}
	result, err := svc.DescribeTags(input)
	if err != nil {
		return
	}
	for _, tag := range result.Tags {
		tags = append(tags, fmt.Sprintf("%s=%s", *tag.Key, *tag.Value))
	}
	return
}
