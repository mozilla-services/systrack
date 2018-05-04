all: systrack-lambda

package:
	docker run -i --rm -v `pwd`:/go/src/github.com/mozilla-services/systrack/systrack-lambda \
	    golang:1.10 \
	    /bin/bash -c 'cd /go/src/github.com/mozilla-services/systrack/systrack-lambda && make lambda'

lambda: clean systrack-lambda cache
	apt-get update
	apt-get install -y zip
	zip -r systrack-lambda.zip systrack-lambda cache

cache: systrack-lambda
	mkdir cache
	env CACHEDIR=./cache MAKECACHE=1 ./systrack-lambda

clean:
	rm -rf systrack-lambda.zip systrack-lambda cache

systrack-lambda: main.go rhel.go
	go build -o systrack-lambda -ldflags="-s -w" main.go rhel.go

.PHONY: clean lambda package cache
