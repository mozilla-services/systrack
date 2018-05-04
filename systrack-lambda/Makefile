all: pkgcheck-lambda

package:
	docker run -i --rm -v `pwd`:/go/src/github.com/mozilla-services/pkgcheck-lambda \
	    golang:1.10 \
	    /bin/bash -c 'cd /go/src/github.com/mozilla-services/pkgcheck-lambda && make lambda'

dep:
	go get ./...

lambda: clean pkgcheck-lambda cache
	apt-get update
	apt-get install -y zip
	zip -r pkgcheck-lambda.zip pkgcheck-lambda cache

cache: pkgcheck-lambda
	mkdir cache
	env CACHEDIR=./cache MAKECACHE=1 ./pkgcheck-lambda

clean:
	rm -rf pkgcheck-lambda.zip pkgcheck-lambda cache

pkgcheck-lambda: main.go rhel.go
	go build -o pkgcheck-lambda -ldflags="-s -w" main.go rhel.go

.PHONY: clean dep lambda package cache
