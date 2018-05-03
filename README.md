SysTrack
========

System tracking for security. This repository contains a command line tool
called `systrack` that dumps metadata and installed packages from linux
systems into kinesis, and a lambda function `systrack-lambda` that processes
kinesis messages and looks for security issues.

The idea is to run `systrack` from a cronjob on production systems, publishes
the state of running systems into kinesis, and analyze that data and raise
alerts in the `systrack-lambda` function.
