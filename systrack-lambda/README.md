# Lambda Function for OS Package Vulnerability Validation

This is a Lambda function that compares package information submitted via a
Kinesis stream in mozlog format against OS advisory infomation, and identifies
packages that potentially have known vulnerabilities. Any hits are logged to a
Kinesis Firehose output stream.
