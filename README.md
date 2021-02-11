# Lambda Port Scanner

## Overview
* Automatically provisions hundreds of Lambda function workers (each with unique public source IPs) to conduct distributed port scanning and source IP rotation
* Randomizes order of target IP and ports to blend in with generic "noise"
* Automatically tears down all Lambda functions after a scan to prevent a "warm" reload on subseqent scans. This guarantees a fresh, unique source IP for each function worker each time.

## Why?
Network perimeter appliances and controls are getting much better at detecting scanners and reconnaissance activity. They may be silently blocking or intentionally returning inaccurate results. Normally, the only option is to drastically reduce the scan timing in order to not trigger anti-scanning mechanisms. In circumstances where timing cannot be sacrificed, this tool will likely bypass anti-scanning controls by distributing the scan through hundreds of Lambda function workers, which each having a unique source IP.

## Other Source IP Rotation options:

* [ProxyCannon-NG](https://github.com/proxycannon/proxycannon-ng): Sets up a private VPN with rotation through user-controlled “exit nodes”. **CONS**: need to provision full EC2/DigitalOcean/etc instances as exit nodes, and those IPs stay permanent per exit node. So to achieve rotation through 10 AWS IPs, you need 10 full EC2 instances.
* [Fireprox](https://github.com/ustayready/fireprox): Uses AWS API Gateway for creating on the fly HTTP pass-through proxies. **CONS**: not designed for scanning as each API gateway is a 1-to-1 mapping to a specific target host

## Pre-reqs
* An AWS account
* Setup AWS credentials locally for Boto3 to use (usually either populated in your `~/.aws/credentials` file or environment variables. See [Boto3 docs](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html) for more details)
* Create a IAM Lambda execution role in AWS. 
	* This will be used for the Lamba function workers. 
	* This role doesn't need special permisssions, just the `role-trust-policy.json` document
* [optional]: upload the `lambda-port-scanner--ports.zip` to a S3 bucket in your account to take advantage of the `--s3-zip` parameter. This allows the controller to generate Lambda functions from this code instead of manually uploading it with each new worker.

#### [Optional] Deploy Script:
There is a one-time use `deploy.sh` deploy script included which will do these steps for you:

* Create the required Lambda Execution IAM role
* Create a new S3 bucket and upload the code ZIP files to that bucket

Just run this once and you can then use the resources for the `--role` and `--s3-zip` arguments:

```
./deploy.sh

[*] Creating S3 bucket
"/b424c464-6bff-11eb-89b9-faffc212389a-lambda-port-scanner"
[*] Uploading code ZIP files
upload: ./lambda-port-scanner--ports.zip to s3://b424c464-6bff-11eb-89b9-faffc212389a-lambda-port-scanner/lambda-port-scanner--ports.zip
upload: ./lambda-port-scanner--nmap.zip to s3://b424c464-6bff-11eb-89b9-faffc212389a-lambda-port-scanner/lambda-port-scanner--nmap.zip
[*] Creating Lambda IAM Execution Role
Use these for controller arguments:
--role "arn:aws:iam::<REDACTED>:role/service-role/lambda-port-scanner"
--s3-zip b424c464-6bff-11eb-89b9-faffc212389a-lambda-port-scanner/lambda-port-scanner--ports.zip
``` 

## Installation
### Pipenv Installation (recommended)
```
git clone https://github.com/bridge-four/lambda-port-scanner.git
cd lambda-port-scanner
pipenv install
pipenv run python lambscanController.py --help
```
### Normal Python (v3.5+)
```
git clone https://github.com/bridge-four/lambda-port-scanner.git
cd lambda-port-scanner
pip3 install boto3
python3 lambscanController.py --help
```
## Usage
```
usage: lambscanController.py [-h] [--ports [PORTS]] [--role [ROLE]] [--target [TARGET]] [--target-file [TARGET_FILE]] [--workers WORKER_MAX] [--threads THREAD_MAX] [--clean] [--region REGION]
                             [--outfile OUTFILE] [--open] [-v]

Create workers in Lambda to conduct distributed port scans on selected targets

optional arguments:
  -h, --help            show this help message and exit
  --ports [PORTS]       Ports to scan. Example:80,81,1000-2000
  --role [ROLE]         AWS IAM role ARN for lambda functions to use
  --target [TARGET]     IP address or CIDR range
  --target-file [TARGET_FILE]
                        File with one IP address or CIDR per line
  --workers WORKER_MAX  Number of Lambda workers to create
  --threads THREAD_MAX  Max number of threads for port scanning
  --clean               Do not scan. Delete all Lambda functions matching ^scanworker_. Use if something goes wrong
  --region REGION       Specify the target region to create and run the lambscan workers (e.g, us-east-1)
  --outfile OUTFILE     Specify the output file to store timestamped scan results
  --open                Only show open ports
  --s3-zip [S3ZIP]      Provide a S3 bucket and key path to the code ZIP file and the controller will use that to create each function worker instead of uploading each manually
  -v, --verbose         increase console output verbosity
```
### Examples:

Simple example with verbosity (`-v`) enabled to see the details of what is happening. This scan provisions 2 Lambda workers to scan 4 ports on the target `scanme.nmap.org `. From the output, we can see that those 2 workers were assigned the IPs `3.233.217.229` and `3.233.217.229` from the AWS IP pool, and the controller rotated through them to complete the 4 port scans: 

```
$ pipenv run python lambscanController.py \
	--role arn:aws:iam::<AWSACCOUNT>:<EXECUTIONROLE> \
	--target scanme.nmap.org \
	--threads 2 \
	--workers 2 \
	--ports 21,22,80,443 \
	--region us-east-1 \
	-v
	
Resolved scanme.nmap.org to 45.33.32.156
# of Host/Port Combos: 4
[*] Creating 2 Lambda workers in AWS...
Creating worker: scanworker_0
Creating worker: scanworker_1
Success creating: scanworker_0
Success creating: scanworker_1
Verifying worker count...
Workers: 2
[*] Scanning ports...
Using 2 threads
Using worker scanworker_0 for target: 45.33.32.156:80
Using worker scanworker_1 for target: 45.33.32.156:21
Using worker scanworker_0 for target: 45.33.32.156:443
3.233.217.229   --> 45.33.32.156     80/tcp     Open
Using worker scanworker_1 for target: 45.33.32.156:22
3.238.3.192     --> 45.33.32.156     21/tcp     Closed/Filtered
3.233.217.229   --> 45.33.32.156     443/tcp    Closed/Filtered
3.238.3.192     --> 45.33.32.156     22/tcp     Open
All threads completed
[*] Deleting Lambda workers from AWS...
Lambda Functions to delete: 2
Deleting scanworker_0
Deleting scanworker_1
('Success Deleting', 'scanworker_0')
('Success Deleting', 'scanworker_1')
Lambda Functions now: 0
[*] Done!
```

Scan targeted ports on a target subnet. (This rotates each port scan through 20 Lambda workers provisioned in the `us-east-1` region, which will provide 20 unique source IPs to rotate through):

```
$ pipenv run python lambscanController.py \
	--role arn:aws:iam::<AWSACCOUNT>:<EXECUTIONROLE> \
	--target 52.94.76.0/24 \
	--threads 20 \
	--workers 20 \
	--ports 21,22,80,443,8080 \
	--region us-east-1

[*] Creating 20 Lambda workers in AWS...
[*] Scanning ports...
54.237.193.133  --> 52.94.76.149     22/tcp     Closed/Filtered
3.88.15.82      --> 52.94.76.38      8080/tcp   Closed/Filtered
3.88.185.34     --> 52.94.76.184     80/tcp     Closed/Filtered
3.83.78.214     --> 52.94.76.137     22/tcp     Closed/Filtered
3.235.94.80     --> 52.94.76.61      443/tcp    Closed/Filtered
18.205.96.112   --> 52.94.76.151     22/tcp     Closed/Filtered
...<snip>...
18.205.96.112   --> 52.94.76.23      8080/tcp   Closed/Filtered
3.235.94.80     --> 52.94.76.55      443/tcp    Closed/Filtered
18.207.120.219  --> 52.94.76.35      21/tcp     Closed/Filtered
3.83.78.214     --> 52.94.76.252     443/tcp    Closed/Filtered
34.201.108.107  --> 52.94.76.191     443/tcp    Closed/Filtered
All threads completed
[*] Deleting Lambda workers from AWS...
[*] Done!
```

Scan ports 1-1024 on all targets in the `targets.txt` file, using 800 Lambda function workers in the `us-west-1` region. Lambda functions will be created using the code uploaded to `s3://b424c464-6bff-11eb-89b9-faffc212389a-lambda-port-scanner/lambda-port-scanner--ports.zip`. All requests (both open and closed) will show on the console and will also be logged with a timestamp to `scan.log`:

```
$ pipenv run python lambscanController.py \
	--role arn:aws:iam::<AWSACCOUNT>:<EXECUTIONROLE> \
	--s3-zip b424c464-6bff-11eb-89b9-faffc212389a-lambda-port-scanner/lambdaportscanner-workercode.zip
	--target-file targets.txt \
	--threads 200 \
	--workers 1000 \
	--ports 1-1024 \
	--region us-west-1 \
	--outfile scan.log

[*] Creating 800 Lambda workers in AWS...
...<snip>...
```

Crash, exception, or other issues? Trigger a manual cleanup of any leftover worker functions that may still exist in a region:   
`pipenv run python lambscanController.py --clean --region us-east-1`

## Caveats:
- You may encounter stability issues when using more than ~800 function workers, such as rate limiting issues (`TooManyRequestsException`), concurrency issues, or Boto3 session issues. If this occurs, reduce the worker count or play with the settings of the `self.botoConfig` Boto3 configuration of the Scanner class.

## Credits:
Some functionality inspired from or originally developed in [LambScan](https://github.com/rickoooooo/LambScan) and [Nmap-aws](https://github.com/3m3x/nmap-aws). Grateful to these developers for their contributions to open source!

## To Do:
- [ ] Concurrency performance comparisons with asyncio or aioboto3 (or potentially shift the execution to an AWS Batch service)
- [ ] Add ability to do a full Nmap per target instead of simple port up/down checks
- [ ] The 1000 function limit is technically *per region*, so we could technically also add ability to distribute the scan across multiple regions to go above that limit
- [ ] Maybe add the option to store output/logs in a S3 bucket or 