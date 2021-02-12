import ipaddress
import boto3
import json
import concurrent.futures
import argparse
import socket
import logging
from botocore.config import Config
from threading import Lock
from random import shuffle

logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

ZIPFILE = "workercode-portscan.zip"  # local ZIP if not using S3zip
FN_NAME = "scanworker"

class Scanner:
    def __init__(
            self,
            role_arn=None,
            handler_name=None,
            region=None,
            s3zip=None,
            worker_name=FN_NAME,
            worker_max=1,
            thread_max=1,
            nmapargs=None):

        self.botoConfig = Config(
            region_name=region,
            read_timeout=600,
            connect_timeout=600,
            retries={"total_max_attempts": 10}
        )

        self.handler_name = handler_name
        self.nmapargs = nmapargs
        self.role_arn = role_arn
        self.region = region

        # Populate codeParams with the code ZIP source (S3 or local)
        if s3zip:
            s3bucket = s3zip.split('/')[0]
            s3key = "/".join(s3zip.split('/')[1:])
            self.codeParams = {'S3Bucket': s3bucket, 'S3Key': s3key}
            logger.debug(f"Using code from S3. Bucket = {s3bucket}, Key = {s3key}")
        else:
            self.codeParams = {'ZipFile': open(ZIPFILE, 'rb').read()}

        # Create a default client that the class can use for single tasks
        self.lambda_client = boto3.client('lambda', config=self.botoConfig)

        self.worker_name = FN_NAME  # Prefix name of Lambda functions
        self.worker_max = int(worker_max)  # Max number of Lambda worker functions
        self.worker_current = 0  # Keep track of which Lambda worker was the last used
        self.thread_max = int(thread_max)

        # Intialize other stuff
        self.targets = []
        self.ports = []
        self.target_tuples = []
        self.lck = Lock()
        self.fn_names = set()

    def is_ip(self, address):
        try:
            ipaddress.ip_address(address)
        except Exception as e:
            return False
        return True

    def is_network(self, network):
        try:
            ipaddress.ip_network(network)
        except Exception as e:
            return False
        return True

    def add_target(self, host):
        target = host
        if self.is_ip(target):
            self.targets.append(target)
            return True
        elif self.is_network(target):
            for host in ipaddress.ip_network(target).hosts():
                self.targets.append(str(host))
            return True
        else:
            # Target must be a hostname
            # Try to convert hostname to IP and append
            target = socket.gethostbyname(host)
            logger.debug(f"Resolved {host} to {target}")
            self.targets.append(target)

        return False

    def add_targets_from_file(self, filename):
        try:
            f = open(filename, 'r')
            for line in f:
                line = line.strip()
                if not self.add_target(line):
                    print("ERROR: Could not add target: " + str(line))
        except Exception as e:
            return False
        return True

    def add_port(self, port):
        self.ports.append(int(port))

    # Add multiple ports from dict of ports
    # Ports can be a single port, or a range like 80-90
    def add_ports(self, ports):
        for port in ports:
            p = str(port)

            # Break up port range into individual ports
            if "-" in p:
                # Get start and end ports
                start = int(p.split("-")[0])
                end = int(p.split("-")[1]) + 1

                for i in range(start, end):
                    self.ports.append(i)
            # Otherwise, convert string value to int
            else:
                self.ports.append(int(port))

    def add_ports_from_string(self, ports):
        port_list = ports.split(',')
        self.add_ports(port_list)

    # Populates the list of target tuples to proccess and randomizes
    def populate_target_tuples(self):
        for target in self.targets:
            for port in self.ports:
                self.target_tuples.append((target, port))
        shuffle(self.target_tuples)

    # Get reliable count of all workers with pagination
    def count_all_lambda_workers(self):
        function_count = 0
        paginator = self.lambda_client.get_paginator('list_functions')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            for function in page['Functions']:
                prefix = self.worker_name + "_"
                if prefix in function['FunctionName']:
                    function_count = function_count + 1
                    self.fn_names.add(function['FunctionName'])
        return function_count

    # Delete all workers from Lambda
    def threaded_lambda_cleanup(self):
        tmpcount = self.count_all_lambda_workers()
        logger.debug(f"Lambda Functions to delete: {tmpcount}")
        prefix = self.worker_name + "_"
        future_list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            for function in self.fn_names:
                future = executor.submit(self.delete_function, function)
                future_list.append(future)
        for future in future_list:
            try:
                logger.debug(future.result())
            except Exception as e:
                print(e)

        # Verify and print count at end
        tmpcount = self.count_all_lambda_workers()
        logger.debug(f"Lambda Functions now: {tmpcount}")

    # Delete the given Lambda function from AWS
    def delete_function(self, fn_name):
        logger.debug(f"Deleting {fn_name}")
        tmp_lambda_client = boto3.client('lambda', config=self.botoConfig)
        tmp_lambda_client.delete_function(FunctionName=fn_name)
        return("Success Deleting", fn_name)

    # Keep track of which Lambda function worker is in use
    def next_worker(self):
        self.worker_current = self.worker_current + 1
        if self.worker_current >= self.worker_max:
            self.worker_current = 0

    # Start the threaded scan against the target tuple list
    def threadedScan(self):
        global args
        future_list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_max) as executor:
            for i in range(0, len(self.target_tuples)):
                future = executor.submit(self.scan_next_tuple)
                future_list.append(future)
            for future in concurrent.futures.as_completed(future_list):
                try:
                    res = future.result()
                    output = f'{res["source_ip"]:<15} --> {res["target"]:<15}  {str(res["port"]) + "/tcp":<9}  {"Open" if res["status"] else "Closed/Filtered"}'

                    # Dont show if --open flag and port is closed
                    if not (args.open and not res["status"]):
                        logger.warning(output)
                except Exception as e:
                    logger.info(e)
                del future
        print("All threads completed")

    # Scan a single tuple target
    def scan_next_tuple(self):
        # Pop the next IP/Port tuple off
        tmpTarget, tmpPort = self.target_tuples.pop()

        # Use lock, save what worker we should use, then increment for next
        with self.lck:
            local_worker = self.worker_current
            logger.debug(f"Using {self.worker_name}_{local_worker} for target: {tmpTarget}:{tmpPort}")
            self.next_worker()

        # Create new boto3 client to be thread-safe
        tmp_lambda_client = boto3.client('lambda', config=self.botoConfig)

        # Invoke Lambda function to actually execute the port scan
        response = tmp_lambda_client.invoke(
            FunctionName=f'{self.worker_name}_{local_worker}',
            InvocationType='RequestResponse',
            Payload=json.dumps(dict({'host': tmpTarget, 'proto': 'TCP', 'port': tmpPort}))
        )

        # Get response
        result = json.loads(response['Payload'].read().decode('utf-8'))
        source_ip = ''
        # Parse result
        if 'errorMessage' in result:
            logger.info(f'Error occured for: {tmpTarget}:{tmpPort}')
            status = False          # Sometimes Lambda will time out trying to connect to a closed port
        elif 'body' in result:
            status = bool(result['body']) # True or False
            source_ip = result['source_ip']
        else:
            status = None           # Something went wrong

        # Return source ip, target, port, and result: True(Open) or False(Closed)
        return({"source_ip": source_ip, "target": tmpTarget, "port": tmpPort, "status": status})

    # Start multi-threading job to create lambda functions in AWS faster
    def createWorkers(self, func_timeout):
        future_list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            for i in range(self.worker_max):
                future = executor.submit(self.create_worker_function, i, func_timeout)
                future_list.append(future)
            for future in concurrent.futures.as_completed(future_list):
                try:
                    logger.debug(future.result())
                except Exception as e:
                    logger.info(e)

        logger.debug("Verifying worker count...")
        tmpCount = self.count_all_lambda_workers()
        logger.debug(f"Workers: {tmpCount}")

        # Raise exception if actual function count doens't match requested
        if tmpCount != self.worker_max:
            raise Exception(f"Error: could not create required worker functions. Counted: {tmpCount} Requested: {self.worker_max}")

    # Create single AWS lambda function worker
    def create_worker_function(self, functionIndex, func_timeout):
        fn_name = self.worker_name + "_" + str(functionIndex)
        try:
            logger.debug(f"Creating worker: {fn_name}")
            tmp_lambda_client = boto3.client('lambda', config=self.botoConfig)
            tmp_lambda_client.create_function(
                FunctionName=fn_name,
                Runtime='python3.8',
                Role=self.role_arn,
                Handler=f"{self.handler_name}.lambda_handler",
                Code=self.codeParams,
                Timeout=func_timeout)
            return(f"Success creating: {fn_name}")
        except Exception as e:
            if hasattr(e, 'message'):
                raise type(e)(e.message + ' happened with %s' % fn_name)
            else:
                raise type(e)('"Error happened with %s' % fn_name)

    # Conduct an nmap scan against the targets
    def threadedNmapScan(self):
        future_list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_max) as executor:
            for target in self.targets:
                future = executor.submit(self.nmapscan_next_target, target)
                future_list.append(future)
            for future in concurrent.futures.as_completed(future_list):
                try:
                    res = future.result()
                except Exception as e:
                    logger.info(e)
                del future
        logger.info("All threads completed")

    # Scan a single tuple target
    def nmapscan_next_target(self, target):
        # Pop the next IP target off
        tmpTarget = target

        # Use lock, save what worker we should use, then increment for next
        with self.lck:
            local_worker = self.worker_current
            logger.debug(f"Using {self.worker_name}_{local_worker} for target: {tmpTarget}")
            self.next_worker()

        # Create new boto3 client to be thread-safe
        tmp_lambda_client = boto3.client('lambda', config=self.botoConfig)

        # Invoke Lambda function to actually execute the port scan
        response = tmp_lambda_client.invoke(
            FunctionName=f'{self.worker_name}_{local_worker}',
            InvocationType='RequestResponse',
            Payload=json.dumps(dict({"args": self.nmapargs, "target": tmpTarget}))
        )

        # Get response
        responseJson = json.loads(response['Payload'].read().decode('utf-8'))
        if 'errorMessage' in responseJson:
            logger.info(f'Error occured for: {tmpTarget}')
            return responseJson['errorMessage']  # try to catch lambda errors
        else:
            logger.debug(f"Scan complete for {tmpTarget}")
            #logger.debug(f"Details for {tmpTarget}: {responseJson}")
            writeOutput(responseJson)

            # Log source IPs for each scan
            logger.info(f"{responseJson['source_ip']:<15} --> {responseJson['target']:<15}")

            return True


# Helper function to write nmap/gnmap/xml output files
def writeOutput(responseJson):
    target = responseJson['target']
    with open(f"{target}.gnmap", 'w') as fout:
        fout.write(responseJson['output_gnmap'])
    with open(f"{target}.nmap", 'w') as fout:
        fout.write(responseJson['output_nmap'])
    with open(f"{target}.xml", 'w') as fout:
        fout.write(responseJson['output_xml'])

##########################################
# Parse arguments
##########################################
def parse_args(parser):
    #parser.add_argument('command', help='subcommand for scan type')

    subparsers = parser.add_subparsers(dest="subcommand", metavar='')

    # PORTSCAN SUBCOMMAND PARSING
    portscan = subparsers.add_parser('portscan', help='Portscan subcommand. Get port up/down status. scan is randomized across target ports and IPs')
    requiredNamed = portscan.add_argument_group('required named arguments')
    requiredNamed.add_argument('--ports', nargs='?', required=True, dest='ports', help='Ports to scan. Example:80,81,1000-2000')
    requiredNamed.add_argument('--role', nargs='?', required=True, dest='role', help='AWS IAM role ARN for lambda functions to use')
    requiredNamed.add_argument('--target', nargs='?', dest='target', help='IP address or CIDR range')
    requiredNamed.add_argument('--target-file', nargs='?', dest='target_file', help='File with one IP address or CIDR per line')
    requiredNamed.add_argument('--region', nargs='?', dest='region', required=True, help='Specify the target region to create and run the Lambda workers (e.g, us-east-1)')
    portscan.add_argument('--workers', default=1, dest='worker_max', help='Number of Lambda workers to create. Default: 1')
    portscan.add_argument('--threads', default=1, dest='thread_max', help='Max number of threads for port scanning. Default: 1')
    portscan.add_argument('--outfile', dest='outfile', help='Specify the output file to store timestamped scan results')
    portscan.add_argument('--open', dest='open', action="store_true", help='Only show open ports')
    portscan.add_argument('--s3-zip', dest='s3zip', nargs='?', help='Provide a S3 bucket and key path to the code ZIP file and the controller will use that to create each function worker instead of uploading each manually')
    portscan.add_argument("-v", "--verbose", dest='verbose', action="store_true", help="increase console output verbosity")
    portscan.set_defaults(func=subCommand_portscan)

    # NMAP SUBCOMMAND PARSING
    nmap = subparsers.add_parser('nmap', help='Nmap subcommand. Each Lambda worker will conduct Nmap on its target')
    nmap.add_argument('nmapargs', help='''Arguments to pass to nmap. Note: do NOT include any output flags. Add -- before all nmap arguments to parse correctly.
        Example: %(prog)s --target [] --role [] --region [] --s3-zip [] -- "-Pn --top-ports 100"''')
    nmaprequiredNamed = nmap.add_argument_group('required named arguments')
    nmaprequiredNamed.add_argument('--target', nargs='?', dest='target', help='IP address or CIDR range')
    nmaprequiredNamed.add_argument('--target-file', nargs='?', dest='target_file', help='File with one IP address or CIDR per line')
    nmaprequiredNamed.add_argument('--region', nargs='?', dest='region', required=True, help='Specify the target region to create and run the Lambda workers (e.g, us-east-1)')
    nmaprequiredNamed.add_argument('--role', nargs='?', required=True, dest='role', help='AWS IAM role ARN for lambda functions to use')
    nmap.add_argument('--workers', default=1, dest='worker_max', help='Number of Lambda workers to create. Default: 1')
    nmap.add_argument('--threads', default=1, dest='thread_max', help='Max number of threads for port scanning. Default: 1')
    nmap.add_argument('--s3-zip', dest='s3zip', nargs='?', help='Provide a S3 bucket and key path to the code ZIP file and the controller will use that to create each function worker instead of uploading each manually')
    nmap.add_argument('--outfile', dest='outfile', help='Specify the output file to store timestamped scan results')
    nmap.add_argument("-v", "--verbose", dest='verbose', action="store_true", help="increase console output verbosity")
    nmap.set_defaults(func=subCommand_nmap)

    # CLEAN SUBCOMMAND PARSING
    clean = subparsers.add_parser('clean', help='Clean subcommand. Do not scan. Delete all Lambda functions matching ^scanworker_. Use if something goes wrong.')
    cleanrequiredNamed = clean.add_argument_group('required named arguments')
    cleanrequiredNamed.add_argument('--region', nargs='?', dest='region', required=True, help='Specify the target region to clean')
    clean.add_argument("-v", "--verbose", dest='verbose', action="store_true", help="increase console output verbosity")
    clean.set_defaults(func=subCommand_clean)


    args = parser.parse_args()

    return args




##############################################
# Main program execution
##############################################
def subCommand_portscan(args):
    global ZIPFILE
    ZIPFILE = "workercode-portscan.zip"  # local ZIP if not using S3zip

    # Make sure required arguments are set
    if not (args.target or args.target_file) or not args.ports or not args.role:
        parser.print_help()
        exit(1)

    if args.target and args.target_file:
        print("ERROR: Specify a target or a target file, not both.")
        exit()

    # Initialize scanner
    scanner = Scanner(
        role_arn=args.role,
        worker_name=FN_NAME,
        handler_name="lambscan",
        worker_max=args.worker_max,
        thread_max=args.thread_max,
        s3zip=args.s3zip,
        region=args.region)

    #print("codeParams:", scanner.codeParams)

    # Add target ports
    scanner.add_ports_from_string(args.ports)

    # Add target IPs
    if args.target_file:
        scanner.add_targets_from_file(args.target_file)
    if args.target:
        scanner.add_target(args.target)

    # Populate a shuffled IP/Port tuple list to process
    scanner.populate_target_tuples()
    logger.debug(f"# of Host/Port Combos: {len(scanner.target_tuples)}")

    # Create the AWS lambda function workers
    print(f"[*] Creating {args.worker_max} Lambda workers in AWS...")
    scanner.createWorkers(func_timeout=20)  # 20s timeout for portscans

    # Begin the port scan
    print("[*] Scanning ports...")
    logger.debug(f"Using {scanner.thread_max} threads")
    scanner.threadedScan()

    # Delete Lambda worker functions
    print("[*] Deleting Lambda workers from AWS...")
    scanner.threaded_lambda_cleanup()
    print("[*] Done!")


def subCommand_nmap(args):
    global ZIPFILE
    ZIPFILE = "workercode-nmap.zip"  # local ZIP if not using S3zip

    # Make sure required arguments are set
    if not (args.target or args.target_file) or not args.role:
        parser.print_help()
        exit(1)

    if args.target and args.target_file:
        print("ERROR: Specify a target or a target file, not both.")
        exit()

    logger.debug(f"Using nmap args: {args.nmapargs}")

    # Initialize scanner
    scanner = Scanner(
        role_arn=args.role,
        worker_name=FN_NAME,
        handler_name="nmap_aws",
        worker_max=args.worker_max,
        thread_max=args.thread_max,
        s3zip=args.s3zip,
        region=args.region,
        nmapargs=args.nmapargs)

    # Add target IPs
    if args.target_file:
        scanner.add_targets_from_file(args.target_file)
    if args.target:
        scanner.add_target(args.target)

    # Shuffle targets
    shuffle(scanner.targets)
    logger.debug(f"{len(scanner.targets)} targets loaded")

    # Create the AWS lambda function workers
    print(f"[*] Creating {args.worker_max} Lambda workers in AWS...")
    scanner.createWorkers(func_timeout=300)  # 5m timeout for nmap scans

    # Start nmap scans
    print("[*] Executing Nmap scans...")
    logger.debug(f"Using {scanner.thread_max} threads")
    scanner.threadedNmapScan()

    # Clean up functions
    print("[*] Deleting Lambda functions from AWS...")
    scanner.threaded_lambda_cleanup()
    print("[*] Done!")


def subCommand_clean(args):
    scanner = Scanner(region=args.region)
    try:
        print("[*] Deleting Lambda functions from AWS...")
        scanner.threaded_lambda_cleanup()
    except Exception as e:
        print("ERROR: Could not delete Lambda functions!\nException: " + str(e))
        exit(1)
    exit(0)


if __name__ == "__main__":

    # Parse arguments
    parser = argparse.ArgumentParser()
    args = parse_args(parser)

    # -- LOGGER: CONSOLE HANDLER --
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logger.addHandler(ch)

    # Break here to clean subcommand
    if args.subcommand == 'clean':
        subCommand_clean(args)

    # -- LOGGER: FILE HANDLER --
    if args.outfile:
        # create file handler which logs only the scan result messages
        fh = logging.FileHandler(args.outfile)
        fh.setLevel(logging.WARNING)
        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        # add formatter to fh
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        # log the execution
        logger.warning(f'{__file__.split("/")[-1]} ARGS: {vars(args)}')

    args.func(args)
