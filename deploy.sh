#!/bin/bash

PORTS_LAMBDA_WORKER_ZIP='workercode-portscan.zip'
NMAP_LAMBDA_WORKER_ZIP='workercode-nmap.zip'
BUCKET_NAME='lambdaportscanner'
ROLE_NAME='lambdaportscanner'

function create_bucket() {
    aws s3api create-bucket --bucket $BUCKET_NAME | jq '.Location'
}

function upload_code_zips() {
    aws s3 cp $PORTS_LAMBDA_WORKER_ZIP "s3://$BUCKET_NAME/$PORTS_LAMBDA_WORKER_ZIP"
    aws s3 cp $NMAP_LAMBDA_WORKER_ZIP "s3://$BUCKET_NAME/$NMAP_LAMBDA_WORKER_ZIP"
}

function create_role() {
    ROLE_ARN=`aws iam create-role --path '/service-role/' \
        --role-name $ROLE_NAME \
        --assume-role-policy-document file://role-trust-policy.json | jq '.Role.Arn'`
}

function main() {
    echo "[*] Creating S3 bucket"
    create_bucket
    echo "[*] Uploading code ZIP files"
    upload_code_zips
    echo "[*] Creating Lambda IAM Execution Role"
    create_role
    echo "** Use these for controller arguments: **" 
    echo "--role $ROLE_ARN"
    echo "For portscan command: --s3-zip $BUCKET_NAME/$PORTS_LAMBDA_WORKER_ZIP"
    echo "For nmap command: --s3-zip $BUCKET_NAME/$NMAP_LAMBDA_WORKER_ZIP"
}

main
exit 0