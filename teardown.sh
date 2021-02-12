#!/bin/bash

BUCKET_NAME='lambdaportscanner'
ROLE_NAME='lambdaportscanner'

function delete_bucket() {
    aws s3 rm "s3://$BUCKET_NAME/" --recursive --no-cli-pager
    aws s3api delete-bucket --bucket $BUCKET_NAME --no-cli-pager
}

function delete_role() {
    aws iam delete-role --role-name $ROLE_NAME --no-cli-pager
}

function main() {
    echo "[*] Tearing down S3 bucket"
    delete_bucket
    echo "[*] Tearing down Lambda IAM Execution Role"
    delete_role
}

main
exit 0