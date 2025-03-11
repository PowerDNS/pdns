# Testing Documentation Workflow with AWS

This setup allows you to test the documentation build and AWS upload processes locally using the [act](https://github.com/nektos/act) tool.

## Prerequisites

1. Install the act tool: https://github.com/nektos/act
2. Docker installed and running

## Files

- `test-docs-aws.secrets`: Contains the AWS credentials
- `test-docs-aws-event.json`: Simulates a GitHub push event
- `test-docs-aws.sh`: Sets up environment variables and prints the command to run

## How to Use

1. Make sure the `test-docs-aws.sh` script is executable:
   ```
   chmod +x test-docs-aws.sh
   ```

2. Run the setup script:
   ```
   ./test-docs-aws.sh
   ```

3. Run the command provided by the script:
   ```
   act push -W .github/workflows/documentation.yml -j build-docs,publish-to-aws -s @test-docs-aws.secrets --eventpath test-docs-aws-event.json
   ```

## What This Tests

This setup will:
1. Build the documentation for PowerDNS products (Auth, Recursor, DNSdist)
2. Upload the built documentation to the test S3 bucket: `powerdns-docs-test`

## Security Note

The test setup uses real AWS credentials to upload to a test bucket. Make sure not to commit these credentials to a public repository. 