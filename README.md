# AWS VPC

Creates a VPC for AWS (well duh). Balanced uses this for structuring our infrastructure on AWS.

## Features

### Subnets

* OLTP - Serves online requests for your business. We use this to prioritise high priority traffic. Anything that lives in here is important and essential to life and death.
* Offline - Workers and other services which are not critical to serving requests
* Infra - Databases and other services which are not custom applications.
* DMZ - Anything that handles traffic directly from the Internet. Mostly we use this for ELBs and use the ELB to route traffic to anything internally. Instances that live in this subnet also have direct external access to the internet rather than being routed via NATs.

## How to launch

1. Generate:

      python vpc.py > vpc.json

2. Upload:

      aws s3 cp vpc.json s3://some-bucket/

3. Create:

      AWS_DEFAULT_REGION=us-west-2 aws cloudformation create-stack --template-url https://s3-us-west-1.amazonaws.com/some-bucket/vpc.json --stack-name my-sexy-vpc --parameters ParameterKey=KeyName,ParameterValue=your-key-name

