# Sitecore Experience Manager (XM) on AWS — Quick Start

For architectural details, step-by-step instructions, and customization options, see the [deployment guide](https://fwd.aws/n9N4D?).

To post feedback, submit feature ideas, or report bugs, use the Issues section of this GitHub repo.

It deploys 3 roles that compose the complete Sitecore XM platform. All of the roles are deployed into individual Auto Scaling groups to ensure recoverability when an instance fails. Database services are provided by SQL Server through Amazon Relational Database Service (Amazon RDS), and caching is managed by Redis on Amazon ElastiCache.

To control access, this deployment uses AWS Certificate Manager (ACM) and AWS Secrets Manager. Other services used by this Quick Start include Amazon Simple Storage Service (Amazon S3), AWS Systems Manager, Amazon CloudWatch, AWS Lambda, and Amazon Route 53.

You can use the AWS CloudFormation templates included with the Quick Start to deploy Sitecore XM in your AWS account in about 1–1.5 hours. For more information and step-by-step deployment instructions, see [the guide](https://fwd.aws/yW5pE).

This Quick Start provides two deployment options:

- Deploy Sitecore XM into a new VPC (end-to-end deployment). This option builds a new AWS environment consisting of the VPC, subnets, NAT gateways, security groups, bastion hosts, and other infrastructure components. It then deploys Sitecore XM into this new VPC.
- Deploy Sitecore XM into an existing VPC. This option provisions Sitecore XM in your existing AWS infrastructure.
The Quick Start provides separate templates for these options. It also lets you configure Classless Inter-Domain Routing (CIDR) blocks, instance types, and Sitecore XM settings, as discussed later in this guide.

The following diagram shows the architecture for Sitecore XM.

![Quick Start architecture for Sitecore XM](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/sitecore-xp-93-architecture-diagram.png)

For architectural details, best practices, step-by-step instructions, and customization options, see the [deployment guide](https://fwd.aws/yW5pE).

To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo. If you'd like to submit code for this Quick Start, please review the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/). 