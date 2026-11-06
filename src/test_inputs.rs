//! Small test inputs, kept inline so they need no files.

pub const GUIDE_GENERIC: &str = r#"<html><body><h2 id="how_differs">How the service differs</h2>
<ul><li><p>HTTP API is not available.</p></li><li><p>Global Tables and Cross-Region Restore.</p></li><li><p>S3 Express One Zone is not available.</p></li><li><p>EKS support for Fargate is not available.</p></li><li><p>Multi-Region secrets are not available.</p></li></ul>
<h2 id="_documentation">Documentation</h2></body></html>"#;

pub const GUIDE_LAMBDA: &str = r#"<html><body><h1>Service in the Region</h1><p>Intro.</p>
<h2 id="how_differs">How the service differs</h2>
<p>The following differences apply:</p>
<div class="itemizedlist"><ul class="itemizedlist"><li class="listitem"><p>Function URLs is not available.</p></li><li class="listitem"><p>The following event sources are not available:</p><div><ul><li><p>Apache Kafka</p></li><li><p>Amazon <code>MQ</code></p></li></ul></div></li></ul></div>
<h2 id="_documentation">Documentation</h2><ul><li><p><a href="x">Documentation</a></p></li></ul>
</body></html>"#;

pub const GUIDE_RDS: &str = r#"<html><body><h2 id="how_differs">How the service differs</h2>
<ul><li><p>Cross Region Read Replicas are not available.</p></li></ul>
<h3 id="aurora">Features not available for Aurora PostgreSQL</h3>
<ul><li><p>Global Databases</p></li><li><p>Optimized Reads</p></li></ul>
<h2 id="_documentation">Documentation</h2></body></html>"#;

pub const GUIDE_TOC: &str = r#"{
 "contents": [
  {
   "title": "Introduction",
   "href": "introduction.html"
  },
  {
   "title": "Endpoints",
   "href": "endpoints.html"
  },
  {
   "title": "Services",
   "href": "services.html",
   "contents": [
    {
     "title": "AWS Lambda",
     "href": "lambda.html"
    },
    {
     "title": "Amazon API Gateway",
     "href": "apigateway.html"
    },
    {
     "title": "Amazon Cognito",
     "href": "cognito.html"
    },
    {
     "title": "AWS CodePipeline",
     "href": "codepipeline.html"
    },
    {
     "title": "AWS CDK",
     "href": "cdk.html"
    },
    {
     "title": "Amazon DocumentDB",
     "href": "documentdb.html"
    },
    {
     "title": "Amazon RDS",
     "href": "rds.html"
    },
    {
     "title": "Amazon DynamoDB",
     "href": "dynamodb.html"
    },
    {
     "title": "Amazon S3",
     "href": "s3.html"
    },
    {
     "title": "AWS Identity and Access Management",
     "href": "iam.html"
    },
    {
     "title": "Amazon EC2",
     "href": "ec2.html"
    },
    {
     "title": "Amazon VPC",
     "href": "vpc.html"
    },
    {
     "title": "Amazon EKS",
     "href": "eks.html"
    },
    {
     "title": "Amazon ECS",
     "href": "ecs.html"
    },
    {
     "title": "AWS KMS",
     "href": "kms.html"
    },
    {
     "title": "AWS Secrets Manager",
     "href": "secretsmanager.html"
    }
   ]
  }
 ]
}"#;

pub const BOTOCORE_VERSION: &str = r#"1.43.120"#;

pub const TF_PROVIDER_VERSIONS: &str = r#"6.71.0
1.108.0"#;

pub const TF_AWSCC_SCHEMAS: &str = r#"# Test fixture: reduced subset in the shape of internal/provider/all_schemas.hcl.
# Real scans fetch the official file from the latest provider release.

resource_schema "aws_s3_bucket" {
  cloudformation_type_name = "AWS::S3::Bucket"
  path_aware_attribute_names = true
}

resource_schema "aws_lambda_function" {
  cloudformation_type_name = "AWS::Lambda::Function"
}"#;

pub const SAMPLE_TEMPLATE: &str = r#"{
  "Resources": {
    "CDKMetadata": { "Type": "AWS::CDK::Metadata", "Properties": { "Analytics": "v2:deflate64:abc" } },
    "AutoDelete": { "Type": "Custom::S3AutoDeleteObjects", "Properties": { "ServiceToken": { "Fn::GetAtt": ["Provider", "Arn"] } } },
    "Bucket": { "Type": "AWS::S3::Bucket" },
    "FnRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": { "Statement": [{ "Action": "sts:AssumeRole", "Effect": "Allow", "Principal": { "Service": "lambda.amazonaws.com" } }] },
        "ManagedPolicyArns": [
          { "Fn::Join": ["", ["arn:", { "Ref": "AWS::Partition" }, ":iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]] },
          "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        ]
      }
    },
    "Fn": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Role": { "Fn::GetAtt": ["FnRole", "Arn"] },
        "Environment": { "Variables": { "QUEUE_URL": "https://sqs.eu-central-1.amazonaws.com/111122223333/jobs" } }
      }
    },
    "Cdn": { "Type": "AWS::CloudFront::Distribution", "Properties": { "DistributionConfig": { "Enabled": true } } },
    "Build": { "Type": "AWS::CodeBuild::Project" },
    "Assistant": { "Type": "AWS::QBusiness::Application" },
    "Subnet": { "Type": "AWS::EC2::Subnet", "Properties": { "AvailabilityZone": "eu-central-1a" } }
  }
}"#;

pub const CUSTOM_RESOURCES_TEMPLATE: &str = r#"{
 "Resources": {
  "DescribeClient": {
   "Type": "Custom::DescribeUserPoolClient",
   "Properties": {
    "ServiceToken": {"Fn::GetAtt": ["AWS679f53fac002430cb0da5b7982bd22872D164C4C", "Arn"]},
    "Create": {
     "Fn::Join": ["", [
      "{\"region\":\"",
      {"Ref": "AWS::Region"},
      "\",\"service\":\"CognitoIdentityServiceProvider\",\"action\":\"describeUserPoolClient\",\"parameters\":{\"UserPoolId\":\"",
      {"Ref": "UserPool"},
      "\"},\"physicalResourceId\":{\"id\":\"client\"}}"
     ]]
    },
    "InstallLatestAwsSdk": false
   }
  },
  "CreateInvalidation": {
   "Type": "Custom::AWS",
   "Properties": {
    "ServiceToken": {"Fn::GetAtt": ["AWS679f53fac002430cb0da5b7982bd22872D164C4C", "Arn"]},
    "Create": "{\"service\":\"@aws-sdk/client-cloudfront\",\"action\":\"CreateInvalidation\",\"parameters\":{\"DistributionId\":\"E123\"},\"physicalResourceId\":{\"id\":\"inv\"}}"
   }
  },
  "PortalRegistration": {
   "Type": "Custom::PortalRegistration",
   "Properties": {
    "ServiceToken": {"Fn::GetAtt": ["RegistrationFunction", "Arn"]},
    "Name": "example"
   }
  }
 }
}"#;
