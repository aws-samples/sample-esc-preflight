# Test fixture: reduced subset in the shape of names/data/names_data.hcl.
# Real scans fetch the official file from the latest provider release.

service "cloudwatch" {
  sdk {
    id = "CloudWatch"
  }
  endpoint_info {
    endpoint_api_call = "ListDashboards"
  }
  resource_prefix {
    actual  = "aws_cloudwatch_(?!(event_|log_|query_))"
    correct = "aws_cloudwatch_"
  }
}

service "logs" {
  sdk {
    id = "CloudWatch Logs"
  }
  endpoint_info {
    endpoint_api_call = "ListAnomalies"
  }
  resource_prefix {
    actual  = "aws_cloudwatch_(log_|query_)"
    correct = "aws_logs_"
  }
}

service "codebuild" {
  sdk {
    id = "CodeBuild"
  }
  endpoint_info {
    endpoint_api_call = "ListBuildBatches"
  }
  resource_prefix {
    correct = "aws_codebuild_"
  }
}

service "codepipeline" {
  sdk {
    id = "CodePipeline"
  }
  endpoint_info {
    endpoint_api_call = "ListPipelines"
  }
  resource_prefix {
    correct = "aws_codepipeline"
  }
}

service "cognitoidentity" {
  sdk {
    id = "Cognito Identity"
  }
  endpoint_info {
    endpoint_api_call = "ListIdentityPools"
  }
  resource_prefix {
    actual  = "aws_cognito_identity_(?!provider)"
    correct = "aws_cognitoidentity_"
  }
}

service "cognitoidp" {
  sdk {
    id = "Cognito Identity Provider"
  }
  endpoint_info {
    endpoint_api_call = "ListUserPools"
  }
  resource_prefix {
    actual  = "aws_cognito_(identity_provider|log|managed_login_branding|managed_user|resource|risk|user)"
    correct = "aws_cognitoidp_"
  }
}

service "eks" {
  sdk {
    id = "EKS"
  }
  endpoint_info {
    endpoint_api_call = "ListClusters"
  }
  resource_prefix {
    correct = "aws_eks_"
  }
}

service "elasticache" {
  sdk {
    id = "ElastiCache"
  }
  endpoint_info {
    endpoint_api_call = "DescribeCacheClusters"
  }
  resource_prefix {
    correct = "aws_elasticache_"
  }
}

service "elbv2" {
  sdk {
    id = "Elastic Load Balancing v2"
  }
  endpoint_info {
    endpoint_api_call = "DescribeLoadBalancers"
  }
  resource_prefix {
    actual  = "aws_a?lb(\\b|_listener|_target_group|s|_trust_store)"
    correct = "aws_elbv2_"
  }
}

service "elb" {
  sdk {
    id = "Elastic Load Balancing"
  }
  endpoint_info {
    endpoint_api_call = "DescribeLoadBalancers"
  }
  resource_prefix {
    actual  = "aws_(app_cookie_stickiness_policy|elb|lb_cookie_stickiness_policy|lb_ssl_negotiation_policy|load_balancer_|proxy_protocol_policy)"
    correct = "aws_elb_"
  }
}

service "events" {
  sdk {
    id = "EventBridge"
  }
  endpoint_info {
    endpoint_api_call = "ListEventBuses"
  }
  resource_prefix {
    actual  = "aws_cloudwatch_event_"
    correct = "aws_events_"
  }
}

service "iam" {
  sdk {
    id = "IAM"
  }
  endpoint_info {
    endpoint_api_call = "ListRoles"
  }
  resource_prefix {
    correct = "aws_iam_"
  }
}

service "rds" {
  sdk {
    id = "RDS"
  }
  endpoint_info {
    endpoint_api_call = "DescribeDBInstances"
  }
  resource_prefix {
    actual  = "aws_(db_|rds_)"
    correct = "aws_rds_"
  }
}

service "route53" {
  sdk {
    id = "Route 53"
  }
  endpoint_info {
    endpoint_api_call = "ListHostedZones"
  }
  resource_prefix {
    actual  = "aws_route53_(?!resolver_)"
    correct = "aws_route53_"
  }
}

service "route53resolver" {
  sdk {
    id = "Route53Resolver"
  }
  endpoint_info {
    endpoint_api_call = "ListFirewallDomainLists"
  }
  resource_prefix {
    actual  = "aws_route53_resolver_"
    correct = "aws_route53resolver_"
  }
}

service "s3" {
  sdk {
    id = "S3"
  }
  endpoint_info {
    endpoint_api_call = "ListBuckets"
  }
  resource_prefix {
    actual  = "aws_(canonical_user_id|s3_bucket|s3_object|s3_directory_bucket)"
    correct = "aws_s3_"
  }
}

service "dynamodb" {
  sdk {
    id = "DynamoDB"
  }
  endpoint_info {
    endpoint_api_call = "ListTables"
  }
  resource_prefix {
    correct = "aws_dynamodb_"
  }
}

service "ec2" {
  sdk {
    id = "EC2"
  }
  endpoint_info {
    endpoint_api_call = "DescribeVpcs"
  }
  resource_prefix {
    actual  = "aws_(ami|availability_zone|ec2_(allowed_images_settings|availability|capacity|default_credit_specification|fleet|host|instance|public_ipv4_pool|secondary_network|secondary_subnet|serial|spot|tag)|eip|instance|key_pair|launch_template|placement_group|spot)"
    correct = "aws_ec2_"
  }
  resource_prefix {
    actual  = "aws_(ebs_|volume_attach|snapshot_create)"
    correct = "aws_ec2ebs_"
  }
  resource_prefix {
    actual  = "aws_ec2_(coip_pool|local_gateway)"
    correct = "aws_ec2outposts_"
  }
  resource_prefix {
    actual  = "aws_ec2_transit_gateway"
    correct = "aws_transitgateway_"
  }
  resource_prefix {
    actual  = "aws_verifiedaccess"
    correct = "aws_verifiedaccess_"
  }
  resource_prefix {
    actual  = "aws_((default_)?(network_acl|route_table|security_group|subnet|vpc(?!_ipam))|ec2_(managed|network|subnet|traffic)|egress_only_internet|flow_log|internet_gateway|main_route_table_association|nat_gateway|network_interface|prefix_list|route\\b)"
    correct = "aws_vpc_"
  }
  resource_prefix {
    actual  = "aws_vpc_ipam"
    correct = "aws_ipam_"
  }
  resource_prefix {
    actual  = "aws_ec2_client_vpn"
    correct = "aws_vpnclient_"
  }
  resource_prefix {
    actual  = "aws_(customer_gateway|vpn_)"
    correct = "aws_vpnsite_"
  }
  resource_prefix {
    actual  = "aws_ec2_carrier_gateway"
    correct = "aws_wavelength_"
  }
}

service "vpc" {
  sdk {
    id = ""
  }
  resource_prefix {
    correct = "aws_vpc_"
  }
}
