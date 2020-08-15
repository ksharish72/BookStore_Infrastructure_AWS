variable "region" {
  type    = string
}

# Configure the AWS Provider
provider "aws" {
  region  = var.region
}

variable "cidr_block" {
  type    = list(string)
}
variable "lambda_execution_role_arn" {
  type        = string
}
variable "cicdUserName" {
  type        = string
}

variable "codeDeploymentGroup" {
  type        = string
}
variable "codeDeploymentGroupUI" {
  type        = string
}
variable "enable_dns_support" {
  type        = bool
}
variable "enable_dns_hostnames" {
  type        = bool
}
variable "cloudwatch_service_arn" {
  type        = string
}
variable "codeDeployAccountId" {
  type        = string
}
variable "codeDeployApplicationName" {
  type        = string
}
variable "enable_classiclink_dns_support" {
  type        = bool 
}
variable "assign_generated_ipv6_cidr_block" {
  type        = bool
}
variable "tagname" {
  type    = list(string)
}
variable "code_deploy_service_arn" {
  type    = string
}
variable "availability_zone_names" {
  type    = list(string)
}
variable "map_public_ip_on_launch" {
  type    = string
}
variable "db_subnet_group_name" {
  type    = string
}
variable "zoneid"{
  type    = string
}
variable "zonename"{
  type    = string
}
variable "ingressDatabase" {
   type = object({
    type = string
    from_port = number
    to_port = number
    protocol = string
  })
}
variable "aws_db_instance" {
   type = object({
      allocated_storage    = number
      storage_type         = string
      engine               = string
      engine_version       = string
      instance_class       = string
      multi_az             = bool
      identifier           = string
      name                 = string
      username             = string
      password             = string
      publicly_accessible  = bool
      parameter_group_name = string
      final_snapshot_identifier = string
  })
}

variable "aws_dynamodb_table" {
type = object({
   name           = string
  hash_key       = string
  write_capacity = number
  read_capacity = number
  attribute_name_1 = string
  attribute_type_1 = string
  tag_environment = string
})
}

variable "aws_instance" {
  type=object({
  ami           = string
  key_name      = string
  instance_type = string
  disable_api_termination = bool
  root_block_device_volume_type = string
  root_block_device_volume_size = number
  })
}

variable "aws_s3_bucket" {
  type = object({
      bucket = string
      acl    = string
      deploy_bucket = string
      tag_environment = string
      force_destroy = bool
      lifecycle_rule_enabled = bool
      transition_days = number
      transition_storage_class = string
  })
}

variable "aws_kms_key" {
  type = object({
    description        = string
    deletion_window_in_days = number
  })
}
resource "aws_security_group_rule" "ingressDatabase" {
  type = var.ingressDatabase["type"]
  from_port = var.ingressDatabase["from_port"]
  to_port = var.ingressDatabase["to_port"]
  protocol = var.ingressDatabase["protocol"]
  security_group_id = "${aws_security_group.database.id}"
  source_security_group_id = "${aws_security_group.application.id}"
}

# resource "aws_security_group_rule" "ingressDatabase" {
#   type = var.ingressDatabase["type"]
#   from_port = var.ingressDatabase["from_port"]
#   to_port = var.ingressDatabase["to_port"]
#   protocol = var.ingressDatabase["protocol"]
#   security_group_id = "${aws_security_group.database.id}"
#   source_security_group_id = "${aws_security_group.application.id}"
# }
# Create a database subnet group
resource "aws_db_subnet_group" "default" {
  name       = var.db_subnet_group_name
  subnet_ids = ["${aws_subnet.csye6225_a4_subnet_1.id}", "${aws_subnet.csye6225_a4_subnet_2.id}","${aws_subnet.csye6225_a4_subnet_3.id}"]

  tags = {
    Name = var.tagname[5] 
  }
}

# create a rds instance
resource "aws_db_instance" "csye6225-su2020" {
  storage_encrypted    = true
  allocated_storage    = var.aws_db_instance["allocated_storage"]
  storage_type         = var.aws_db_instance["storage_type"]
  engine               = var.aws_db_instance["engine"]
  engine_version       = var.aws_db_instance["engine_version"]
  instance_class       = var.aws_db_instance["instance_class"]
  multi_az             = var.aws_db_instance["multi_az"]
  identifier           = var.aws_db_instance["identifier"]
  name                 = var.aws_db_instance["name"]
  username             = var.aws_db_instance["username"]
  password             = var.aws_db_instance["password"]
  publicly_accessible  = var.aws_db_instance["publicly_accessible"]
  parameter_group_name ="${aws_db_parameter_group.default.name}" 
  db_subnet_group_name = "${aws_db_subnet_group.default.id}"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  final_snapshot_identifier = var.aws_db_instance["final_snapshot_identifier"]
  skip_final_snapshot = true
}
# create a dynamo db table
resource "aws_dynamodb_table" "csye6225_a5_dynamodb-table" {
  name           = var.aws_dynamodb_table["name"]
  hash_key       = var.aws_dynamodb_table["hash_key"]
  write_capacity = var.aws_dynamodb_table["write_capacity"]
  read_capacity = var.aws_dynamodb_table["read_capacity"]
  attribute {
    name = var.aws_dynamodb_table["attribute_name_1"]
    type = var.aws_dynamodb_table["attribute_type_1"]
  }

  tags = {
    Name        = var.tagname[6]
    Environment = var.aws_dynamodb_table["tag_environment"]
  }
}
# Create a EC2 instance
# resource "aws_instance" "web_app" {
#   ami           = var.aws_instance["ami"]
#   key_name      = var.aws_instance["key_name"]
#   instance_type = var.aws_instance["instance_type"]
#   iam_instance_profile = "${aws_iam_instance_profile.test_profile.name}"
#   vpc_security_group_ids = ["${aws_security_group.application.id}"]
#   subnet_id = "${aws_subnet.csye6225_a4_subnet_1.id}"  
#   disable_api_termination = var.aws_instance["disable_api_termination"]
#   user_data = "${data.template_file.init.rendered}"
#   root_block_device  {
#     volume_type = var.aws_instance["root_block_device_volume_type"]
#     volume_size = var.aws_instance["root_block_device_volume_size"]
#   }

#   tags = {
#     Name = var.tagname[7]
#   }
# }
data "template_file" "init" {
  template = "${file("./userdata.sh")}"
  vars = {
    rds_address = "${aws_db_instance.csye6225-su2020.address}"
  }
}
#Create a ec2 key pair
resource "aws_key_pair" "dev" {
  key_name   = "aws_ec2"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1AJxbKh06EegGVBwBtUz5Wu0kKWxscaPz/G6wtiLqgWV5gA1OjZphlTfWU68ldB3X/k7DaZ2J272T27YJZ2A3ifKn1m12MSx8AKRAvz4DDsjGa8jKadsrRpS7Ks2TVf5q1EEaNOlrddBnAh1M0mDz3eHZLvlvML1exi52ntmLDkJW2gbym0stLeigumdFimSOJJZbRkBpJp1ACC3mfmmxSAMaQF7XQSSQ8fpQOh8ZQ1wdv4Lq3AeWmYu7qQUJiYKJ2hTotNhLoJBSeuwG1GRtL+x+w7QK86yX5pOXf0XT9jO4ylhXsb6lik9zKqPu8V0ls10DCjzUpIoUFkLTjocn harish@harish-Inspiron-7386"
}

# Create a database security group
resource "aws_security_group" "database" {
  name        = "database"
  description = "Database"
  vpc_id      = "${aws_vpc.csye6225_a4.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = var.tagname[8]
  }
}
# Create a application security group
resource "aws_security_group" "webapp_security" {
  name        = "webapp-security"
  description = "Web application"
  vpc_id      = "${aws_vpc.csye6225_a4.id}"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "webapp-security"
  }
}
# Create a application security group
resource "aws_security_group" "application" {
  name        = "application"
  description = "Web application"
  vpc_id      = "${aws_vpc.csye6225_a4.id}"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.webapp_security.id]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.webapp_security.id]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    security_groups = [aws_security_group.webapp_security.id]
  }
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = [aws_security_group.webapp_security.id]
  }
  

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application"
  }
}
# Create a VPC
resource "aws_vpc" "csye6225_a4" {
  cidr_block = var.cidr_block[0]
  enable_dns_support = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_classiclink_dns_support = var.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = var.assign_generated_ipv6_cidr_block
  tags = {
      Name = var.tagname[0]
  }
}

# create a iam policy webapps3
resource "aws_iam_policy" "web_app_s3" {
  name        = "WebAppS3"
  description = "Web application s3 policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
            "s3:DeleteObject",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:PutObject",
            "s3:PutObjectAcl",
            "SNS:Publish"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.aws_s3_bucket["bucket"]}",
                "arn:aws:s3:::${var.aws_s3_bucket["bucket"]}/*",
                "arn:aws:sns:us-east-1:${var.codeDeployAccountId}:forgotPassword"
            ]
        }
    ]
}
EOF
}
# create a iam policy webapps3
resource "aws_iam_policy" "dynamodb_lambda_policy" {
  name        = "dynamodb_lambda_policy"
  description = "Dynamo DB lambda policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement":[
    {
      "Sid":"Stmt1428510662000",
      "Effect":"Allow",
      "Action":[
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:PutItem",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:UpdateItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:BatchGetItem",
        "dynamodb:DescribeTable",
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource":["arn:aws:dynamodb:us-east-1:123456789012:table/snslambda","*"]
    }
  ]
}
EOF
}

# create a iam policy code deploy ec2
#what is resources here
resource "aws_iam_policy" "code_deploy_ec2_s3" {
  name        = "CodeDeploy-EC2-S3"
  description = "Code Deploy EC2-s3 policy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.aws_s3_bucket["deploy_bucket"]}",
                "arn:aws:s3:::${var.aws_s3_bucket["deploy_bucket"]}/*"
              ]
        }
    ]
}


EOF
}

# create a iam policy circle ci uplaod to s3
resource "aws_iam_policy" "circleci_upload_s3" {
  name        = "CircleCI-Upload-To-S3"
  description = "Circle CI upload to S3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":"AddCannedAcl",
            "Effect": "Allow",
            "Action":["s3:PutObject","s3:PutObjectAcl","s3:ListBucket","s3:GetObject"],
            "Resource": [
                "arn:aws:s3:::${var.aws_s3_bucket["deploy_bucket"]}",
                "arn:aws:s3:::${var.aws_s3_bucket["deploy_bucket"]}/*"
              ]
        }
    ]
}
EOF
}


# create a iam policy circle ci to call code deploy
resource "aws_iam_policy" "CircleCI-Code-Deploy" {
  name        = "CircleCI-Code-Deploy"
  description = "Circle CI Code Deploy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision",
        "codedeploy:GetApplication"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.codeDeployAccountId}:application:${var.codeDeployApplicationName}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment",
        "codedeploy:GetDeploymentGroup",
        "codedeploy:CreateDeploymentGroup"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.codeDeployAccountId}:deploymentgroup:${var.codeDeploymentGroup}",
        "arn:aws:codedeploy:${var.region}:${var.codeDeployAccountId}:deploymentgroup:${var.codeDeploymentGroupUI}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.codeDeployAccountId}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${var.codeDeployAccountId}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${var.codeDeployAccountId}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

# create a iam policy circle ci building ami
resource "aws_iam_policy" "circleci_ec2_ami" {
  name        = "circleci-ec2-ami"
  description = "Circle CI building AMI"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}


#create iam role CodeDeployEC2Service
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

}

#create iam role CodeDeployServiceRole
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

}
#create iam role
resource "aws_iam_role" "EC2-CSYE6225" {
  name = "EC2-CSYE6225"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "EC2-CSYE6225"
  }
}

# create a cicd iam access key
resource "aws_iam_access_key" "cicd_access_key" {
  user    = "${aws_iam_user.cicd.name}"
}

output "aws_secret" {
  value = aws_iam_access_key.cicd_access_key.secret
}
# create a cicd iam user
resource "aws_iam_user" "cicd" {
  name = "cicd"
}


# create a s3 bucket 
resource "aws_s3_bucket" "csye6225_a5_s3_bucket" {
  bucket = var.aws_s3_bucket["bucket"]
  acl    = var.aws_s3_bucket["acl"]
  lifecycle_rule {
    enabled = var.aws_s3_bucket["lifecycle_rule_enabled"]
    transition {
      days          = var.aws_s3_bucket["transition_days"]
      storage_class = var.aws_s3_bucket["transition_storage_class"]
    }
  }
  force_destroy = var.aws_s3_bucket["force_destroy"]
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # kms_master_key_id = "${aws_kms_key.csye6225_a5_mykey.arn}"
        sse_algorithm     = "AES256"
      }
    }
  }
  tags = {
    Name        = var.tagname[9]
    Environment = var.aws_s3_bucket["tag_environment"]
  }
}

# create a s3 bucket for code deploy 
resource "aws_s3_bucket" "code_deploy" {
  bucket = var.aws_s3_bucket["deploy_bucket"]
  acl    = var.aws_s3_bucket["acl"]
  lifecycle_rule {
    enabled = var.aws_s3_bucket["lifecycle_rule_enabled"]
    transition {
      days          = var.aws_s3_bucket["transition_days"]
      storage_class = var.aws_s3_bucket["transition_storage_class"]
    }
  }
  force_destroy = var.aws_s3_bucket["force_destroy"]
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # kms_master_key_id = "${aws_kms_key.csye6225_a5_mykey.arn}"
        sse_algorithm     = "AES256"
      }
    }
  }
}



#default key encryption
# resource "aws_kms_key" "csye6225_a5_mykey" {
#   description             = var.aws_kms_key["description"]
#   deletion_window_in_days = var.aws_kms_key["deletion_window_in_days"]
# }
# iam policy attachment
resource "aws_iam_policy_attachment" "cloudwatch_attach" {
  name       = "cloudwatch_attachment"
  roles      = ["${aws_iam_role.CodeDeployEC2ServiceRole.name}"]
  policy_arn = var.cloudwatch_service_arn
}
# iam policy attachment
resource "aws_iam_policy_attachment" "code_deploy_ec2_s3" {
  name       = "code_deploy_ec2_s3_attachment"
  roles      = ["${aws_iam_role.CodeDeployEC2ServiceRole.name}"]
  policy_arn = "${aws_iam_policy.code_deploy_ec2_s3.arn}"
  #doubt here why are we not giving the policy name
}

resource "aws_iam_policy_attachment" "dynamodb_lambda" {
  name       = "dynamodb_lamda"
  roles      = ["${aws_iam_role.iam_for_lambda.name}"]
  policy_arn = "${aws_iam_policy.dynamodb_lambda_policy.arn}"
  #doubt here why are we not giving the policy name
}
resource "aws_iam_policy_attachment" "lambda_logs" {
  name       = "lambda_logs"
  roles      = ["${aws_iam_role.iam_for_lambda.name}"]
  policy_arn = var.lambda_execution_role_arn
  #doubt here why are we not giving the policy name
}
# iam policy attachment
#what is this for?
resource "aws_iam_policy_attachment" "webapp_s3_attach" {
  name       = "webapp_s3_attachment"
  roles      = ["${aws_iam_role.CodeDeployEC2ServiceRole.name}"]
  policy_arn = "${aws_iam_policy.web_app_s3.arn}"
}
# arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

# iam policy attachment
#what is this for?
resource "aws_iam_policy_attachment" "code_deploy_service" {
  name       = "code_deploy_service"
  roles      = ["${aws_iam_role.CodeDeployServiceRole.name}"]
  policy_arn = var.code_deploy_service_arn
}
# iam policy attachment
resource "aws_iam_user_policy_attachment" "circleci_upload_s3-attach" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci_upload_s3.arn}"
}
resource "aws_iam_user_policy_attachment" "circleci_codedeploy_attachment" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.CircleCI-Code-Deploy.arn}"
}

# iam policy attachment
resource "aws_iam_user_policy_attachment" "circleci_ec2_ami-attach" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci_ec2_ami.arn}"
}
# create a iam instance profile
#what is this for?
resource "aws_iam_instance_profile" "test_profile" {
  name = "test_profile"
  role = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}
# create a subnet
resource "aws_subnet" "csye6225_a4_subnet_1" {
  cidr_block = var.cidr_block[1]
  vpc_id = "${aws_vpc.csye6225_a4.id}"
  availability_zone = var.availability_zone_names[0]
  map_public_ip_on_launch = var.map_public_ip_on_launch
  tags = {
    Name = var.tagname[1]
  }
}

# create a subnet
resource "aws_subnet" "csye6225_a4_subnet_2" {
  cidr_block = var.cidr_block[2]
  vpc_id = "${aws_vpc.csye6225_a4.id}"
  availability_zone = var.availability_zone_names[1]
  map_public_ip_on_launch = var.map_public_ip_on_launch
  tags = {
    Name = var.tagname[2]
  }
}

# create a subnet
resource "aws_subnet" "csye6225_a4_subnet_3" {
  cidr_block = var.cidr_block[3]
  vpc_id = "${aws_vpc.csye6225_a4.id}"
  availability_zone = var.availability_zone_names[2]
  map_public_ip_on_launch = var.map_public_ip_on_launch
  tags = {
    Name = var.tagname[3]
  }
}


resource "aws_internet_gateway" "csye6225_a4_internet_gateway" {
  vpc_id = "${aws_vpc.csye6225_a4.id}"

  tags = {
    Name = var.tagname[4]
  }
}
# create a code deploy
resource "aws_codedeploy_app" "csye6225-webapp" {
  name = "csye6225-webapp"
}
# create a code deployment group
resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  autoscaling_groups    = ["${aws_autoscaling_group.webappasg.name}"]
  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "Web application"
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}
# create sns topic
resource "aws_sns_topic" "forgotPassword_SNS" {
  name = "forgotPassword"
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.test_lambda.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.forgotPassword_SNS.arn}"
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = "${aws_sns_topic.forgotPassword_SNS.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.test_lambda.arn}"
}
resource "aws_lambda_function" "test_lambda" {
  filename      = "forgotPassword_function_payload.zip"
  function_name = "forgotPassword"
  role          = "${aws_iam_role.iam_for_lambda.arn}"
  handler       = "index.handler"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = "${filebase64sha256("forgotPassword_function_payload.zip")}"

  runtime = "nodejs12.x"

}

# create a code deployment group
resource "aws_codedeploy_deployment_group" "csye6225-webapp-ui-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-ui-deployment"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  autoscaling_groups    = ["${aws_autoscaling_group.webappasg.name}"]
  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "Web application"
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}
resource "aws_launch_configuration" "asg_launch_config" {
  name_prefix   = "asg_launch_config"
  image_id      = var.aws_instance["ami"]
  key_name      = var.aws_instance["key_name"]
  associate_public_ip_address   = true
  user_data     = "${data.template_file.init.rendered}"
  instance_type = "t2.micro"
  iam_instance_profile = "${aws_iam_instance_profile.test_profile.name}"
  security_groups = ["${aws_security_group.application.id}"]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "webappasg" {
  name                 = "webappasg"
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  min_size             = 2
  max_size             = 5
  vpc_zone_identifier   = ["${aws_subnet.csye6225_a4_subnet_1.id}", "${aws_subnet.csye6225_a4_subnet_2.id}","${aws_subnet.csye6225_a4_subnet_3.id}"]
  health_check_grace_period = 300
  health_check_type         = "EC2"
  desired_capacity          = 2
  default_cooldown          = 60
  force_delete         = true
  target_group_arns    =  ["${aws_lb_target_group.webapplb_target_group.id}","${aws_lb_target_group.serverlb_target_group.id}"]
  lifecycle {
    create_before_destroy = true
  }
  tag {
    key                 = "Name"
    value               = "Web Application"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "scaleup_policy" {
  name                   = "webapp_scaleup_policy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.webappasg.name}"
  policy_type            = "TargetTrackingScaling"
  estimated_instance_warmup = 60
  target_tracking_configuration {
    predefined_metric_specification {
        predefined_metric_type = "ASGAverageCPUUtilization"
    }
  target_value = 5
  }
}
resource "aws_autoscaling_policy" "scaledown_policy" {
  name                   = "webapp_scaledown_policy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.webappasg.name}"
  policy_type            = "TargetTrackingScaling"
  estimated_instance_warmup = 60
  target_tracking_configuration {
    predefined_metric_specification {
        predefined_metric_type = "ASGAverageCPUUtilization"
    }
  target_value = 3
  }
}

resource "aws_lb" "front_end" {
  name               = "webapp-lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.webapp_security.id}"]
  subnets            = ["${aws_subnet.csye6225_a4_subnet_1.id}", "${aws_subnet.csye6225_a4_subnet_2.id}","${aws_subnet.csye6225_a4_subnet_3.id}"]

  # enable_deletion_protection = true

  # access_logs {
  #   bucket  = "${aws_s3_bucket.lb_logs.bucket}"
  #   prefix  = "test-lb"
  #   enabled = true
  # }

  tags = {
    Environment = "dev"
  }
}
resource "aws_route53_record" "record_set" {
  zone_id = var.zoneid
  name    = var.zonename
  type    = "A"

  alias {
    name                   = "${aws_lb.front_end.dns_name}"
    zone_id                = "${aws_lb.front_end.zone_id}"
    evaluate_target_health = false
  }
}
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.front_end.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:708663795942:certificate/d3ea4b20-1eb1-4f66-8aa4-983bda3c4983"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.webapplb_target_group.arn}"
  }
}
resource "aws_lb_listener" "server" {
  load_balancer_arn = "${aws_lb.front_end.arn}"
  port              = "3000"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:708663795942:certificate/d3ea4b20-1eb1-4f66-8aa4-983bda3c4983"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.serverlb_target_group.arn}"
  }
}
resource "aws_lb_target_group" "webapplb_target_group" {
  name     = "webapplb-target-group"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.csye6225_a4.id}"
}

resource "aws_lb_target_group" "serverlb_target_group" {
  name     = "serverlb-target-group"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.csye6225_a4.id}"
}
# create a route table
resource "aws_route_table" "csye6225_a4_route_table" {
  vpc_id = "${aws_vpc.csye6225_a4.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.csye6225_a4_internet_gateway.id}"
  }

  tags = {
    Name = "csye6225_a4_route_table"
  }
}

# create a route table association
resource "aws_route_table_association" "csye6225_a4_route_table_associate_1" {
  subnet_id      = aws_subnet.csye6225_a4_subnet_1.id
  route_table_id = aws_route_table.csye6225_a4_route_table.id
}
resource "aws_route_table_association" "csye6225_a4_route_table_associate_2" {
  subnet_id      = aws_subnet.csye6225_a4_subnet_2.id
  route_table_id = aws_route_table.csye6225_a4_route_table.id
}
resource "aws_route_table_association" "csye6225_a4_route_table_associate_3" {
  subnet_id      = aws_subnet.csye6225_a4_subnet_3.id
  route_table_id = aws_route_table.csye6225_a4_route_table.id
}


resource "aws_db_parameter_group" "default" {
    name = "rds-pg"
    family = "mysql5.7"
    description = "RDS csye6225"

    parameter {
        name = "performance_schema"
        value = "1"
        apply_method = "pending-reboot"
    }
}