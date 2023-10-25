provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "vpc_1" {
  cidr_block = var.vpc_cidr[0]
  tags = {
    Name = "vpc_1"
  }
}


resource "aws_subnet" "public_subnets_1" {
  count                   = length(data.aws_availability_zones.available.names) > 2 ? 3 : 2
  cidr_block              = "${var.subnet_prefix_1}.${count.index + 1}.${var.subnet_suffix}"
  vpc_id                  = aws_vpc.vpc_1.id
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Type = var.public_tag
    Name = "${var.public_subnet_name}_${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnets_1" {
  count             = length(data.aws_availability_zones.available.names) > 2 ? 3 : 2
  cidr_block        = "${var.subnet_prefix_1}.${count.index + 4}.${var.subnet_suffix}"
  vpc_id            = aws_vpc.vpc_1.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Type = var.private_tag
    Name = "${var.private_subnet_name}_${count.index + 1}"
  }
}


resource "aws_internet_gateway" "internet_gateway_1" {
  vpc_id = aws_vpc.vpc_1.id
  tags = {
    Name = "internet_gateway_1"
  }
}


resource "aws_route_table" "public_route_table_1" {
  vpc_id = aws_vpc.vpc_1.id
  route {
    cidr_block = var.public_route_table_cidr
    gateway_id = aws_internet_gateway.internet_gateway_1.id
  }
  tags = {
    Name = "${var.public_tag}_routetable_1"
  }
}


resource "aws_route_table" "private_route_table_1" {
  vpc_id = aws_vpc.vpc_1.id
  tags = {
    Name = "${var.private_tag}_routetable_1"
  }
}


resource "aws_route_table_association" "public_subnets_association_1" {
  count          = length(aws_subnet.public_subnets_1.*.id)
  subnet_id      = aws_subnet.public_subnets_1[count.index].id
  route_table_id = aws_route_table.public_route_table_1.id
}


resource "aws_route_table_association" "private_subnets_association_1" {
  count          = length(aws_subnet.private_subnets_1.*.id)
  subnet_id      = aws_subnet.private_subnets_1[count.index].id
  route_table_id = aws_route_table.private_route_table_1.id
}


# Security group for load_balancer
resource "aws_security_group" "load_balancer_security_group" {
  name_prefix = "load_balancer_sg_"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  vpc_id = aws_vpc.vpc_1.id
}

resource "aws_security_group" "application" {
  name_prefix = "my-application-sg-"

  # ingress {
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = var.app_port
  #   to_port     = var.app_port
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  vpc_id = aws_vpc.vpc_1.id
}

resource "aws_security_group_rule" "application_ssh_ingress" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.load_balancer_security_group.id
}
resource "aws_security_group_rule" "application_web_ingress" {
  type                     = "ingress"
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.load_balancer_security_group.id
}

resource "aws_launch_template" "EC2-CSYE6225" {
  name          = "EC2-CSYE6225"
  image_id      = var.aws_ami
  instance_type = "t2.micro"

  key_name = aws_key_pair.ec2keypair.key_name
  # vpc_security_group_ids  = [aws_security_group.application.id]
  disable_api_termination = false
  ebs_optimized           = false
  # associate_public_ip_address = true

  network_interfaces {
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.public_subnets_1[0].id
    security_groups             = [aws_security_group.application.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.s3_access_instance_profile.name
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs_custom_key.arn
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "EC2 Instance"
    }
  }

  user_data = base64encode(<<EOF
    #!/bin/bash
    echo "[Unit]
    Description=Webapp Service
    After=network.target

    [Service]
    Environment="DB_HOST=${element(split(":", aws_db_instance.rds_instance.endpoint), 0)}"
    Environment="DB_USER=${aws_db_instance.rds_instance.username}"
    Environment="DB_PASSWORD=${aws_db_instance.rds_instance.password}"
    Environment="DB_DATABASE=${aws_db_instance.rds_instance.db_name}"
    Environment="AWS_BUCKET_NAME=${aws_s3_bucket.webapp1bucket.bucket}"
    Environment="AWS_REGION=${var.aws_region}"
    Type=simple
    User=ec2-user
    WorkingDirectory=/home/ec2-user/webapp
    ExecStart=/usr/bin/node server.js
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/webapp.service
    sudo systemctl daemon-reload
    sudo systemctl restart webapp.service
    sudo systemctl enable webapp.service
    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json
EOF
  )

}

#Created a Auto scaling group 

resource "aws_autoscaling_group" "webapp_autoscaling_group" {
  name             = "webapp_autoscaling_group"
  max_size         = 3
  min_size         = 1
  desired_capacity = 1
  # launch_configuration = aws_launch_template.EC2-CSYE6225.name
  launch_template {
    id      = aws_launch_template.EC2-CSYE6225.id
    version = "$Latest"
  }
  vpc_zone_identifier = [aws_subnet.public_subnets_1[0].id]
  target_group_arns   = [aws_lb_target_group.load_balancer_target_group.arn]

  # Wait 5 minutes before starting new instances after a scaling event
  default_cooldown = 60

  # Tags for the instances created by the ASG
  tag {
    key                 = "Name"
    value               = "WEBAPP AUTOSCALING  EC2 Instance - ${timestamp()}"
    propagate_at_launch = true
  }

}

# Create a scale-up policy
resource "aws_autoscaling_policy" "scale_up_policy" {
  name                   = "scale-up-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.webapp_autoscaling_group.name

  # Increase the desired capacity of the group by 1 when average CPU usage is above 5%
  scaling_adjustment = 1
  adjustment_type    = "ChangeInCapacity"
  # metric_aggregation_type = "Average"
}

# Create a scale-down policy
resource "aws_autoscaling_policy" "scale_down_policy" {
  name                   = "scale-down-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.webapp_autoscaling_group.name

  # Decrease the desired capacity of the group by 1 when average CPU usage is below 3%
  scaling_adjustment = -1
  adjustment_type    = "ChangeInCapacity"
  # metric_aggregation_type = "Average"
}

# Create a CloudWatch metric alarm for high CPU usage
resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 5
  alarm_description   = "This metric checks if CPU usage is higher than 5% for the past 2 minutes"
  alarm_actions       = [aws_autoscaling_policy.scale_up_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_autoscaling_group.name
  }
}

# Create a CloudWatch metric alarm for low CPU usage
resource "aws_cloudwatch_metric_alarm" "low_cpu_alarm" {
  alarm_name          = "low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 3
  alarm_description   = "This metric checks if CPU usage is lower than 3% for the past 2 minutes"
  alarm_actions       = [aws_autoscaling_policy.scale_down_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_autoscaling_group.name
  }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "ebs_custom_key" {
  description             = "Symmetric customer-managed KMS key for EBS"
  deletion_window_in_days = 10
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Sid" : "Allow service-linked role use of the customer managed key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:CreateGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ] }
  )
}

#  kms_key for RDS
resource "aws_kms_key" "rds_custom_key" {
  description = "Encrypting RDS instance"
  policy = jsonencode({
    Id = "ebskeypolicy"
    Statement = [
      {
        Action = "kms:*"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }

        Resource = "*"
        Sid      = "Enable IAM User Permissions"
      },
    ]
    Version = "2012-10-17"
  })
}

resource "aws_lb" "load_balancer" {
  name               = "webapp-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_security_group.id]
  subnets            = aws_subnet.public_subnets_1[*].id

  tags = {
    Name = "webapp-load-balancer"
  }

  enable_deletion_protection = false
}

data "aws_acm_certificate" "certificate" {
  domain   = var.domain_name
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "webapp_listener" {
  load_balancer_arn = aws_lb.load_balancer.arn
  port              = 443
  protocol          = "HTTPS"
   certificate_arn = data.aws_acm_certificate.certificate.arn

  default_action {
    target_group_arn = aws_lb_target_group.load_balancer_target_group.arn
    type             = "forward"
  }
}


resource "aws_lb_target_group" "load_balancer_target_group" {
  name_prefix = "EC2TG"
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc_1.id
  target_type = "instance"

  health_check {
    enabled             = true
    interval            = 30
    path                = "/healthz"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 2
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
}
resource "aws_security_group" "database_security_group" {
  name_prefix = "database-"
  description = "Security group for RDS Instance"
  vpc_id      = aws_vpc.vpc_1.id
  tags = {
    Name = "database-security-group"
  }
}

# Add an inbound rule to the RDS security group to allow traffic from the EC2 security group
resource "aws_security_group_rule" "rds_ingress" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.database_security_group.id
  source_security_group_id = aws_security_group.application.id
}
# Add an outbound rule to the RDS security group to allow traffic from the EC2 security group
resource "aws_security_group_rule" "rds_egress" {
  type                     = "egress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.database_security_group.id
  source_security_group_id = aws_security_group.application.id
}

# Add an inbound rule to the EC2 security group to allow traffic to the RDS security group
resource "aws_security_group_rule" "ec2_ingress" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.database_security_group.id
}


resource "aws_key_pair" "ec2keypair" {
  key_name   = "ec2"
  public_key = file("~/.ssh/ec2.pub")
}
# RDS Instance
resource "aws_db_instance" "rds_instance" {
  db_name                = "csye6225"
  identifier             = "csye6225"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  multi_az               = false
  username               = "csye6225"
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.database_security_group.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.rds_parameter_group.name
  allocated_storage      = 20
  skip_final_snapshot    = true
  storage_encrypted      = true
  # kms_key_id = 
  #   engine_version         = "5.7"

  tags = {
    Name = "csye6225_rds_instance"
  }
}

# DB subnet group
resource "aws_db_subnet_group" "rds_subnet_group" {
  name        = "rds_subnet_group"
  subnet_ids  = [aws_subnet.private_subnets_1[1].id, aws_subnet.private_subnets_1[2].id]
  description = "Subnet group for the RDS instance"
}

# RDS Parameter Group
resource "aws_db_parameter_group" "rds_parameter_group" {
  name_prefix = "rds-parameter-group"
  family      = "mysql8.0"
  description = "RDS DB parameter group for MySQL 8.0"

}

# Create EC2 Instance

# resource "aws_instance" "EC2-CSYE6225" {
#   ami                     = var.aws_ami
#   instance_type           = "t2.micro"
#   disable_api_termination = false
#   ebs_optimized           = false
#   root_block_device {
#     volume_size           = 50
#     volume_type           = "gp2"
#     delete_on_termination = true
#   }
#   vpc_security_group_ids = [aws_security_group.application.id]
#   subnet_id              = aws_subnet.public_subnets_1[0].id
#   key_name               = aws_key_pair.ec2keypair.key_name
#   iam_instance_profile   = aws_iam_instance_profile.s3_access_instance_profile.name
#   user_data              = <<EOF
# #!/bin/bash
# echo "[Unit]
# Description=Webapp Service
# After=network.target

# [Service]
# Environment="DB_HOST=${element(split(":", aws_db_instance.rds_instance.endpoint), 0)}"
# Environment="DB_USER=${aws_db_instance.rds_instance.username}"
# Environment="DB_PASSWORD=${aws_db_instance.rds_instance.password}"
# Environment="DB_DATABASE=${aws_db_instance.rds_instance.db_name}"
# Environment="AWS_BUCKET_NAME=${aws_s3_bucket.webapp1bucket.bucket}"
# Environment="AWS_REGION=${var.aws_region}"
# Type=simple
# User=ec2-user
# WorkingDirectory=/home/ec2-user/webapp
# ExecStart=/usr/bin/node server.js
# Restart=on-failure

# [Install]
# WantedBy=multi-user.target" > /etc/systemd/system/webapp.service
# sudo systemctl daemon-reload
# sudo systemctl start webapp.service
# sudo systemctl enable webapp.service
# sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json
# EOF

#   tags = {
#     Name = "WEBAPP EC2 Instance"
#   }
# }

resource "random_uuid" "image_uuid" {}

#S3 Bucket
resource "aws_s3_bucket" "webapp1bucket" {
  bucket = "webapp1bucket-${random_uuid.image_uuid.result}"
  # acl           = "private"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "access_bucket" {
  bucket = aws_s3_bucket.webapp1bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_server_side_encryption_configuration" "my_bucket_encryption" {
  bucket = aws_s3_bucket.webapp1bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "my_bucket_lifecycle" {
  bucket = aws_s3_bucket.webapp1bucket.id
  rule {
    id     = "transition-objects-to-standard-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_iam_instance_profile" "s3_access_instance_profile" {
  name = "s3_access_instance_profile"
  role = aws_iam_role.s3_access_role.name

  tags = {
    Terraform = "true"
  }
}

resource "aws_iam_role" "s3_access_role" {
  name = "EC2-CSYE6225"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Terraform = "true"
  }
}

resource "aws_iam_policy" "s3_access_policy" {
  name        = "WebAppS3"
  description = "Policy to allow access to S3 bucket"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:s3:::${aws_s3_bucket.webapp1bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.webapp1bucket.bucket}/*"
        ]
      }
    ]
    }
  )
}
resource "aws_iam_role_policy_attachment" "s3_access_role_policy_attachment" {
  policy_arn = aws_iam_policy.s3_access_policy.arn
  role       = aws_iam_role.s3_access_role.name
}

data "aws_route53_zone" "webappDNS" {
  name = var.aws_profile == "dev" ? "dev.banishmg.me" : "prod.banishmg.me"
}

resource "aws_route53_record" "webapproute53" {
  zone_id = data.aws_route53_zone.webappDNS.zone_id
  name    = data.aws_route53_zone.webappDNS.name
  type    = "A"
  # ttl     = "300"
  # records = [aws_instance.EC2-CSYE6225.public_ip]
  alias {
    name                   = aws_lb.load_balancer.dns_name
    zone_id                = aws_lb.load_balancer.zone_id
    evaluate_target_health = true
  }

}

resource "aws_iam_policy_attachment" "web-app-atach-cloudwatch" {
  name       = "attach-cloudwatch-server-policy-ec2"
  roles      = [aws_iam_role.s3_access_role.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}


