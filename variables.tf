variable "vpc_cidr" {
  type        = list(string)
  description = "Mulltiple CIDRs for vpcs in the same region"
}

variable "aws_region" {
  type        = string
  description = "AWS Region"
}

variable "aws_profile" {
  type        = string
  description = "AWS Account profile"
}

variable "public_tag" {
  type        = string
  description = "public tag"
}

variable "public_subnet_name" {
  type        = string
  description = "public subnet name"
}

variable "private_tag" {
  type        = string
  description = "private subnet name"
}

variable "private_subnet_name" {
  type        = string
  description = "private subnet name"
}

variable "subnet_prefix_1" {
  type        = string
  description = "subnet prefix for all subnets under vpc 1"
}

variable "subnet_prefix_2" {
  type        = string
  description = "subnet prefix for all subnets under vpc 2"
}

variable "subnet_suffix" {
  type        = string
  description = "subnet suffix for all subnets under all vpcs"
}

variable "public_route_table_cidr" {
  type        = string
  description = "public route table CIDR for all ipv4"
}

variable "app_port" {
  type        = number
  description = "port number on which the application runs"
  default     = 8000
}

variable "db_port" {
  type        = number
  description = "port number on which the application runs"
  default     = 3306
}

variable "aws_ami" {
  description = "ami values"
  type        = string
}

variable "db_password" {
  description = "db password"
  type        = string
}

variable "domain_name" {
  description = "domain name"
  type        = string
}
