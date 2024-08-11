provider "aws" {
	region = var.region
}

# Filter out local zones, which are not currently supported 
# with managed node groups
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  cluster_name = "votingapp-eks-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

# Creating VPC for EKS
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.12.1"
  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs  = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = true
  enable_dns_hostnames = true
  
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
  
  tags = {
    Terraform = "true"
    Environment = "dev"
  }
}

# Creating EKS Cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.30"

  cluster_endpoint_public_access           = true
  enable_cluster_creator_admin_permissions = true
  cluster_addons = {
	coredns                = {}
	eks-pod-identity-agent = {}
	kube-proxy             = {}
	vpc-cni                = {}
	}

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_group_defaults = {
        instance_types = ["m6i.large", "m5.large", "m5n.large", "m5zn.large"]
    }
    
    eks_managed_node_groups = {
        eks_nodes = {
        # Starting on 1.30, AL2023 is the default AMI type for EKS managed node groups
        ami_type       = "AL2023_x86_64_STANDARD"
        instance_types = ["m5.large"]

        min_size     = 2
        max_size     = 3
        desired_size = 2
        }
    }
  
tags = {
    Environment = "dev"
    Terraform   = "true"
  }
  
}