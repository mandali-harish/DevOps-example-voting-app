data "aws_partition" "current" {}
data "aws_iam_session_context" "current" {
  # This data source provides information on the IAM source role of an STS assumed role
  # For non-role ARNs, this data source simply passes the ARN through issuer ARN
  # Ref https://github.com/terraform-aws-modules/terraform-aws-eks/issues/2327#issuecomment-1355581682
  # Ref https://github.com/hashicorp/terraform-provider-aws/issues/28381
  arn = data.aws_caller_identity.current.arn
}
data "aws_caller_identity" "current" {}

locals {
    partition = data.aws_partition.current.partition
    enable_cluster_encryption_config = length(var.cluster_encryption_config) > 0
    create_outposts_local_cluster    = length(var.outpost_config) > 0
    cluster_role = try(aws_iam_role.this.arn, var.iam_role_arn)
}

################################################################################
# EKS Cluster
################################################################################

resource "aws_eks_cluster" "this"{

    name = var.cluster_name
    role_arn = local.cluster_role
    version = var.cluster_version
    bootstrap_self_managed_addons = var.bootstrap_self_managed_addons
    enabled_cluster_log_types = var.cluster_enabled_log_types


    vpc_config {
        endpoint_private_access = var.cluster_endpoint_private_access
        endpoint_public_access = var.cluster_endpoint_public_access
        public_access_cidrs = var.cluster_public_access_cidrs
        security_group_ids = compact(distinct(concat(var.cluster_additional_security_group_ids, [local.cluster_security_group_id])))
        subnet_ids = coalescelist(var.control_plane_subnet_ids, var.cluster_subnet_ids)
    }

    access_config {
        authentication_mode = var.authentication_mode
        bootstrap_cluster_creator_admin_permissions = false
    }

    dynamic "encryption_config" {
        for_each = local.enable_cluster_encryption_config ? [var.cluster_encryption_config] : []

        content {
            provider {
                key_arn = var.create_kms_key ? module.kms.key_arn : encryption_config.value.provider_key_arn
            }
            resources = encryption_config.value.resources
            }
    }

    dynamic "kubernetes_network_config" {
        for_each = local.create_outposts_local_cluster ? [] : [1]

        content {
            ip_family  = var.cluster_ip_family
            service_ipv4_cidr = var.cluster_service_ipv4_cidr
        }
    }

    dynamic "outpost_config" {
        for_each = local.create_outposts_local_cluster ? [var.outpost_config] : []

        content {
        control_plane_instance_type = outpost_config.value.control_plane_instance_type
        outpost_arns                = outpost_config.value.outpost_arns
        }
    }

    dynamic "upgrade_policy" {
        for_each = length(var.cluster_upgrade_policy) > 0 ? [var.cluster_upgrade_policy] : []

        content {
            support_type = try(upgrade_policy.value.support_type, null)
        }
    }

    tags = merge(
    { terraform-aws-modules = "eks" },
    var.tags,
    var.cluster_tags,
    )

    depends_on = [
        aws_iam_role_policy_attachment.this
    ]

      lifecycle {
    ignore_changes = [
      access_config[0].bootstrap_cluster_creator_admin_permissions
    ]
  }
}

resource "aws_cloudwatch_log_group" "this" {
  count = var.create_cloudwatch_log_group ? 1 : 0

  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id
  log_group_class   = var.cloudwatch_log_group_class

  tags = merge(
    var.tags,
    var.cloudwatch_log_group_tags,
    { Name = "/aws/eks/${var.cluster_name}/cluster" }
  )
}

################################################################################
# Access Entry
################################################################################
locals {

    # This replaces the one time logic from the EKS API with something that can be
  # better controlled by users through Terraform
  bootstrap_cluster_creator_admin_permissions = {
    cluster_creator = {
      principal_arn = data.aws_iam_session_context.current.issuer_arn
      type          = "STANDARD"

      policy_associations = {
        admin = {
          policy_arn = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }
    # Merge the bootstrap behavior with the entries that users provide
    merged_access_entries = merge(
    { for k, v in local.bootstrap_cluster_creator_admin_permissions : k => v if var.enable_cluster_creator_admin_permissions },
    var.access_entries,
  )

  # Flatten out entries and policy associations so users can specify the policy
  # associations within a single entry
  flattened_access_entries = flatten([
    for entry_key, entry_val in local.merged_access_entries : [
      for pol_key, pol_val in lookup(entry_val, "policy_associations", {}) :
      merge(
        {
          principal_arn = entry_val.principal_arn
          entry_key     = entry_key
          pol_key       = pol_key
        },
        { for k, v in {
          association_policy_arn              = pol_val.policy_arn
          association_access_scope_type       = pol_val.access_scope.type
          association_access_scope_namespaces = lookup(pol_val.access_scope, "namespaces", [])
        } : k => v if !contains(["EC2_LINUX", "EC2_WINDOWS", "FARGATE_LINUX"], lookup(entry_val, "type", "STANDARD")) },
      )
    ]
  ])

}

resource "aws_eks_access_entry" "this" {
for_each = { for k,v in local.merged_access_entries : k => v }
  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = each.value.principal_arn
  kubernetes_groups = try(each.value.kubernetes_groups, null)
  type              = try(each.value.type, "STANDARD")
  user_name = try(each.value.user_name, null)

  tags = merge(var.tags, try(each.value.tags, {}))
}

resource "aws_eks_access_policy_association" "this" {
  for_each = { for k, v in local.flattened_access_entries : "${v.entry_key}_${v.pol_key}" => v }

  access_scope {
    namespaces = try(each.value.association_access_scope_namespaces, [])
    type       = each.value.association_access_scope_type
  }

  cluster_name = aws_eks_cluster.this.name

  policy_arn    = each.value.association_policy_arn
  principal_arn = each.value.principal_arn

  depends_on = [
    aws_eks_access_entry.this,
  ]
}

################################################################################
# KMS Key
################################################################################

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "2.1.0" # Note - be mindful of Terraform/provider version compatibility between modules

  create = var.create_kms_key && local.enable_cluster_encryption_config # not valid on Outposts

  description             = coalesce(var.kms_key_description, "${var.cluster_name} cluster encryption key")
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.enable_kms_key_rotation

  # Policy
  enable_default_policy     = var.kms_key_enable_default_policy
  key_owners                = var.kms_key_owners
  key_administrators        = coalescelist(var.kms_key_administrators, [data.aws_iam_session_context.current.issuer_arn])
  key_users                 = concat([local.cluster_role], var.kms_key_users)
  key_service_users         = var.kms_key_service_users
  source_policy_documents   = var.kms_key_source_policy_documents
  override_policy_documents = var.kms_key_override_policy_documents

  # Aliases
  aliases = var.kms_key_aliases
  computed_aliases = {
    # Computed since users can pass in computed values for cluster name such as random provider resources
    cluster = { name = "eks/${var.cluster_name}" }
  }

  tags = merge(
    { terraform-aws-modules = "eks" },
    var.tags,
  )
}

################################################################################
# Cluster Security Group
# Defaults follow https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html
################################################################################

locals {
  cluster_sg_name   = coalesce(var.cluster_security_group_name, "${var.cluster_name}-cluster")
  create_cluster_sg = var.create_cluster_security_group

  cluster_security_group_id = local.create_cluster_sg ? aws_security_group.cluster[0].id : var.cluster_security_group_id

  # Do not add rules to node security group if the module is not creating it
  cluster_security_group_rules = { for k, v in {
    ingress_nodes_443 = {
      description                = "Node groups to cluster API"
      protocol                   = "tcp"
      from_port                  = 443
      to_port                    = 443
      type                       = "ingress"
      source_node_security_group = true
    }
  } : k => v if local.create_node_sg }
}

resource "aws_security_group" "cluster" {
  count = local.create_cluster_sg ? 1 : 0

  name        = var.cluster_security_group_use_name_prefix ? null : local.cluster_sg_name
  name_prefix = var.cluster_security_group_use_name_prefix ? "${local.cluster_sg_name}${var.prefix_separator}" : null
  description = var.cluster_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    { "Name" = local.cluster_sg_name },
    var.cluster_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "cluster" {
  for_each = { for k, v in merge(
    local.cluster_security_group_rules,
    var.cluster_security_group_additional_rules
  ) : k => v if local.create_cluster_sg }

  # Required
  security_group_id = aws_security_group.cluster[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type

  # Optional
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_node_security_group, false) ? local.node_security_group_id : lookup(each.value, "source_security_group_id", null)
}

################################################################################
# IRSA
# Note - this is different from EKS identity provider
################################################################################

locals {
  # Not available on outposts
  create_oidc_provider =  var.enable_irsa && !local.create_outposts_local_cluster

  oidc_root_ca_thumbprint = local.create_oidc_provider && var.include_oidc_root_ca_thumbprint ? [data.tls_certificate.this[0].certificates[0].sha1_fingerprint] : []
}

data "tls_certificate" "this" {
  # Not available on outposts
  count = local.create_oidc_provider && var.include_oidc_root_ca_thumbprint ? 1 : 0

  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "oidc_provider" {
  # Not available on outposts
  count = local.create_oidc_provider ? 1 : 0

  client_id_list  = distinct(compact(concat(["sts.amazonaws.com"], var.openid_connect_audiences)))
  thumbprint_list = concat(local.oidc_root_ca_thumbprint, var.custom_oidc_thumbprints)
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer

  tags = merge(
    { Name = "${var.cluster_name}-eks-irsa" },
    var.tags
  )
}

################################################################################
# IAM Role
################################################################################

locals{
    create_iam_role        =  var.create_iam_role
    iam_role_name          = coalesce(var.iam_role_name, "${var.cluster_name}-cluster")
    iam_role_policy_prefix = "arn:${local.partition}:iam::aws:policy"
    cluster_encryption_policy_name = coalesce(var.cluster_encryption_policy_name, "${local.iam_role_name}-ClusterEncryption")
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    sid     = "EKSClusterAssumeRole"
    actions   = ["sts:AssumeRole"]
    principals {
        type = "Service"
        identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.iam_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  path = var.iam_role_path
  description = var.iam_role_description
  permissions_boundary = var.iam_role_permissions_boundary
  force_detach_policies = true

  tags = merge(var.tags, var.iam_role_tags)

}

resource "aws_iam_role_policy_attachment" "this" {
    for_each = { for k, v in {
        AmazonEKSClusterPolicy = "${local.iam_role_policy_prefix}/AmazonEKSClusterPolicy",
        AmazonEKSVPCResourceController = "${local.iam_role_policy_prefix}/AmazonEKSVPCResourceController",
        } : k => v if local.create_iam_role
    }

    policy_arn = each.value
    role = aws_iam_role.this.name
}

resource "aws_iam_policy" "cluster_encryption" {
  # Encryption config not available on Outposts
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  name        = var.cluster_encryption_policy_use_name_prefix ? null : local.cluster_encryption_policy_name
  name_prefix = var.cluster_encryption_policy_use_name_prefix ? local.cluster_encryption_policy_name : null
  description = var.cluster_encryption_policy_description
  path        = var.cluster_encryption_policy_path

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ListGrants",
          "kms:DescribeKey",
        ]
        Effect   = "Allow"
        Resource = var.create_kms_key ? module.kms.key_arn : var.cluster_encryption_config.provider_key_arn
      },
    ]
  })

  tags = merge(var.tags, var.cluster_encryption_policy_tags)
}


resource "aws_iam_role_policy_attachment" "cluster_encryption" {
  # Encryption config not available on Outposts
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  policy_arn = aws_iam_policy.cluster_encryption[0].arn
  role       = aws_iam_role.this.name
}

################################################################################
# EKS Addons
################################################################################

data "aws_eks_addon_version" "this" {
  for_each = { for k, v in var.cluster_addons : k => v if !local.create_outposts_local_cluster }

  addon_name         = try(each.value.name, each.key)
  kubernetes_version = coalesce(var.cluster_version, aws_eks_cluster.this.version)
  most_recent        = try(each.value.most_recent, null)
}

resource "aws_eks_addon" "this" {
  # Not supported on outposts
  for_each = { for k, v in var.cluster_addons : k => v if !try(v.before_compute, false) && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this.name
  addon_name   = try(each.value.name, each.key)

  addon_version               = coalesce(try(each.value.addon_version, null), data.aws_eks_addon_version.this[each.key].version)
  configuration_values        = try(each.value.configuration_values, null)
  preserve                    = try(each.value.preserve, true)
  resolve_conflicts_on_create = try(each.value.resolve_conflicts_on_create, "OVERWRITE")
  resolve_conflicts_on_update = try(each.value.resolve_conflicts_on_update, "OVERWRITE")
  service_account_role_arn    = try(each.value.service_account_role_arn, null)

  timeouts {
    create = try(each.value.timeouts.create, var.cluster_addons_timeouts.create, null)
    update = try(each.value.timeouts.update, var.cluster_addons_timeouts.update, null)
    delete = try(each.value.timeouts.delete, var.cluster_addons_timeouts.delete, null)
  }

  depends_on = [
    module.eks_managed_node_group,
  ]

  tags = merge(var.tags, try(each.value.tags, {}))
}

resource "aws_eks_addon" "before_compute" {
  # Not supported on outposts
  for_each = { for k, v in var.cluster_addons : k => v if try(v.before_compute, false) && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this.name
  addon_name   = try(each.value.name, each.key)

  addon_version               = coalesce(try(each.value.addon_version, null), data.aws_eks_addon_version.this[each.key].version)
  configuration_values        = try(each.value.configuration_values, null)
  preserve                    = try(each.value.preserve, true)
  resolve_conflicts_on_create = try(each.value.resolve_conflicts_on_create, "OVERWRITE")
  resolve_conflicts_on_update = try(each.value.resolve_conflicts_on_update, "OVERWRITE")
  service_account_role_arn    = try(each.value.service_account_role_arn, null)

  timeouts {
    create = try(each.value.timeouts.create, var.cluster_addons_timeouts.create, null)
    update = try(each.value.timeouts.update, var.cluster_addons_timeouts.update, null)
    delete = try(each.value.timeouts.delete, var.cluster_addons_timeouts.delete, null)
  }

  tags = merge(var.tags, try(each.value.tags, {}))
}


################################################################################
# EKS Identity Provider
# Note - this is different from IRSA
################################################################################

locals {
  # Maintain current behavior for <= 1.29, remove default for >= 1.30
  # `null` will return the latest Kubernetes version from the EKS API, which at time of writing is 1.30
  # https://github.com/kubernetes/kubernetes/pull/123561
  idpc_backwards_compat_version = contains(["1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28", "1.29"], coalesce(var.cluster_version, "1.30"))
  idpc_issuer_url               = local.idpc_backwards_compat_version ? try(aws_eks_cluster.this.identity[0].oidc[0].issuer, null) : null
}

resource "aws_eks_identity_provider_config" "this" {
  for_each = { for k, v in var.cluster_identity_providers : k => v if !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this.name

  oidc {
    client_id                     = each.value.client_id
    groups_claim                  = lookup(each.value, "groups_claim", null)
    groups_prefix                 = lookup(each.value, "groups_prefix", null)
    identity_provider_config_name = try(each.value.identity_provider_config_name, each.key)
    # TODO - make argument explicitly required on next breaking change
    issuer_url      = try(each.value.issuer_url, local.idpc_issuer_url)
    required_claims = lookup(each.value, "required_claims", null)
    username_claim  = lookup(each.value, "username_claim", null)
    username_prefix = lookup(each.value, "username_prefix", null)
  }

  tags = merge(var.tags, try(each.value.tags, {}))
}

################################################################################
# EKS Managed Node Groups
################################################################################

locals {
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  # EKS managed node group
  default_update_config = {
    max_unavailable_percentage = 33
  }

  kubernetes_network_config = try(aws_eks_cluster.this.kubernetes_network_config[0], {})
}

# This sleep resource is used to provide a timed gap between the cluster creation and the downstream dependencies
# that consume the outputs from here. Any of the values that are used as triggers can be used in dependencies
# to ensure that the downstream resources are created after both the cluster is ready and the sleep time has passed.
# This was primarily added to give addons that need to be configured BEFORE data plane compute resources
# enough time to create and configure themselves before the data plane compute resources are created.
resource "time_sleep" "this" {

  create_duration = var.dataplane_wait_duration

  triggers = {
    cluster_name         = aws_eks_cluster.this.name
    cluster_endpoint     = aws_eks_cluster.this.endpoint
    cluster_version      = aws_eks_cluster.this.version
    cluster_service_cidr = var.cluster_ip_family == "ipv6" ? try(local.kubernetes_network_config.service_ipv6_cidr, "") : try(local.kubernetes_network_config.service_ipv4_cidr, "")

    cluster_certificate_authority_data = aws_eks_cluster.this.certificate_authority[0].data
  }
}

module "eks_managed_node_group" {
  source = "./modules/eks-managed-node-group"

  for_each = { for k, v in var.eks_managed_node_groups : k => v if !local.create_outposts_local_cluster }

  create = try(each.value.create, true)

  cluster_name    = time_sleep.this.triggers["cluster_name"]
  cluster_version = try(each.value.cluster_version, var.eks_managed_node_group_defaults.cluster_version, time_sleep.this.triggers["cluster_version"])

  # EKS Managed Node Group
  name            = try(each.value.name, each.key)
  use_name_prefix = try(each.value.use_name_prefix, var.eks_managed_node_group_defaults.use_name_prefix, true)

  subnet_ids = try(each.value.subnet_ids, var.eks_managed_node_group_defaults.subnet_ids, var.cluster_subnet_ids)

  min_size     = try(each.value.min_size, var.eks_managed_node_group_defaults.min_size, 1)
  max_size     = try(each.value.max_size, var.eks_managed_node_group_defaults.max_size, 3)
  desired_size = try(each.value.desired_size, var.eks_managed_node_group_defaults.desired_size, 1)

  ami_id                         = try(each.value.ami_id, var.eks_managed_node_group_defaults.ami_id, "")
  ami_type                       = try(each.value.ami_type, var.eks_managed_node_group_defaults.ami_type, null)
  ami_release_version            = try(each.value.ami_release_version, var.eks_managed_node_group_defaults.ami_release_version, null)
  use_latest_ami_release_version = try(each.value.use_latest_ami_release_version, var.eks_managed_node_group_defaults.use_latest_ami_release_version, false)

  capacity_type        = try(each.value.capacity_type, var.eks_managed_node_group_defaults.capacity_type, null)
  disk_size            = try(each.value.disk_size, var.eks_managed_node_group_defaults.disk_size, null)
  force_update_version = try(each.value.force_update_version, var.eks_managed_node_group_defaults.force_update_version, null)
  instance_types       = try(each.value.instance_types, var.eks_managed_node_group_defaults.instance_types, null)
  labels               = try(each.value.labels, var.eks_managed_node_group_defaults.labels, null)

  remote_access = try(each.value.remote_access, var.eks_managed_node_group_defaults.remote_access, {})
  taints        = try(each.value.taints, var.eks_managed_node_group_defaults.taints, {})
  update_config = try(each.value.update_config, var.eks_managed_node_group_defaults.update_config, local.default_update_config)
  timeouts      = try(each.value.timeouts, var.eks_managed_node_group_defaults.timeouts, {})

  # User data
  platform                   = try(each.value.platform, var.eks_managed_node_group_defaults.platform, "linux")
  cluster_endpoint           = try(time_sleep.this.triggers["cluster_endpoint"], "")
  cluster_auth_base64        = try(time_sleep.this.triggers["cluster_certificate_authority_data"], "")
  cluster_service_ipv4_cidr  = var.cluster_service_ipv4_cidr
  cluster_ip_family          = var.cluster_ip_family
  cluster_service_cidr       = try(time_sleep.this.triggers["cluster_service_cidr"], "")
  enable_bootstrap_user_data = try(each.value.enable_bootstrap_user_data, var.eks_managed_node_group_defaults.enable_bootstrap_user_data, false)
  pre_bootstrap_user_data    = try(each.value.pre_bootstrap_user_data, var.eks_managed_node_group_defaults.pre_bootstrap_user_data, "")
  post_bootstrap_user_data   = try(each.value.post_bootstrap_user_data, var.eks_managed_node_group_defaults.post_bootstrap_user_data, "")
  bootstrap_extra_args       = try(each.value.bootstrap_extra_args, var.eks_managed_node_group_defaults.bootstrap_extra_args, "")
  user_data_template_path    = try(each.value.user_data_template_path, var.eks_managed_node_group_defaults.user_data_template_path, "")
  cloudinit_pre_nodeadm      = try(each.value.cloudinit_pre_nodeadm, var.eks_managed_node_group_defaults.cloudinit_pre_nodeadm, [])
  cloudinit_post_nodeadm     = try(each.value.cloudinit_post_nodeadm, var.eks_managed_node_group_defaults.cloudinit_post_nodeadm, [])

  # Launch Template
  create_launch_template                 = try(each.value.create_launch_template, var.eks_managed_node_group_defaults.create_launch_template, true)
  use_custom_launch_template             = try(each.value.use_custom_launch_template, var.eks_managed_node_group_defaults.use_custom_launch_template, true)
  launch_template_id                     = try(each.value.launch_template_id, var.eks_managed_node_group_defaults.launch_template_id, "")
  launch_template_name                   = try(each.value.launch_template_name, var.eks_managed_node_group_defaults.launch_template_name, each.key)
  launch_template_use_name_prefix        = try(each.value.launch_template_use_name_prefix, var.eks_managed_node_group_defaults.launch_template_use_name_prefix, true)
  launch_template_version                = try(each.value.launch_template_version, var.eks_managed_node_group_defaults.launch_template_version, null)
  launch_template_default_version        = try(each.value.launch_template_default_version, var.eks_managed_node_group_defaults.launch_template_default_version, null)
  update_launch_template_default_version = try(each.value.update_launch_template_default_version, var.eks_managed_node_group_defaults.update_launch_template_default_version, true)
  launch_template_description            = try(each.value.launch_template_description, var.eks_managed_node_group_defaults.launch_template_description, "Custom launch template for ${try(each.value.name, each.key)} EKS managed node group")
  launch_template_tags                   = try(each.value.launch_template_tags, var.eks_managed_node_group_defaults.launch_template_tags, {})
  tag_specifications                     = try(each.value.tag_specifications, var.eks_managed_node_group_defaults.tag_specifications, ["instance", "volume", "network-interface"])

  ebs_optimized           = try(each.value.ebs_optimized, var.eks_managed_node_group_defaults.ebs_optimized, null)
  key_name                = try(each.value.key_name, var.eks_managed_node_group_defaults.key_name, null)
  disable_api_termination = try(each.value.disable_api_termination, var.eks_managed_node_group_defaults.disable_api_termination, null)
  kernel_id               = try(each.value.kernel_id, var.eks_managed_node_group_defaults.kernel_id, null)
  ram_disk_id             = try(each.value.ram_disk_id, var.eks_managed_node_group_defaults.ram_disk_id, null)

  block_device_mappings              = try(each.value.block_device_mappings, var.eks_managed_node_group_defaults.block_device_mappings, {})
  capacity_reservation_specification = try(each.value.capacity_reservation_specification, var.eks_managed_node_group_defaults.capacity_reservation_specification, {})
  cpu_options                        = try(each.value.cpu_options, var.eks_managed_node_group_defaults.cpu_options, {})
  credit_specification               = try(each.value.credit_specification, var.eks_managed_node_group_defaults.credit_specification, {})
  elastic_gpu_specifications         = try(each.value.elastic_gpu_specifications, var.eks_managed_node_group_defaults.elastic_gpu_specifications, {})
  elastic_inference_accelerator      = try(each.value.elastic_inference_accelerator, var.eks_managed_node_group_defaults.elastic_inference_accelerator, {})
  enclave_options                    = try(each.value.enclave_options, var.eks_managed_node_group_defaults.enclave_options, {})
  instance_market_options            = try(each.value.instance_market_options, var.eks_managed_node_group_defaults.instance_market_options, {})
  license_specifications             = try(each.value.license_specifications, var.eks_managed_node_group_defaults.license_specifications, {})
  metadata_options                   = try(each.value.metadata_options, var.eks_managed_node_group_defaults.metadata_options, local.metadata_options)
  enable_monitoring                  = try(each.value.enable_monitoring, var.eks_managed_node_group_defaults.enable_monitoring, true)
  enable_efa_support                 = try(each.value.enable_efa_support, var.eks_managed_node_group_defaults.enable_efa_support, false)
  create_placement_group             = try(each.value.create_placement_group, var.eks_managed_node_group_defaults.create_placement_group, false)
  placement                          = try(each.value.placement, var.eks_managed_node_group_defaults.placement, {})
  placement_group_az                 = try(each.value.placement_group_az, var.eks_managed_node_group_defaults.placement_group_az, null)
  placement_group_strategy           = try(each.value.placement_group_strategy, var.eks_managed_node_group_defaults.placement_group_strategy, "cluster")
  network_interfaces                 = try(each.value.network_interfaces, var.eks_managed_node_group_defaults.network_interfaces, [])
  maintenance_options                = try(each.value.maintenance_options, var.eks_managed_node_group_defaults.maintenance_options, {})
  private_dns_name_options           = try(each.value.private_dns_name_options, var.eks_managed_node_group_defaults.private_dns_name_options, {})

  # IAM role
  create_iam_role               = try(each.value.create_iam_role, var.eks_managed_node_group_defaults.create_iam_role, true)
  iam_role_arn                  = try(each.value.iam_role_arn, var.eks_managed_node_group_defaults.iam_role_arn, null)
  iam_role_name                 = try(each.value.iam_role_name, var.eks_managed_node_group_defaults.iam_role_name, null)
  iam_role_use_name_prefix      = try(each.value.iam_role_use_name_prefix, var.eks_managed_node_group_defaults.iam_role_use_name_prefix, true)
  iam_role_path                 = try(each.value.iam_role_path, var.eks_managed_node_group_defaults.iam_role_path, null)
  iam_role_description          = try(each.value.iam_role_description, var.eks_managed_node_group_defaults.iam_role_description, "EKS managed node group IAM role")
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, var.eks_managed_node_group_defaults.iam_role_permissions_boundary, null)
  iam_role_tags                 = try(each.value.iam_role_tags, var.eks_managed_node_group_defaults.iam_role_tags, {})
  iam_role_attach_cni_policy    = try(each.value.iam_role_attach_cni_policy, var.eks_managed_node_group_defaults.iam_role_attach_cni_policy, true)
  # To better understand why this `lookup()` logic is required, see:
  # https://github.com/hashicorp/terraform/issues/31646#issuecomment-1217279031
  iam_role_additional_policies = lookup(each.value, "iam_role_additional_policies", lookup(var.eks_managed_node_group_defaults, "iam_role_additional_policies", {}))
  create_iam_role_policy       = try(each.value.create_iam_role_policy, var.eks_managed_node_group_defaults.create_iam_role_policy, true)
  iam_role_policy_statements   = try(each.value.iam_role_policy_statements, var.eks_managed_node_group_defaults.iam_role_policy_statements, [])

  # Autoscaling group schedule
  create_schedule = try(each.value.create_schedule, var.eks_managed_node_group_defaults.create_schedule, true)
  schedules       = try(each.value.schedules, var.eks_managed_node_group_defaults.schedules, {})

  # Security group
  vpc_security_group_ids            = compact(concat([local.node_security_group_id], try(each.value.vpc_security_group_ids, var.eks_managed_node_group_defaults.vpc_security_group_ids, [])))
  cluster_primary_security_group_id = try(each.value.attach_cluster_primary_security_group, var.eks_managed_node_group_defaults.attach_cluster_primary_security_group, false) ? aws_eks_cluster.this.vpc_config[0].cluster_security_group_id : null

  tags = merge(var.tags, try(each.value.tags, var.eks_managed_node_group_defaults.tags, {}))
}


################################################################################
# Node Security Group
# Defaults follow https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html
# Plus NTP/HTTPS (otherwise nodes fail to launch)
################################################################################

locals {
  node_sg_name   = coalesce(var.node_security_group_name, "${var.cluster_name}-node")
  create_node_sg = var.create_node_security_group

  node_security_group_id = local.create_node_sg ? aws_security_group.node[0].id : var.node_security_group_id

  node_security_group_rules = {
    ingress_cluster_443 = {
      description                   = "Cluster API to node groups"
      protocol                      = "tcp"
      from_port                     = 443
      to_port                       = 443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    ingress_cluster_kubelet = {
      description                   = "Cluster API to node kubelets"
      protocol                      = "tcp"
      from_port                     = 10250
      to_port                       = 10250
      type                          = "ingress"
      source_cluster_security_group = true
    }
    ingress_self_coredns_tcp = {
      description = "Node to node CoreDNS"
      protocol    = "tcp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      self        = true
    }
    ingress_self_coredns_udp = {
      description = "Node to node CoreDNS UDP"
      protocol    = "udp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      self        = true
    }
  }

  node_security_group_recommended_rules = { for k, v in {
    ingress_nodes_ephemeral = {
      description = "Node to node ingress on ephemeral ports"
      protocol    = "tcp"
      from_port   = 1025
      to_port     = 65535
      type        = "ingress"
      self        = true
    }
    # metrics-server
    ingress_cluster_4443_webhook = {
      description                   = "Cluster API to node 4443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 4443
      to_port                       = 4443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    # prometheus-adapter
    ingress_cluster_6443_webhook = {
      description                   = "Cluster API to node 6443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 6443
      to_port                       = 6443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    # Karpenter
    ingress_cluster_8443_webhook = {
      description                   = "Cluster API to node 8443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 8443
      to_port                       = 8443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    # ALB controller, NGINX
    ingress_cluster_9443_webhook = {
      description                   = "Cluster API to node 9443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 9443
      to_port                       = 9443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    egress_all = {
      description      = "Allow all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = var.cluster_ip_family == "ipv6" ? ["::/0"] : null
    }
  } : k => v if var.node_security_group_enable_recommended_rules }

  efa_security_group_rules = { for k, v in
    {
      ingress_all_self_efa = {
        description = "Node to node EFA"
        protocol    = "-1"
        from_port   = 0
        to_port     = 0
        type        = "ingress"
        self        = true
      }
      egress_all_self_efa = {
        description = "Node to node EFA"
        protocol    = "-1"
        from_port   = 0
        to_port     = 0
        type        = "egress"
        self        = true
      }
    } : k => v if var.enable_efa_support
  }
}

resource "aws_security_group" "node" {
  count = local.create_node_sg ? 1 : 0

  name        = var.node_security_group_use_name_prefix ? null : local.node_sg_name
  name_prefix = var.node_security_group_use_name_prefix ? "${local.node_sg_name}${var.prefix_separator}" : null
  description = var.node_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      "Name"                                      = local.node_sg_name
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    },
    var.node_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "node" {
  for_each = { for k, v in merge(
    local.efa_security_group_rules,
    local.node_security_group_rules,
    local.node_security_group_recommended_rules,
    var.node_security_group_additional_rules,
  ) : k => v if local.create_node_sg }

  # Required
  security_group_id = aws_security_group.node[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type

  # Optional
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", [])
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_cluster_security_group, false) ? local.cluster_security_group_id : lookup(each.value, "source_security_group_id", null)
}
