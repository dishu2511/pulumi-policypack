from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

RDS_PORT = 3306
COMPANY_NAME = "abc"
PROJECT_NAME = "xyz"
ENV_LIST = ["dev", "test", "uat", "staging", "prod", "train", "sandbox"]

# policy to check the resource name


def check_resource_name(name):
    return (
        name is not None
        and name.startswith(f"{COMPANY_NAME}-{PROJECT_NAME}")
        # and name.endswith(f"{PROJECT_NAME}")
        and name.split("-")[-1] in ENV_LIST
        and name.count("-") > 2
        and "_" not in name
    )


def check_naming_convention(
    args: ResourceValidationArgs, report_violation: ReportViolation
):
    name = args.name
    if args.resource_type not in [
        "pulumi:pulumi:Stack",
        "pulumi:providers:aws",
        "pulumi:providers:random",
    ]:
        if "name" in args.props and not check_resource_name(args.props["name"]):
            violating_name = args.props["name"]
            report_violation(
                f"{violating_name} does not follow the standard naming policy."
            )


resource_naming_convention = ResourceValidationPolicy(
    name="resource-naming-convention",
    description="Prohibits creation of the resource if not following naming convention",
    validate=check_naming_convention,
)

##########################################################################################
##########################################################################################

# policy to check s3 naming


def check_s3_bucket_name(resource, report_violation):
    if resource.resource_type == "aws:s3/bucket:Bucket":
        bucketName = resource.props.get("bucket", "")
        if not (
            bucketName.startswith(f"{COMPANY_NAME}-{PROJECT_NAME}")
            and any(bucketName.endswith(env) for env in ENV_LIST)
        ):
            report_violation("The S3 bucket name must start with 'my-company'.")


check_s3_bucket_naming_convention = ResourceValidationPolicy(
    name="check_s3_bucket_naming_convention",
    description="Prohibits creation of the resource if not following naming convention",
    validate=check_s3_bucket_name,
)

##########################################################################################
##########################################################################################


# policy to check is s3 is open to public


def s3_no_public_read_validator(
    args: ResourceValidationArgs, report_violation: ReportViolation
):
    if args.resource_type == "aws:s3/bucket:Bucket" and "acl" in args.props:
        acl = args.props["acl"]
        if acl == "public-read" or acl == "public-read-write":
            report_violation(
                "Please review the code. "
                + "You cannot set public-read or public-read-write on an S3 bucket. "
                + "Read more about ACLs here: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html"
            )


s3_no_public_read = ResourceValidationPolicy(
    name="s3-no-public-read",
    description="Prohibits setting the publicRead or publicReadWrite permission on AWS S3 buckets.",
    validate=s3_no_public_read_validator,
)

##########################################################################################
##########################################################################################


# policy to check tags


def tag_policy_func(args: ResourceValidationArgs, report_violation: ReportViolation):
    if args.resource_type not in [
        "pulumi:pulumi:Stack",
        "pulumi:providers:aws",
        "pulumi:providers:random",
    ]:

        if not "tags" in args.props:
            report_violation("Resource is missing tags")
            return

        if not "Project" in args.props["tags"]:
            report_violation('Resource is missing required "Project" tag')


tagging_policy = ResourceValidationPolicy(
    name="require-name-tag",
    description="Enforces a 'Project' tag on all resources",
    validate=tag_policy_func,
)

##########################################################################################
##########################################################################################


# policy to check security group on open to the internet for SSH


def sg_policy_func(args: ResourceValidationArgs, report_violation):
    if args.resource_type != "aws:ec2/securityGroup:SecurityGroup":
        return

    if "ingress" not in args.props:
        return

    for ingress in args.props["ingress"]:
        if (
            ingress["fromPort"] == 22
            and ingress["toPort"] == 22
            and "0.0.0.0/0" in ingress["cidrBlocks"]
        ):
            report_violation(
                "Ingress rule allowing traffic on port 22 from 0.0.0.0/0 is not allowed"
            )


sg_policy = ResourceValidationPolicy(
    name="no-inbound-ssh-rule",
    description="Prevents creating a security group with an inbound rule of 0.0.0.0/0 on port 22",
    validate=sg_policy_func,
)

##########################################################################################
##########################################################################################


# policy to check security group on open to the internet for SSH


def rds_sg_policy_func(args: ResourceValidationArgs, report_violation):
    if args.resource_type != "aws:ec2/securityGroup:SecurityGroup":
        return

    if "ingress" not in args.props:
        return

    for ingress in args.props["ingress"]:
        if (
            ingress["fromPort"] == RDS_PORT
            and ingress["toPort"] == RDS_PORT
            and "0.0.0.0/0" in ingress["cidrBlocks"]
        ):
            report_violation(
                f"Ingress rule allowing traffic on port {RDS_PORT} from 0.0.0.0/0 is not allowed"
            )


rds_sg_policy = ResourceValidationPolicy(
    name="no-inbound-open--rds-access",
    description=f"Prevents creating a security group with an inbound rule of 0.0.0.0/0 on port {RDS_PORT}",
    validate=rds_sg_policy_func,
)

##########################################################################################
##########################################################################################


# policy to prevent RDS instance that are open to public


def rds_policy_func(args: ResourceValidationArgs, report_violation):
    if args.resource_type != "aws:rds/instance:Instance":
        return

    if "publiclyAccessible" in args.props and args.props["publiclyAccessible"]:
        report_violation("Prevents creating RDS instances that are open to the public")


rds_privacy_policy = ResourceValidationPolicy(
    name="no-public-rds",
    description="RDS privacy policy",
    validate=rds_policy_func,
)

policy_pack = PolicyPack(
    name="aws-python",
    enforcement_level=EnforcementLevel.MANDATORY,
    policies=[
        sg_policy,
        s3_no_public_read,
        tagging_policy,
        rds_privacy_policy,
        rds_sg_policy,
        resource_naming_convention,
        check_s3_bucket_naming_convention,
    ],
)
