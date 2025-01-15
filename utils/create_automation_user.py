import argparse
import json
import logging
import os
import sys
from enum import Enum
from typing import Dict

import boto3

logger = logging.getLogger()


class Organization:
    """
    Get Account Organization Information
    """

    def __init__(self) -> None:
        self._org = boto3.client("organizations")

    def get_info(self) -> None:
        """
        Get organizational Info

        :return: Account Organization Information
        """
        try:
            if "Organization" in self._org.describe_organization():
                org_info = self._org.describe_organization()["Organization"]
                if "AvailablePolicyTypes" in org_info:
                    del org_info["AvailablePolicyTypes"]
                if "Id" in org_info:
                    del org_info["Id"]

                return org_info  # type: ignore

        except Exception as e:
            logger.error("Failed to get AWS Org Info: {}".format(e))
            raise


class AWSAccount:
    """
    Get AWS Account Information
    """

    def __init__(self) -> None:
        self._account = boto3.client("sts")

    def get_info(self) -> None:
        """
        Get current AWS account information

        :return: Current AWS Account Information
        """
        try:
            if "Account" in self._account.get_caller_identity():
                account_info = self._account.get_caller_identity()["Account"]

                return {"AccountID": account_info}  # type: ignore

        except Exception as e:
            logger.error("Failed to get AWS Account Info: {}".format(e))
            raise


class SesMailSender:
    """
    Sends an email via Amazon Simple Email Service(SES)
    """

    def __init__(self, source: str, destination: str, org_info: str, account_info: str, credentials: str) -> None:
        """
        :param source: The source email address
        :param destination: The destination email address
        :param org_info: Account organization information
        :param org_info: Account information
        :param credentials: Account Credentials
        """
        self._ses = boto3.client("ses")
        self.source = source
        self.destination = SesDestination([destination])  # type: ignore
        self.org_info = org_info
        self.account_info = account_info
        self.credentials = credentials

    def send_email(self, reply_tos=None) -> None:  # type: ignore
        """
        Send the email message

        :param reply_tos: Reply to email address
        """
        try:
            subject = "Cloudforge Environment Credentials"
            send_args = {
                "Source": self.source,
                "Destination": self.destination.to_service_format(),
                "Message": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": self._compile_msg()}}},
            }
            if reply_tos is not None:
                send_args["ReplyToAddresses"] = reply_tos

            response = self._ses.send_email(**send_args)
            message_id = response["MessageId"]
            logger.info("Sent mail {} from {} to {}.".format(message_id, self.source, self.destination.tos))

        except Exception as e:
            logger.error("SES Unable to send the email message: {}".format(e))
            raise

    def _compile_msg(self) -> str:
        """
        Compile the email message
        """
        email_message = {}  # type: ignore
        email_message.update(self.org_info)  # type: ignore
        email_message.update(self.account_info)  # type: ignore
        email_message.update(self.credentials)  # type: ignore

        return json.dumps(email_message, indent=2)


class ExposeCredsToGitHubWorkflow:
    """
    Expose credentials to GitHub Workflow
    """

    def __init__(self, credentials: Dict[str, str], org_info: Dict[str, str], account_info: Dict[str, str]) -> None:
        """
        :param credentials: The credentials to expose
        :param org_info: The org information to expose
        :param account_info: The account information to expose
        """
        self.credentials = credentials
        self.org_info = org_info
        self.account_info = account_info

    def execute(self) -> None:
        """
        Expose credentials command
        """
        try:
            if os.environ.get("GITHUB_OUTPUT", "") == "":
                error_msg = "The GITHUB_OUTPUT does not exit!"
                raise Exception(error_msg)

            else:
                for key in self.credentials:
                    os.system(
                        f"echo AUTOMATION_SCRIPT_VAR_{key.upper()}='{self.credentials.get(key)}' >> $GITHUB_OUTPUT"
                    )
                for key in self.org_info:
                    os.system(f"echo AUTOMATION_SCRIPT_VAR_{key.upper()}='{self.org_info.get(key)}' >> $GITHUB_OUTPUT")
                for key in self.account_info:
                    os.system(
                        f"echo AUTOMATION_SCRIPT_VAR_{key.upper()}='{self.account_info.get(key)}' >> $GITHUB_OUTPUT"
                    )

        except Exception as e:
            logger.error("Unable to expose credentials to GitHub workflow: {}".format(e))
            raise


class SesDestination:
    """
    Contains data about an email destination.
    """

    def __init__(self, tos: str, ccs=None, bccs=None) -> None:  # type: ignore
        """
        :param tos: The list of recipients on the 'To:' line.
        :param ccs: The list of recipients on the 'CC:' line.
        :param bccs: The list of recipients on the 'BCC:' line.
        """
        self.tos = tos
        self.ccs = ccs
        self.bccs = bccs

    def to_service_format(self) -> str:
        """
        :return: The destination data in the format expected by Amazon SES.
        """
        svc_format = {"ToAddresses": self.tos}
        if self.ccs is not None:
            svc_format["CcAddresses"] = self.ccs
        if self.bccs is not None:
            svc_format["BccAddresses"] = self.bccs
        return svc_format  # type: ignore


class SesValidateEmailIdentity:
    """
    Validate Email Identity in Amazon Simple Email Service(SES)
    """

    def __init__(self, email: str) -> None:
        """
        :param email: Email address
        """
        self.email = email
        self._ses = boto3.client("ses")

    def validate(self) -> None:
        """
        Send validation request
        """
        try:
            if self.is_validated():
                logger.info('Email "{}" is already validated!'.format(self.email))
                return

            self._ses.verify_email_identity(EmailAddress=self.email)
            logger.info('Validation request from AWS successfully sent to "{}" email'.format(self.email))
        except Exception as e:
            logger.error('SES Unable to start verification of "{}" email: {}'.format(self.email, e))
            raise

    def is_validated(self) -> bool:
        try:
            if self.email in self._ses.list_identities()["Identities"]:
                verification_response = self._ses.get_identity_verification_attributes(Identities=[self.email])
                return verification_response["VerificationAttributes"][self.email]["VerificationStatus"] == "Success"  # type: ignore
            return False

        except Exception as e:
            logger.error("Unable to check email validation status: {}".format(e))
            raise

    def remove_email_identity(self) -> None:
        """
        Remove Email Identity
        """
        try:
            if not self.is_validated():
                logger.info("{} is already removed from Amazon SES.".format(self.email))
                return

            answer = input(f"Do you want to remove {self.email} from Amazon SES (y/n)? ")
            if answer.lower() == "y":
                self._ses.delete_identity(Identity=self.email)
                logger.info("{} removed from Amazon SES.".format(self.email))
        except Exception as e:
            logger.error('SES Unable to remove of "{}" email identity: {}'.format(self.email, e))
            raise


class IAMUserCredentials:
    """
    IAMUser User Credentials
    """

    def __init__(self, name: str, regenerate_creds: bool) -> None:
        """
        :param name: Username
        :param regenerate_creds: Flag for regenerating AWS Key Pair
        """
        self.name = name
        self.regenerate_creds = regenerate_creds
        self._iam = boto3.resource("iam")
        self._key_pair = None

    def create(self) -> str:
        """
        Create the AWS Key Pair
        """
        try:
            if self.exists():
                if self.regenerate_creds:
                    logger.info("Removing existing keys")
                    for key_pair in list(self._iam.User(self.name).access_keys.all()):
                        key_pair.delete()
                else:
                    error_msg = (
                        "An Active AWS Key Pair Already Exists! " + 'Use the "-r" option to regenerate the credentials'
                    )
                    raise Exception(error_msg)

            logger.info("Generating AWS Key Pair")
            self._key_pair = self._iam.User(self.name).create_access_key_pair()
            credentials = {
                "username": self._key_pair._user_name,  # type: ignore
                "aws_access_key_id": self._key_pair.id,  # type: ignore
                "aws_secret_access_key": self._key_pair.secret_access_key,  # type: ignore
                "aws_key_status": self._key_pair.status,  # type: ignore
                "aws_key_create_date": str(self._key_pair.create_date),  # type: ignore
            }
            logger.info("AWS Credentials successfully generated")
            return credentials  # type: ignore

        except Exception as e:
            logger.error("User AWS Key Pair Creation Exception: {}".format(e))
            raise

    def exists(self) -> bool:
        """
        Check if an active AWS Key Pair exists

        :return: True if it exists, False otherwise
        """
        try:
            for key_pair in list(self._iam.User(self.name).access_keys.all()):
                if "Active" in key_pair.status:
                    return True
            return False
        except Exception as e:
            logger.error("Fetching User Key Exception: {}".format(e))
            raise


class IAMUser:
    """
    IAMUser Class
    """

    def __init__(self, name: str) -> None:
        """
        :param name: User Name
        """
        self.name = name
        self._iam = boto3.resource("iam")
        self._user = None

    def create(self) -> None:
        """
        Create the IAM Group
        """
        if self.exists():
            return

        try:
            self._user = self._iam.create_user(UserName=self.name)
        except Exception as e:
            logger.error("Create User Exception: {}".format(e))
            raise

    def attach_policy(self, policy_arn: str) -> None:
        """
        Attach a policy to this user object

        :param policy_arn: Policy ARN
        """
        try:
            if self._user:
                self._user.attach_policy(UserName=self.name, PolicyArn=policy_arn)
        except Exception as e:
            logger.error("Attach User Policy Exception: {}".format(e))
            raise

    def add_group(self, group_name: str) -> None:
        """
        Add user to the group

        :param group_name: Group Name
        """
        try:
            if self._user:
                self._user.add_group(GroupName=group_name)
        except Exception as e:
            logger.error("Add User to Group Exception: {}".format(e))
            raise

    def exists(self) -> bool:
        """
        Check if user exists

        :return: True if it exists, False otherwise
        """
        if self._user:
            return True

        for user in self._iam.users.all():
            if self.name in user.user_name:
                self._user = user
                return True
        return False


class IAMGroup:
    """
    IAMGroup Class
    """

    def __init__(self, name: str) -> None:
        """
        :param name: Group Name
        """
        self.name = name
        self._iam = boto3.resource("iam")
        self._group = None

    def create(self) -> None:
        """
        Create the IAM Group
        """
        if self.exists():
            return

        try:
            self._group = self._iam.create_group(GroupName=self.name)
        except Exception as e:
            logger.error("Create Group Exception: {}".format(e))
            raise

    def attach_policy(self, policy_arn: str) -> None:
        """
        Attch policy to this group object

        :param policy_arn: Policy ARN
        """
        try:
            if self._group:
                self._group.attach_policy(PolicyArn=policy_arn)
        except Exception as e:
            logger.error("Create Group Exception: {}".format(e))
            raise

    def exists(self) -> bool:
        """
        Check if policy exists

        :return: True if it exists, False otherwise
        """
        if self._group:
            return True

        for group in self._iam.groups.all():
            if self.name in group.group_name:
                self._group = group
                return True
        return False


class IAMPolicy:
    """
    IAMPolicy Class
    """

    def __init__(self, name: str, description: str, document: object) -> None:
        """
        :param name: Policy Name
        :param description: Policy Description
        :param document: Policy Document
        """
        self.name = name
        self.description = description
        self.document = document
        self._iam = boto3.resource("iam")
        self._policy = None

    def create(self) -> None:
        if self.exists():
            return

        try:
            self._policy = self._iam.create_policy(
                PolicyName=self.name,
                Description=self.description,
                PolicyDocument=json.dumps(self.document),
            )
        except Exception as e:
            logger.error("Policy Creation Exception: {}".format(e))
            raise

    def get_policy_arn(self) -> str:
        """
        Return the policy ARN

        :return: Policy ARN
        """
        if self.exists() and self._policy:
            return self._policy._arn
        return ""  # Added to satisfy mypy unit test failure

    def exists(self) -> bool:
        """
        Check if policy exists
        :return: True if it exists, False otherwise
        """
        if self._policy:
            return True

        for policy in self._iam.policies.filter(Scope="All"):
            if self.name in policy.policy_name:
                self._policy = policy
                return True
        return False


class CloudforgeGroupAndPolicies(Enum):
    GROUP_NAME = "cf-platform-ops-automation-security-group"
    GROUP_POLICIES = [
        {
            "cf-platform-ops-assume-role-policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": "*"}],
            }
        }
    ]
    USER_POLICIES = [
        {
            "cf-platform-ops-automation-policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "*",
                        ],
                        "Effect": "Allow",
                        "Resource": "*",
                        "Sid": "DeploymentAccess",
                    }
                ],
            }
        }
    ]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--email", required=False, help="Sender Email Address, i.e. john.doe@example.com")
    parser.add_argument(
        "-u",
        "--username",
        help="Automation user name, i.e. cf-platform-ops-user",
        action="store",
        default="cf-platform-ops-user",
    )
    parser.add_argument("-v", "--validate", help="Validate Email Identities Only", action="store_true", default=False)
    parser.add_argument(
        "-r", "--regenerate_creds", help="Regenerate cf-platform-ops-user user credentials", action="store_true", default=False
    )
    parser.add_argument(
        "-d", "--delete_identities", help="Delete Email identities from SES", action="store_true", default=False
    )
    parser.add_argument(
        "-s", "--share_creds", help="Expose credentials to GitHub workflow", action="store_true", default=False
    )
    args = parser.parse_args()
    email = args.email
    username = args.username
    validate_identities = args.validate
    regenerate_creds = args.regenerate_creds
    delete_identities = args.delete_identities
    share_creds = args.share_creds

    try:
        group_name = CloudforgeGroupAndPolicies.GROUP_NAME.value
        group_policies = CloudforgeGroupAndPolicies.GROUP_POLICIES.value
        user_policies = CloudforgeGroupAndPolicies.USER_POLICIES.value

        # Delete email identities from SES
        if delete_identities:
            SesValidateEmailIdentity(email=email).remove_email_identity()
            sys.exit(0)

        # Validate customer email identities
        if validate_identities:
            if not email:
                raise Exception('Must specify sender email when using "-v" option!')
            else:
                SesValidateEmailIdentity(email=email).validate()
                sys.exit(1)

        if share_creds and not regenerate_creds:
            error_msg = 'The "-r | --regenerate_creds" option must be selected with share_creds flag!'
            raise Exception(error_msg)
        elif email and not SesValidateEmailIdentity(email=email).is_validated():
            error_msg = (
                "Sender email addresses is not validated!\n"
                + 'Use "-v | --validate" option to start the validation process if it has not already started!'
            )
            raise Exception(error_msg)

        # Create the user and group
        logger.info('Creating the "{}" user'.format(username))
        user = IAMUser(name=username)
        user.create()

        logger.info('Creating the "{}" group'.format(group_name))
        group = IAMGroup(name=group_name)
        group.create()

        # Create group and user policies
        logger.info("Creating group policies")
        for policy_doc in group_policies:
            for policy_id in policy_doc:
                policy = IAMPolicy(
                    name=policy_id,
                    description=policy_id,
                    document=policy_doc.get(policy_id),
                )
                policy.create()
                group.attach_policy(policy.get_policy_arn())

        logger.info("Creating user policies")
        for policy_doc in user_policies:
            for policy_id in policy_doc:
                policy = IAMPolicy(
                    name=policy_id,
                    description=policy_id,
                    document=policy_doc.get(policy_id),
                )
                policy.create()
                user.attach_policy(policy_arn=policy.get_policy_arn())

        # Add user to groups
        logger.info('Adding user "{}" to the "{}" group'.format(username, group_name))
        user.add_group(group_name=group_name)

        # Generate and share automation user credentials
        if not share_creds:
            logger.info("Generating and sharing credentials via AWS SES")
            credentials = IAMUserCredentials(name=username, regenerate_creds=regenerate_creds)
            SesMailSender(
                source=email,
                destination=email,
                org_info=Organization().get_info(),  # type: ignore
                account_info=AWSAccount().get_info(),  # type: ignore
                credentials=credentials.create(),
            ).send_email()
        else:
            logger.info("Exposing credentials to GitHub workflow")
            credentials = IAMUserCredentials(name=username, regenerate_creds=regenerate_creds)
            ExposeCredsToGitHubWorkflow(
                credentials=credentials.create(),  # type: ignore
                org_info=Organization().get_info(),  # type: ignore
                account_info=AWSAccount().get_info(),  # type: ignore
            ).execute()

    except Exception as e:
        logger.error("Main Program Exception: %s" % e)
        sys.exit(1)
