from .s3_public import S3Public
from .sg_open_admin import SgOpenAdmin
from .iam_wildcard import IamWildcard
from .ebs_unencrypted import EbsUnencrypted
from .rds_public import RdsPublic
from .cloudtrail_off import CloudtrailOff

ALL_CHECKS = [S3Public(), SgOpenAdmin(), IamWildcard(), EbsUnencrypted(), RdsPublic(), CloudtrailOff()]
