from my_modules.benchmarker import print_execution_time

from aws_cis_modules.aws_cis_s3 import check_bucket_encryption, check_bucket_policy, check_bucket_public_access, check_bucket_versioning
from aws_cis_modules.aws_cis_cloudtrails import check_cloudtrail


def main():
    # no_of_runs = 2
    # print_execution_time(check_bucket_encryption.__name__, no_of_runs)

    bucket_issues = check_bucket_encryption()
    bucket_issues = check_bucket_policy(bucket_issues)
    bucket_issues = check_bucket_public_access(bucket_issues)
    bucket_issues = check_bucket_versioning(bucket_issues)
    print(bucket_issues)

    # trails = check_cloudtrail()
    # print(trails)


if __name__ == '__main__':
    main()
