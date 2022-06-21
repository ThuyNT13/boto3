'''

3.8
$ aws kms list-keys --query Keys[*].KeyId
$ aws kms get-key-rotation-status --key-id d119611c-431e-421c-b4de-8974fdcb9572

'''

import boto3
import json
import datetime

from botocore.exceptions import ClientError
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

REGION = 'us-gov-west-1'

STS_CLIENT = boto3.client('sts', region_name=REGION)
AWS_ACCOUNT = STS_CLIENT.get_caller_identity().get('Account')
        
def getKeyAlias(keyAliases, keyId):
  for key in keyAliases:
    if 'TargetKeyId' in key and key['AliasName'].startswith('alias/aws'):
      continue

    if 'TargetKeyId' in key:
      if key['TargetKeyId'] == keyId:
        return key['AliasName']
        
  return ''

def lambda_handler(event, context):
  is_compliant = True
  result_token = 'No token found.'
  annotation = ''
  compliance_resource_type = 'N/A'

  if 'resultToken' in event:
    result_token = event['resultToken']

  evaluations = []
  kms_client = boto3.client('kms')
  config_client = boto3.client('config')

  # Get a list of key aliases. This will be used to discard AWS managed keys from rotation consideration.
  aws_managed_keys = []
  keyAliases = kms_client.list_aliases()['Aliases']

  for key in keyAliases:
    if 'TargetKeyId' in key and key['AliasName'].startswith('alias/aws'):
      aws_managed_keys.append(key['TargetKeyId'])

  for key in kms_client.list_keys()['Keys']:
    # Do not evaluate AWS-managed keys.
    if not key['KeyId'] in aws_managed_keys:
      try:
        is_compliant = kms_client.get_key_rotation_status(
          KeyId=key['KeyId'])['KeyRotationEnabled']
      except:
        is_compliant = True

      keyIdentifier = ''
      kIdentifier1 = getKeyAlias(keyAliases, key['KeyId'])

      if kIdentifier1 == '':
        keyIdentifier = ' KeyId = ' + key['KeyId']
      else:
        keyIdentifier = ' Key Alias = ' + kIdentifier1

      if is_compliant:
        annotation = 'Key rotation is enabled for the specified CMK.' +  keyIdentifier
      else:
        annotation = 'Key rotation is not enabled for the specified CMK.' + keyIdentifier
      evaluations.append(
        {
          'ComplianceResourceType': 'AWS::KMS::Key',
          'ComplianceResourceId': key['KeyId'],
          'ComplianceType': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
          'Annotation': annotation,
          'OrderingTimestamp': datetime.datetime.now()
        }
      )

  response = config_client.put_evaluations(
    Evaluations=evaluations,
    ResultToken=event['resultToken']
  )

