# MIT License
#
# Copyright (c) 2019 Qumulo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# qumulo_python_versions = { 2 }

# derived from AWS Secrets Manager Rotation Lambda Template on GitHub at
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/

import json
import logging
import os

import boto3

from qumulo.rest_client import RestClient

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, _context):
    """Qumulo Secrets Manager Rotation Template

    This is a sample for creating a AWS Secrets Manager rotation lambda
    for Qumulo clusters.

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must
        include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret,
              testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the secretsmanager service client
    service_client = boto3.client(
        'secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT']
    )

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error('Secret {} is not enabled for rotation'.format(arn))
        raise ValueError('Secret {} is not enabled for rotation'.format(arn))

    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(
            'Secret version {} has no stage for rotation of secret {}.'
            ''.format(token, arn)
        )
        raise ValueError(
            'Secret version {} has no stage for rotation of secret {}.'
            ''.format(token, arn)
        )

    if 'AWSCURRENT' in versions[token]:
        logger.info(
            'Secret version {} already set as AWSCURRENT for secret {}.'
            ''.format(token, arn)
        )
        return

    elif 'AWSPENDING' not in versions[token]:
        logger.error(
            'Secret version {} not set as AWSPENDING for rotation of secret {}.'
            ''.format(token, arn)
        )
        raise ValueError(
            'Secret version {} not set as AWSPENDING for rotation of secret {}.'
            ''.format(token, arn)
        )

    if step == 'createSecret':
        create_secret(service_client, arn, token)

    elif step == 'setSecret':
        set_secret(service_client, arn, token)

    elif step == 'testSecret':
        test_secret(service_client, arn, token)

    elif step == 'finishSecret':
        finish_secret(service_client, arn, token)

    else:
        raise ValueError('Invalid step parameter')


def create_secret(service_client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in
    token. If one does not exist, it will generate a new secret and put it with
    the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret
        version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist
    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, 'AWSCURRENT')

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(service_client, arn, 'AWSPENDING')
        logger.info('createSecret: Successfully retrieved secret for {}.'.format(arn))
    except service_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        passwd = service_client.get_random_password(ExcludeCharacters="/@\"'\\")
        current_dict['password'] = passwd['RandomPassword']
        new_secret = json.dumps(current_dict)

        # Put the secret
        service_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=new_secret,
            VersionStages=['AWSPENDING'],
        )
        logger.info(
            'createSecret: Successfully put secret for ARN {} and version {}.'
            ''.format(arn, token)
        )


def set_secret(service_client, arn, token):
    """Set the secret

    This method sets the Qumulo cluster's admin password to the secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret
        version
    """
    # First try to login with the pending secret, if it succeeds, return
    pending_dict = get_secret_dict(service_client, arn, 'AWSPENDING', token)
    conn = get_connection(pending_dict)

    if conn:
        logger.info(
            'setSecret: AWSPENDING secret is already set as password on '
            'Qumulo cluster for secret arn {}.'.format(arn)
        )
        return

    # Now try the current password
    current_dict = get_secret_dict(service_client, arn, 'AWSCURRENT')
    current_password = current_dict['password']
    conn = get_connection(current_dict)
    if not conn:
        # If both current and pending do not work, try previous
        try:
            previous_dict = get_secret_dict(service_client, arn, 'AWSPREVIOUS')
            current_password = previous_dict['password']
            conn = get_connection(previous_dict)
        except service_client.exceptions.ResourceNotFoundException:
            conn = None

    # If we still don't have a connection, raise a ValueError
    if not conn:
        logger.error(
            'setSecret: Unable to log into Qumulo with previous, current, or '
            'pending secret of secret arn {}'.format(arn)
        )
        raise ValueError(
            'Unable to log into Qumulo with previous, current, or pending '
            'secret of secret arn {}'.format(arn)
        )

    # Now set the password to the pending password
    resp = conn.auth.change_password(current_password, pending_dict['password'])
    logger.info('setSecret: {}'.format(resp))
    logger.info(
        'setSecret: Successfully set password for user {} in Qumulo for secret'
        ' arn {}.'.format(pending_dict['username'], arn)
    )


def test_secret(service_client, arn, token):
    """Test the secret

    This method validates that the user can login to the Qumulo cluster with the
    password in AWSPENDING.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret
        version
    """
    # Try to login with the pending secret, if it succeeds, return
    conn = get_connection(get_secret_dict(service_client, arn, 'AWSPENDING', token))

    if conn:
        # Validate that the Qumulo API can be queried.
        conn.fs.read_fs_stats()

        logger.info(
            'testSecret: Successfully signed into Qumulo with AWSPENDING '
            'secret in {}.'.format(arn)
        )
        return

    else:
        logger.error(
            'testSecret: Unable to log into Qumulo with pending secret of '
            'secret ARN {}'.format(arn)
        )
        raise ValueError(
            'Unable to log into Qumulo with pending secret of '
            'secret ARN {}'.format(arn)
        )


def finish_secret(service_client, arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version
    passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret
        version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not
        exist
    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata['VersionIdsToStages']:
        if 'AWSCURRENT' in metadata['VersionIdsToStages'][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    'finishSecret: Version {} already marked as AWSCURRENT '
                    'for {}'.format(version, arn)
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage='AWSCURRENT',
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        'finishSecret: Successfully set AWSCURRENT stage to version {} for '
        'secret {}.'.format(current_version, arn)
    )


def get_connection(secret_dict):
    """
    Create Qumulo REST client. Return None if unable to log into the cluster.
    """
    try:
        # Log into Qumulo cluster using the host specified in the secret.
        rc = RestClient(secret_dict['host'], 8000)
        rc.login(secret_dict['username'], secret_dict['password'])
        return rc
    except Exception as e:
        logger.info('get_connection: {}'.format(e))
        return None


def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and
    token

    This helper function gets credentials for the arn and stage passed in and
    returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        stage (string): The stage identifying the secret version
        token (string): The ClientRequestToken associated with the secret
        version, or None if no validation is desired

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist
        ValueError: If the secret is not valid JSON
    """
    required_fields = ['host', 'username', 'password']

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage=stage
        )
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)

    plaintext = secret['SecretString']
    try:
        secret_dict = json.loads(plaintext)
    except Exception as e:
        raise Exception('get_secret_dict: {}, {}'.format(plaintext, e))

    # Run validations against the secret
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError('{} key is missing from secret JSON'.format(field))

    # Parse and return the secret JSON string
    return secret_dict
