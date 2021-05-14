import unittest
from unittest.mock import call, patch, MagicMock

from typing import Any, Dict, Optional

from qumulo_secret_rotation_lambda import *

# lambda_handler, create_secret, finish_secret are un-tested because they are directly
# derived from the AWS Secrets Manager Rotation Lambda Template on GitHub at
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/

@patch('qumulo_secret_rotation_lambda.get_secret_dict')
@patch('qumulo_secret_rotation_lambda.get_connection')
class SetSecretTest(unittest.TestCase):
    def setup_mocks(self, get_secret_dict_mock: MagicMock) -> None:
        def get_secret_dict_mocked(
            service_client: Any, arn: str, stage: str, token: str = None
        ) -> Dict[str, str]:
            if stage == 'AWSPENDING':
                return { 'username': 'admin', 'password': '123' }
            elif stage == 'AWSCURRENT':
                return { 'password': '456' }
            else:
                return { 'password': '789' }
        get_secret_dict_mock.side_effect = get_secret_dict_mocked

    def test_pending_secret_connects(
        self, get_connection_mock: MagicMock, get_secret_dict_mock: MagicMock
    ) -> None:
        self.setup_mocks(get_secret_dict_mock)
        get_connection_mock.return_value = True

        set_secret(service_client=MagicMock(), arn='arn', token='token')

        self.assertEqual(
            get_connection_mock.call_args[0][0],
            {'username': 'admin', 'password': '123'}
        )

    def test_current_secret_connects(
        self, get_connection_mock: MagicMock, get_secret_dict_mock: MagicMock
    ) -> None:
        self.setup_mocks(get_secret_dict_mock)

        mock_connection = MagicMock()
        get_connection_mock.side_effect = [False, mock_connection]

        set_secret(service_client=MagicMock(), arn='arn', token='token')

        self.assertEqual(get_connection_mock.call_args[0][0], {'password': '456'})
        self.assertEqual(mock_connection.auth.change_password.call_args[0], ('456', '123'))

    def test_previous_secret_connects(
        self, get_connection_mock: MagicMock, get_secret_dict_mock: MagicMock
    ) -> None:
        self.setup_mocks(get_secret_dict_mock)

        mock_connection = MagicMock()
        get_connection_mock.side_effect = [False, False, mock_connection]

        set_secret(service_client=MagicMock(), arn='arn', token='token')

        self.assertEqual(get_connection_mock.call_args[0][0], {'password': '789'})
        self.assertEqual(mock_connection.auth.change_password.call_args[0], ('789', '123'))

    def test_nothing_connects(
        self, get_connection_mock: MagicMock, get_secret_dict_mock: MagicMock
    ) -> None:
        get_connection_mock.return_value = False
        with self.assertRaisesRegex(ValueError, 'Unable to log into Qumulo'):
            set_secret(service_client=MagicMock(), arn='arn', token='token')

@patch('qumulo_secret_rotation_lambda.get_secret_dict')
@patch('qumulo_secret_rotation_lambda.get_connection')
class TestSecretTest(unittest.TestCase):
    def test_login_succeeds(
        self, get_connection_mock: MagicMock, get_secret_dict_mock: MagicMock
    ) -> None:
        mock_connection = MagicMock()
        get_connection_mock.return_value = mock_connection

        test_secret(service_client=MagicMock(), arn='arn', token='token')

        self.assertEqual(mock_connection.fs.read_fs_stats.call_count, 1)

    def test_login_fails(
        self, get_connection_mock: MagicMock, get_secret_dict_mock: MagicMock
    ) -> None:
        get_connection_mock.return_value = False
        with self.assertRaisesRegex(ValueError, 'Unable to log into Qumulo'):
            test_secret(service_client=MagicMock(), arn='arn', token='token')


@patch('qumulo.rest_client.RestClient')
class GetConnectionTest(unittest.TestCase):
    def test_login_succeeds(self, rest_client_mock: MagicMock) -> None:
        rest_client_mock.return_value = rest_client_mock

        secret_dict = { 'host': 'host', 'username': 'admin', 'password': '123' }
        rc = get_connection(secret_dict)

        self.assertEqual(rest_client_mock.login.call_args[0], ('admin', '123'))
        self.assertEqual(rc, rest_client_mock)

    def test_login_fails(self, rest_client_mock: MagicMock) -> None:
        rest_client_mock.return_value = rest_client_mock

        # This will fail because there is no host
        secret_dict = { 'username': 'admin', 'password': '123' }
        rc = get_connection(secret_dict)

        self.assertIsNone(rc)

class GetSecretDictTest(unittest.TestCase):
    def test_success_no_token(self) -> None:
        mock_service_client = MagicMock()
        mock_service_client.get_secret_value.return_value = {
            'SecretString': '{ "host": "host", "username": "admin", "password": "123" }'
        }
        secret_dict = get_secret_dict(mock_service_client, arn='arn', stage='AWSPENDING')
        self.assertEqual(
            secret_dict,
            { 'host': 'host', 'username': 'admin', 'password': '123' }
        )
        self.assertEqual(
            mock_service_client.get_secret_value.call_args,
            call(SecretId='arn', VersionStage='AWSPENDING')
        )


    def test_success_with_token(self) -> None:
        mock_service_client = MagicMock()
        mock_service_client.get_secret_value.return_value = {
            'SecretString': '{ "host": "host", "username": "admin", "password": "123" }'
        }
        secret_dict = get_secret_dict(mock_service_client, arn='arn', stage='AWSCURRENT', token='token')
        self.assertEqual(
            secret_dict,
            { 'host': 'host', 'username': 'admin', 'password': '123' }
        )
        self.assertEqual(
            mock_service_client.get_secret_value.call_args,
            call(SecretId='arn', VersionId='token', VersionStage='AWSCURRENT')
        )

    def test_missing_host(self) -> None:
        mock_service_client = MagicMock()
        mock_service_client.get_secret_value.return_value = {
            'SecretString': '{ "username": "admin", "password": "123" }'
        }

        with self.assertRaisesRegex(KeyError, 'host key is missing'):
            get_secret_dict(mock_service_client, arn='arn', stage='AWSPENDING')

    def test_missing_username(self) -> None:
        mock_service_client = MagicMock()
        mock_service_client.get_secret_value.return_value = {
            'SecretString': '{ "host": "host", "password": "123" }'
        }

        with self.assertRaisesRegex(KeyError, 'username key is missing'):
            get_secret_dict(mock_service_client, arn='arn', stage='AWSPENDING')

    def test_missing_password(self) -> None:
        mock_service_client = MagicMock()
        mock_service_client.get_secret_value.return_value = {
            'SecretString': '{ "host": "host", "username": "admin" }'
        }

        with self.assertRaisesRegex(KeyError, 'password key is missing'):
            get_secret_dict(mock_service_client, arn='arn', stage='AWSPENDING')

if __name__ == '__main__':
    unittest.main()
