import os
import json
import unittest
from unittest.mock import call, patch, MagicMock

from typing import Any, Dict, Optional

from troposphere import Template

from generate_qumulo_cloudformation_template import *

@patch('troposphere.ec2.EBSBlockDevice')
class ChassisSpecTest(unittest.TestCase):
    def test_init(self, mock_ebs_block_device: MagicMock) -> None:
        spec = ChassisSpec(
            volume_count=20,
            pairing_ratio=4,
            working_spec={'VolumeSize': 1},
            backing_spec={'VolumeSize': 5},
        )
        self.assertEqual(spec.working_volume_count, 4)
        self.assertEqual(spec.backing_volume_count, 16)

    def test_init_no_backing_spec(self, mock_ebs_block_device: MagicMock) -> None:
        spec = ChassisSpec(
            volume_count=5,
            pairing_ratio=0,
            working_spec={'VolumeSize': 1},
            backing_spec=None,
        )
        self.assertEqual(spec.working_volume_count, 5)
        self.assertEqual(spec.backing_volume_count, 0)

    def test_init_too_many_volumes(self, mock_ebs_block_device: MagicMock) -> None:
        with self.assertRaisesRegex(AssertionError, 'Too many volumes specified'):
            ChassisSpec(
                volume_count=26,
                pairing_ratio=0,
                working_spec={'VolumeSize': 1},
                backing_spec={'VolumeSize': 5},
            )


    def test_init_bad_pairing_ratio(self, mock_ebs_block_device: MagicMock) -> None:
        with self.assertRaisesRegex(AssertionError, 'Not all volumes can be used'):
            ChassisSpec(
                volume_count=10,
                pairing_ratio=3,
                working_spec={'VolumeSize': 1},
                backing_spec={'VolumeSize': 3},
            )


    def test_init_need_backing_spec(self, mock_ebs_block_device: MagicMock) -> None:
        with self.assertRaisesRegex(AssertionError, 'Backing volumes require'):
            ChassisSpec(
                volume_count=10,
                pairing_ratio=1,
                working_spec={'VolumeSize': 1},
                backing_spec=None,
            )

    def test_from_json(self, mock_ebs_block_device: MagicMock) -> None:
        json_spec = {
            'slot_count': 12,
            'pairing_ratio': 2,
            'working_spec': {'VolumeSize': 1},
            'backing_spec': {'VolumeSize': 5}
        }
        spec = ChassisSpec.from_json(json_spec)
        self.assertEqual(spec.working_volume_count, 4)
        self.assertEqual(spec.backing_volume_count, 8)

    @patch('troposphere.ec2.BlockDeviceMapping')
    def test_get_block_device_mappings(
        self, mock_ebs_block_device: MagicMock, mock_ebs_block_device_mapping: MagicMock
    ) -> None:
        def make_block_device_mapping(DeviceName, Ebs):
            return { DeviceName: Ebs}
        mock_ebs_block_device.side_effect = make_block_device_mapping

        spec = ChassisSpec(
            volume_count=2,
            pairing_ratio=1,
            working_spec={'VolumeSize': 1},
            backing_spec={'VolumeSize': 5},
        )
        mappings = spec.get_block_device_mappings()

        self.assertEqual(len(mappings), 3)
        devices = [list(mapping.keys())[0] for mapping in mappings]
        self.assertEqual(devices, ['/dev/sda1', '/dev/xvdb', '/dev/xvdc'])
        
    def test_get_slot_specs(self, mock_ebs_block_device: MagicMock) -> None:
        spec = ChassisSpec(
            volume_count=2,
            pairing_ratio=1,
            working_spec={'VolumeSize': 1},
            backing_spec={'VolumeSize': 5},
        )

        slot_specs = spec.get_slot_specs()
        expected_specs = [
            {
                'drive_bay': '/dev/xvdb',
                'disk_role': 'working',
                'disk_size': 1073741824,
            },
            {
                'drive_bay': '/dev/xvdc',
                'disk_role': 'backing',
                'disk_size': 5368709120,
            }
        ]
        self.assertEqual(slot_specs['slot_specs'], expected_specs)

class TemplateTest(unittest.TestCase):
    def test_add_conditions(self) -> None:
        template = Template()
        add_conditions(template)
        self.assertEqual(
            list(template.conditions.keys()),
            ['HasEncryptionKey', 'HasIamInstanceProfile', 'HasInstanceRecoveryTopic']
        )

    def test_add_params_with_ingress_cidr_param(self) -> None:
        template = Template()
        add_params(template, True)
        expected_parameters = [
            'ClusterName', 'KeyName', 'InstanceType', 'VpcId', 'SubnetId', 'SgCidr',
            'VolumesEncryptionKey', 'IamInstanceProfile', 'InstanceRecoveryTopic'
        ]
        self.assertEqual(list(template.parameters.keys()), expected_parameters)

    def test_add_params_without_ingress_cidr_param(self) -> None:
        template = Template()
        add_params(template, False)
        expected_parameters = [
            'ClusterName', 'KeyName', 'InstanceType', 'VpcId', 'SubnetId',
            'VolumesEncryptionKey', 'IamInstanceProfile', 'InstanceRecoveryTopic'
        ]
        self.assertEqual(list(template.parameters.keys()), expected_parameters)

    def test_add_ami_map(self) -> None:
        template = Template()
        add_ami_map(template, 'ami-1234')
        expected_mapping = {
            'us-east-1': {'AMI': 'ami-1234'},
            'us-east-2': {'AMI': 'ami-1234'},
            'us-west-1': {'AMI': 'ami-1234'},
            'us-west-2': {'AMI': 'ami-1234'},
            'ca-central-1': {'AMI': 'ami-1234'},
            'eu-central-1': {'AMI': 'ami-1234'},
            'eu-west-1': {'AMI': 'ami-1234'},
            'eu-west-2': {'AMI': 'ami-1234'},
            'eu-west-3': {'AMI': 'ami-1234'},
        }
        self.assertEqual(template.mappings['RegionMap'], expected_mapping)

    def test_add_security_group(self) -> None:
        template = Template()
        add_security_group(template)
        self.assertEqual(
            list(template.resources.keys()),
            ['QumuloSecurityGroup', 'QumuloSecurityGroupNodeRule']
        )

class GenerateUserDataTest(unittest.TestCase):
    def test_generate_node1_user_data(self) -> None:
        instance1 = MagicMock()
        instance1.title = 't1'
        instance2 = MagicMock()
        instance2.title = 't2'
        instances = [instance1, instance2]

        spec = ChassisSpec(
            volume_count=2,
            pairing_ratio=1,
            working_spec={'VolumeSize': 1},
            backing_spec={'VolumeSize': 5},
        )
        user_data = generate_node1_user_data(
            instances, spec, get_ip_ref=lambda x: x, cluster_name_ref='nameref'
        )

        self.assertIn('t2', user_data)
        self.assertIn('nameref', user_data)
        self.assertIn('"spec_info": ', user_data)
        self.assertIn('    "slot_specs": [', user_data)

    def test_generate_other_nodes_user_data(self) -> None:
        spec = ChassisSpec(
            volume_count=2,
            pairing_ratio=1,
            working_spec={'VolumeSize': 1},
            backing_spec={'VolumeSize': 5},
        )
        user_data = generate_other_nodes_user_data(spec)

        self.assertIn('"spec_info": ', user_data)
        self.assertIn('    "slot_specs": [', user_data)

class AddNodesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = ChassisSpec(
            volume_count=2,
            pairing_ratio=1,
            working_spec={'VolumeSize': 1},
            backing_spec={'VolumeSize': 5},
        )
        self.expected_resources = [
            'testEni1',
            'testEni2',
            'testNode1',
            'testNode2',
            'CWRecoveryAlarmtestNode1',
            'CWRecoveryAlarmtestNode2'
        ]
        self.expected_outputs = [
            'ClusterInstanceIDs',
            'ClusterPrivateIPs',
            'SecurityGroup',
            'TemporaryPassword',
            'LinkToManagement',
            'QumuloKnowledgeBase'
        ]

    def test_nodes_no_secondary_ips(self) -> None:
        template = Template()
        add_nodes(template, 2, 'test', self.spec, 0, 'sg-9')

        self.assertEqual(list(template.resources.keys()), self.expected_resources)
        self.assertEqual(list(template.outputs.keys()), self.expected_outputs)

    def test_nodes_has_secondary_ips(self) -> None:
        template = Template()
        add_nodes(template, 2, 'test', self.spec, 1, 'sg-9')

        self.assertEqual(list(template.resources.keys()), self.expected_resources)

        self.expected_outputs.insert(2, 'ClusterSecondaryPrivateIPs')
        self.assertEqual(list(template.outputs.keys()), self.expected_outputs)

class GenerateQumuloCloudformationTemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.file_path = os.path.join(os.getcwd(), 'config_file.json')

    def tearDown(self) -> None:
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def test_generate_qcft_with_override(self) -> None:
        config = {
            'slot_count': 12,
            'pairing_ratio': 2,
            'working_spec': {'VolumeSize': 1},
            'backing_spec': {'VolumeSize': 5}
        }
        json_config = json.dumps(config, indent = 4)
        with open(self.file_path, 'w+') as config_file:
            config_file.write(json_config)

        template = generate_qcft(2, self.file_path, 'st1', 'ami-123')
        self.assertIsNotNone(template)

    def test_generate_qcft_no_override(self) -> None:
        config = {
            'slot_count': 12,
            'pairing_ratio': 2,
            'working_spec': {'VolumeSize': 1},
            'backing_spec': {'VolumeSize': 5}
        }
        json_config = json.dumps(config, indent = 4)
        with open(self.file_path, 'w+') as config_file:
            config_file.write(json_config)

        template = generate_qcft(2, self.file_path, None, 'ami-123')
        self.assertIsNotNone(template)
    

    def test_generate_qcft_bad_override(self) -> None:
        config = {
            'slot_count': 12,
            'pairing_ratio': 2,
            'working_spec': {'VolumeSize': 1},
        }
        json_config = json.dumps(config, indent = 4)
        with open(self.file_path, 'w+') as config_file:
            config_file.write(json_config)

        with self.assertRaisesRegex(NoBackingVolumesException, 'The backing volumes'):
            generate_qcft(2, self.file_path, 'st1', 'ami-123')

