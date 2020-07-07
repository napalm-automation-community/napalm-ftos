"""Test fixtures."""
from builtins import super

from napalm.base.test import conftest as parent_conftest
from napalm.base.test.double import BaseTestDouble

from napalm_ftos import ftos

import pytest


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = ftos.FTOSDriver
    request.cls.patched_driver = PatchedFTOSDriver
    request.cls.vendor = 'ftos'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedFTOSDriver(ftos.FTOSDriver):
    """Patched FTOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Patched FTOS Driver constructor."""
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakeFTOSDevice()

    def open(self):
        """Fake driver, don't do anything."""
        pass

    def disconnect(self):
        """Fake driver, don't do anything."""
        pass


class FakeFTOSDevice(BaseTestDouble):
    """FTOS device test double."""

    def send_command(self, command, **kwargs):
        """Fake driver, get output from file."""
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return str(result)

    def disconnect(self):
        """Fake driver, don't do anything."""
        pass

    def run_commands(self, command_list, encoding='json'):
        """Fake run_commands."""
        result = list()

        for command in command_list:
            filename = '{}.{}'.format(self.sanitize_text(command), encoding)
            full_path = self.find_file(filename)

            if encoding == 'json':
                result.append(self.read_json_file(full_path))
            else:
                result.append({'output': self.read_txt_file(full_path)})

        return result
