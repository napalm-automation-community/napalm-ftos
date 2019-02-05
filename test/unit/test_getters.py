"""Tests for getters."""

import pytest

from napalm.base.test.getters import BaseTestGetters
from napalm.base.test.getters import wrap_test_cases
from napalm.base.test import helpers
from napalm.base.test import models


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        """Test get_arp_table."""
        arp_table = self.device.get_arp_table()

        assert len(arp_table) > 0
        for entry in arp_table:
            assert helpers.test_model(models.arp_table, entry)

        return arp_table
