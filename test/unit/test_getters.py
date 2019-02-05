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
    def test__parse_uptime(self, test_case):
        """Test _parse_uptime."""

        tests = [
            ['32w4d3h', 19710000, True],
            ['1w13d3h', 1738800, True],
            ['04:12:34', 15154, True],
            ['12:34:56', 45296, True],
            ['32 wk, 4 day, 3 hr, 4 min', 19710240, False],
            ['32 wk, 4 day, 3 hr, 4 min', 19710240, False],
            ['32 week(s), 4 day(s), 3 hour(s), 4 minute(s)', 19710240, False],
        ]

        for t in tests:
            out = self.device._parse_uptime(t[0], t[2])
            assert out == t[1]

        return {}

    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        """Test get_arp_table."""
        arp_table = self.device.get_arp_table()

        assert len(arp_table) > 0
        for entry in arp_table:
            assert helpers.test_model(models.arp_table, entry)

        return arp_table

    @wrap_test_cases
    def test_get_facts(self, test_case):
        """Test get_facts."""
        facts = self.device.get_facts()

        assert helpers.test_model(models.facts, facts)

        return facts

    @wrap_test_cases
    def test_get_lldp_neighbors(self, test_case):
        """Test get_lldp_neighbors."""

        neighbors = self.device.get_lldp_neighbors()

        for iface in neighbors.values():
            for neighbor in iface:
                assert helpers.test_model(models.lldp_neighbors, neighbor)

        return neighbors

    @wrap_test_cases
    def test_get_lldp_neighbors_detail(self, test_case):
        """Test get_lldp_neighbors_detail."""
        if test_case == 'normal':
            neighbors = self.device.get_lldp_neighbors_detail()
        else:
            iface = test_case.replace('__', '/').replace('_', ' ')
            neighbors = self.device.get_lldp_neighbors_detail(iface)

        for iface in neighbors.values():
            for neighbor in iface:
                assert helpers.test_model(models.lldp_neighbors_detail, neighbor)

        return neighbors

    @wrap_test_cases
    def test_get_mac_address_table(self, test_case):
        """Test get_mac_address_table."""
        mac_table = self.device.get_mac_address_table()

        for mac in mac_table:
            assert helpers.test_model(models.mac_address_table, mac)

        return mac_table

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""
        interfaces = self.device.get_interfaces()

        for iface in interfaces.values():
            assert helpers.test_model(models.interface, iface)

        return interfaces

    @wrap_test_cases
    def test_get_interfaces_counters(self, test_case):
        """Test get_interfaces_counters."""
        counters = self.device.get_interfaces_counters()

        for iface in counters.values():
            assert helpers.test_model(models.interface_counters, iface)

        return counters
