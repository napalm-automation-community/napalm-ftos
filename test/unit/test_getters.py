"""Tests for getters."""

import pytest

from napalm.base.test.getters import BaseTestGetters
from napalm.base.test.getters import wrap_test_cases

from napalm_ftos.utils import (
    canonical_interface_name,
    parse_uptime,
    transform_lldp_capab,
    prep_addr
)


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    @wrap_test_cases
    def test_canonical_interface_name(self, test_case):
        """Test canonical_interface_name."""
        tests = [
            ['Te 0/1', 'TenGigabitEthernet 0/1'],
            ['Te0/2', 'TenGigabitEthernet 0/2'],
            ['fortyGig 0/33', 'FortyGigabitEthernet 0/33'],
            ['fortyGig0/37', 'FortyGigabitEthernet 0/37'],
        ]

        for t in tests:
            out = canonical_interface_name(t[0])
            assert out == t[1]

        return {}

    @wrap_test_cases
    def test_parse_uptime(self, test_case):
        """Test parse_uptime."""
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
            out = parse_uptime(t[0], t[2])
            assert out == t[1]

        return {}

    @wrap_test_cases
    def test_transform_lldp_capab(self, test_case):
        """Test transform_lldp_capab."""
        tests = [
            ['Bridge WLAN Access Point Router Station only', [
                'bridge', 'wlan-access-point', 'router', 'station',
            ]],
            ['Bridge Router', ['bridge', 'router']],
        ]

        for t in tests:
            out = transform_lldp_capab(t[0])
            assert out == t[1]

        return {}

    @wrap_test_cases
    def test_prep_addr(self, test_case):
        """Test prep_addr."""
        tests = [
            ['eth0', 'ipv4', {'eth0': {'ipv4': {}}}],
            ['eth1', 'ipv6', {'eth1': {'ipv6': {}}}],
        ]

        for t in tests:
            out = prep_addr({}, t[0], t[1])
            assert out == t[2]

        return {}

    @wrap_test_cases
    def test_get_config_filtered(self, test_case):
        """Test get_config method."""
        for config in ['running', 'startup', 'candidate']:
            get_config = self.device.get_config(retrieve=config)

            # FTOS doesn't have candidate config
            # assert get_config['candidate'] == "" if config != "candidate" else True
            assert get_config['startup'] == "" if config != "startup" else True
            assert get_config['running'] == "" if config != "running" else True

        return get_config

    @wrap_test_cases
    def test_is_alive(self, test_case):
        """There is little to test with this function."""
        raise NotImplementedError
