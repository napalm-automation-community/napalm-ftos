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
    def test_get_config_filtered(self, test_case):
        """Test get_config method."""
        for config in ['running', 'startup', 'candidate']:
            get_config = self.device.get_config(retrieve=config)

            # FTOS doesn't have candidate config
            #assert get_config['candidate'] == "" if config != "candidate" else True
            assert get_config['startup'] == "" if config != "startup" else True
            assert get_config['running'] == "" if config != "running" else True

        return get_config
