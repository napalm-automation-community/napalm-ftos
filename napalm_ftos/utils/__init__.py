"""napalm_ftos.utils package."""

import re

from napalm.base.helpers import canonical_interface_name as can_iface_name

# Easier to store these as constants
MINUTE_SECONDS = 60
HOUR_SECONDS = 60 * MINUTE_SECONDS
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


# overload canonical_interface_name and apply some FTOS specifics
def canonical_interface_name(iface):
    """Convert an interface's name into a fully expanded name with a little bit of FTOS sauce."""
    # all interfaces in base.canonical_map.base_interfaces are capitalized
    # so to make sure we match those names, we capitalize the name before running
    # it against that map
    # just using capitalize would be too easy, because then the first letter is
    # the only uppercase letter
    if len(iface) > 0:
        iface = iface[:1].upper() + iface[1:]

    # run it against the original map
    iface = can_iface_name(iface)

    # add whitespace in *GigabitEthernet names
    m = re.search(r'^((?:Forty|Ten)GigabitEthernet)(\d+\/\d+)$', iface)
    if m:
        iface = ' '.join(m.groups())

    return iface


def _parse_uptime_short(uptime_str):
    # until a day has passed, time is expressed in hh:mm:ss
    # after a day, time is expressed as 1d22h23m or even 20w4d21h
    # perhaps even in years at some point

    match = re.compile(r'^(\d+):(\d+):(\d+)$').search(uptime_str)
    if match:
        return (0, 0, 0, int(match.group(1)), int(match.group(2)), int(match.group(3)))

    # Initialize to zero
    (years, weeks, days, hours, minutes, seconds) = (0,) * 6

    match = re.compile(r'(\d+w)?(\d+d)?(\d+h)?(\d+m)?').search(uptime_str)
    for m in match.groups():
        if m is None:
            continue
        # year
        elif m.endswith('y'):
            years = int(m[:-1])
        # week
        elif m.endswith('w'):
            weeks = int(m[:-1])
        # day
        elif m.endswith('d'):
            days = int(m[:-1])
        # hour
        elif m.endswith('h'):
            hours = int(m[:-1])
        # minute
        elif m.endswith('m'):
            minutes = int(m[:-1])

    return (years, weeks, days, hours, minutes, seconds)


def parse_uptime(uptime_str, short=False):
    """Extract uptime from string, given in various forms."""
    # Extract the uptime string from the given FTOS Device given in form of
    # 32 week(s), 6 day(s), 10 hour(s), 39 minute(s).
    #
    # When short is set to True, expect the format to be either hh:mm:ss or
    # in form 32w6d10h.
    #
    # Return the uptime in seconds as an integer.

    # Initialize to zero
    (years, weeks, days, hours, minutes, seconds) = (0,) * 6

    uptime_str = uptime_str.strip()

    if short:
        (years, weeks, days, hours, minutes, seconds) = _parse_uptime_short(uptime_str)
    else:
        # in longer format, uptime is expressed in form of
        # 32 week(s), 6 day(s), 10 hour(s), 39 minute(s)
        time_list = uptime_str.split(', ')
        for element in time_list:
            if re.search(r"year", element):
                years = int(element.split()[0])
            elif re.search(r"w(ee)?k", element):
                weeks = int(element.split()[0])
            elif re.search(r"day", element):
                days = int(element.split()[0])
            elif re.search(r"h(ou)?r", element):
                hours = int(element.split()[0])
            elif re.search(r"min(ute)?", element):
                minutes = int(element.split()[0])

    return (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + \
           (days * DAY_SECONDS) + (hours * HOUR_SECONDS) + \
           (minutes * MINUTE_SECONDS) + seconds


def transform_lldp_capab(capabilities):
    """Transform FTOS LLDP capabilities into Napalm generic capabilities."""
    modes = [
        ['Repeater', 'repeater'],
        ['Bridge', 'bridge'],
        ['WLAN Access Point', 'wlan-access-point'],
        ['Router', 'router'],
        ['Telephone', 'telephone'],
        ['Docsis', 'docsis-cable-device'],
        ['Station only', 'station'],
        ['Other', 'other']
    ]

    capab = []

    # go over each mode and see if it's present
    while len(capabilities):
        found = False
        for mode in modes:
            if re.search('^%s' % mode[0], capabilities, re.IGNORECASE):
                capab.append(mode[1])
                capabilities = re.sub(r'^%s\s*' % mode[0], '', capabilities, re.IGNORECASE)
                found = True

        if not found:
            raise Exception('unhandled lldp capability: %s' % capabilities.strip().split(' ')[0])

    return capab


def prep_addr(addr, iface, prot=u'ipv4'):
    """Ensure specific structure for IP address dict."""
    if iface not in addr:
        addr[iface] = {}
    if prot not in addr[iface]:
        addr[iface][prot] = {}
    return addr
