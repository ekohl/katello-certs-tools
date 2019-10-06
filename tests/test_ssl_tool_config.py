from textwrap import dedent

import pytest

from katello_certs_tools.sslToolConfig import gen_req_alt_names, gen_req_distinguished_name


@pytest.mark.parametrize('hostname,cnames,expected', [
    ('h.example.com', None, 'DNS.1 = h.example.com\n'),
    ('h.example.com', [], 'DNS.1 = h.example.com\n'),
    ('h.example.com', ['alt.example.com'], 'DNS.1 = h.example.com\nDNS.2 = alt.example.com\n'),
])
def test_gen_req_alt_names(hostname, cnames, expected):
    assert gen_req_alt_names(hostname, cnames) == expected


@pytest.mark.parametrize('parameters,expected', [
    (
        {},
        """\
        #C                       = ""
        #ST                      = ""
        #L                       = ""
        #O                       = ""
        #OU                      = ""
        #CN                      = ""
        #emailAddress            = ""
        """
    ),
    (
        {'ignored': 'value'},
        """\
        #C                       = ""
        #ST                      = ""
        #L                       = ""
        #O                       = ""
        #OU                      = ""
        #CN                      = ""
        #emailAddress            = ""
        """
    ),
    (
        {'CN': 'host.example.com', 'C': 'NL', 'emailAddress': 'hostmaster@example.com'},
        """\
        C                       = NL
        #ST                      = ""
        #L                       = ""
        #O                       = ""
        #OU                      = ""
        CN                      = host.example.com
        emailAddress            = hostmaster@example.com
        """
    ),
])
def test_gen_req_distinguished_name(parameters, expected):
    assert gen_req_distinguished_name(parameters) == dedent(expected)
