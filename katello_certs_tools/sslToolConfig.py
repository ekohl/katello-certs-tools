#
# Copyright 2013 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#
#
# katello-ssl-tool openssl.cnf style file manipulation class

# FIXME: the logic here is *WAY* too complicated. Need to simplify -taw
from __future__ import print_function

# language imports
import os
import sys
import copy
import time
import socket
import subprocess

# local imports
from katello_certs_tools.fileutils import cleanupNormPath, rotateFile, cleanupAbsPath
from katello_certs_tools.sslToolLib import daysTil18Jan2038, format_serial


# defaults where we can see them (NOTE: directory is figured at write time)
CERT_PATH = '/etc/pki/katello-certs-tools'
BUILD_DIR = cleanupNormPath('./ssl-build', dotYN=1)
HOSTNAME = socket.gethostname()
MACHINENAME = HOSTNAME

CA_KEY_NAME = 'KATELLO-PRIVATE-SSL-KEY'
CA_CRT_NAME = 'KATELLO-TRUSTED-SSL-CERT'
CA_CRT_RPM_NAME = CA_CRT_NAME.lower()

BASE_SERVER_RPM_NAME = 'katello-httpd-ssl-key-pair'
BASE_SERVER_TAR_NAME = 'katello-httpd-ssl-archive'

CA_OPENSSL_CNF_NAME = 'katello-ca-openssl.cnf'
SERVER_OPENSSL_CNF_NAME = 'katello-server-openssl.cnf'

MD = 'sha256'
CRYPTO = '-des3'


def getOption(options, opt):
    """ fetch the value of an options object item
        without blowing up upon obvious errors
    """
    assert opt.find('-') == -1
    if not options:
        return None
    if opt in options.__dict__:
        return options.__dict__[opt]
    else:
        return None


def setOption(options, opt, value):
    """ set the value of an options object item
        without blowing up upon obvious errors
    """
    if not options:
        return
    if opt in options.__dict__:
        options.__dict__[opt] = value


def getStartDate_aWeekAgo():
    """ for SSL cert/key generation, returns now, minus 1 week
        just in case weird time zone issues get in the way of a working
        cert/key.

        format: YYMMDDHHMMSSZ where Z is the capital letter Z
    """
    aweek = 24*60*60*7
    return time.strftime("%y%m%d%H%M%S", time.gmtime(time.time()-aweek)) + 'Z'


_defs = \
    {
        '--dir': BUILD_DIR,
        '--ca-key': 'KATELLO-PRIVATE-SSL-KEY',
        '--ca-cert': 'KATELLO-TRUSTED-SSL-CERT',
        '--ca-cert-dir': CERT_PATH,
        '--other-ca-certs': None,
        '--cert-expiration': int(daysTil18Jan2038()),
        '--startdate': getStartDate_aWeekAgo(),

        '--server-key': 'server.key',
        '--server-cert-req': 'server.csr',
        '--server-cert': 'server.crt',
        '--server-cert-dir': CERT_PATH,

        '--set-country': 'US',
        '--set-common-name': "",     # these two will never appear
        '--set-hostname': HOSTNAME,  # at the same time on the CLI

        '--ca-cert-rpm': CA_CRT_RPM_NAME,
        '--server-rpm': BASE_SERVER_RPM_NAME+'-'+MACHINENAME,
        '--server-tar': BASE_SERVER_TAR_NAME+'-'+MACHINENAME,
        '--rpm-packager': None,
        '--rpm-vendor': None,
    }

_defsCa = copy.copy(_defs)
_defsCa.update(
    {
        '--set-state': '',
        '--set-city': '',
        '--set-org': '',
        '--set-org-unit': '',
        '--set-email': '',
    })


_defsServer = copy.copy(_defs)
_defsServer.update(
    {
        '--set-state': 'North Carolina',
        '--set-city': 'Raleigh',
        '--set-org': 'Example Corp. Inc.',
        '--set-org-unit': 'unit',
        '--set-email': 'admin@example.com',
    })

DEFS = _defsServer


def reInitDEFS(caYN=0):
    if caYN:
        DEFS.update(_defsCa)
    else:
        DEFS.update(_defsServer)


def figureDEFS_dirs(options):
    """ figure out the directory defaults (after options being at least parsed
        once).
    """

    # fix up the --dir setting
    DEFS['--dir'] = getOption(options, 'dir') or DEFS['--dir'] or '.'
    DEFS['--dir'] = cleanupNormPath(DEFS['--dir'], dotYN=1)

    # fix up the --set-hostname and MACHINENAME settings
    DEFS['--set-hostname'] = getOption(options, 'set_hostname') \
        or DEFS['--set-hostname'] \
        or socket.gethostname()

    global MACHINENAME
    MACHINENAME = DEFS['--set-hostname']

    # remap to options object
    setOption(options, 'dir', DEFS['--dir'])
    setOption(options, 'set_hostname', DEFS['--set-hostname'])


def figureDEFS_CA(options):
    """ figure out the defaults (after options being at least parsed once) for
        the CA key-pair(set) variables.
    """

    if not getOption(options, 'ca_key'):
        # the various default names for CA keys (a hierarchy)
        for possibility in (CA_KEY_NAME, 'ca.key', 'cakey.pem'):
            if os.path.exists(os.path.join(DEFS['--dir'], possibility)):
                DEFS['--ca-key'] = possibility
                break

    DEFS['--ca-key'] = os.path.basename(getOption(options, 'ca_key') or DEFS['--ca-key'])
    DEFS['--ca-cert'] = os.path.basename(getOption(options, 'ca_cert') or DEFS['--ca-cert'])
    DEFS['--ca-cert-dir'] = getOption(options, 'ca_cert_dir') or DEFS['--ca-cert-dir']
    DEFS['--other-ca-certs'] = getOption(options, 'other_ca_certs') or DEFS['--other-ca-certs']

    # the various default names for CA keys and certs
    if not getOption(options, 'ca_cert'):
        if DEFS['--ca-key'] == CA_KEY_NAME:
            DEFS['--ca-cert'] = CA_CRT_NAME
        elif DEFS['--ca-key'] == 'ca.key':
            DEFS['--ca-cert'] = 'ca.crt'
        elif DEFS['--ca-key'] == 'cakey.pem':
            DEFS['--ca-cert'] = 'cacert.pem'
        else:
            DEFS['--ca-cert'] = 'ca.crt'

    DEFS['--cert-expiration'] = getOption(options, 'cert_expiration') \
        or int(daysTil18Jan2038())
    DEFS['--ca-cert-rpm'] = getOption(options, 'ca_cert_rpm') \
        or CA_CRT_RPM_NAME

    DEFS['--rpm-packager'] = getOption(options, 'rpm_packager')
    DEFS['--rpm-vendor'] = getOption(options, 'rpm_vendor')

    if '--cert-expiration' in DEFS:
        # nothing under 1 day or over # days til 18Jan2038
        if DEFS['--cert-expiration'] < 1:
            DEFS['--cert-expiration'] = 1
        _maxdays = int(daysTil18Jan2038())  # already rounded
        if DEFS['--cert-expiration'] > _maxdays:
            DEFS['--cert-expiration'] = _maxdays

    # remap to options object
    setOption(options, 'ca_key', DEFS['--ca-key'])
    setOption(options, 'ca_cert', DEFS['--ca-cert'])
    setOption(options, 'ca_cert_dir', DEFS['--ca-cert-dir'])
    setOption(options, 'cert_expiration', DEFS['--cert-expiration'])
    setOption(options, 'ca_cert_rpm', DEFS['--ca-cert-rpm'])
    setOption(options, 'other_ca_certs', DEFS['--other-ca-certs'])


def figureDEFS_server(options):
    """ figure out the defaults (after options being at least parsed once) for
        the server key-pair(set) variables.
    """

    DEFS['--server-key'] = os.path.basename(getOption(options, 'server_key')
                                            or DEFS['--server-key'] or 'server.key')
    DEFS['--server-cert-req'] = os.path.basename(getOption(options, 'server_cert_req')
                                                 or DEFS['--server-cert-req'] or 'server.csr')
    DEFS['--server-cert'] = os.path.basename(getOption(options, 'server_cert')
                                             or DEFS['--server-cert'] or 'server.crt')
    DEFS['--cert-expiration'] = getOption(options, 'cert_expiration') \
        or int(daysTil18Jan2038())  # already rounded
    DEFS['--server-rpm'] = getOption(options, 'server_rpm') \
        or BASE_SERVER_RPM_NAME+'-'+MACHINENAME
    DEFS['--server-tar'] = getOption(options, 'server_tar') \
        or BASE_SERVER_TAR_NAME+'-'+MACHINENAME
    DEFS['--server-cert-dir'] = getOption(options, 'server_cert_dir') or DEFS['--server-cert-dir']

    DEFS['--rpm-packager'] = getOption(options, 'rpm_packager')
    DEFS['--rpm-vendor'] = getOption(options, 'rpm_vendor')

    if '--cert-expiration' in DEFS:
        # nothing under 1 day or over # days til 18Jan2038
        if DEFS['--cert-expiration'] < 1:
            DEFS['--cert-expiration'] = 1
        _maxdays = int(daysTil18Jan2038())  # already rounded
        if DEFS['--cert-expiration'] > _maxdays:
            DEFS['--cert-expiration'] = _maxdays

    # remap to options object
    setOption(options, 'server_key', DEFS['--server-key'])
    setOption(options, 'server_cert_req', DEFS['--server-cert-req'])
    setOption(options, 'server_cert', DEFS['--server-cert'])
    setOption(options, 'cert_expiration', DEFS['--cert-expiration'])
    setOption(options, 'server_rpm', DEFS['--server-rpm'])
    setOption(options, 'server_tar', DEFS['--server-tar'])
    setOption(options, 'server_cert_dir', DEFS['--server-cert-dir'])


def figureDEFS_distinguishing(options):
    """ figure out the defaults (after options being at least parsed once) for
        the distinguishing variables (C, ST, L, O, OU, CN, emailAddress)
        First from config file, then from commanline.
    """

    # map the config file settings to the DEFS object
    caYN = '--gen-ca-cert' in sys.argv or '--gen-ca' in sys.argv
    if caYN:
        path = os.path.join(DEFS['--dir'], CA_OPENSSL_CNF_NAME)
    else:
        path = os.path.join(DEFS['--dir'], MACHINENAME, SERVER_OPENSSL_CNF_NAME)
    conf = parse_config(cleanupAbsPath(path))

    mapping = {
            'C': ('--set-country',),
            'ST': ('--set-state',),
            'L': ('--set-city',),
            'O': ('--set-org',),
            'OU': ('--set-org-unit',),
            'CN': ('--set-common-name',),
            'emailAddress': ('--set-email',),
              }

    # map config file settings to DEFS (see mapping dict above)
    for key in conf.keys():
        for v in mapping[key]:
            DEFS[v] = conf[key]

    # map commanline options to the DEFS object
    if getOption(options, 'gen_server'):
        DEFS['--purpose'] = 'server'
    if getOption(options, 'gen_client'):
        DEFS['--purpose'] = 'client'

    if getOption(options, 'set_country') is not None:
        DEFS['--set-country'] = getOption(options, 'set_country')
    if getOption(options, 'set_state') is not None:
        DEFS['--set-state'] = getOption(options, 'set_state')
    if getOption(options, 'set_city') is not None:
        DEFS['--set-city'] = getOption(options, 'set_city')
    if getOption(options, 'set_org') is not None:
        DEFS['--set-org'] = getOption(options, 'set_org')
    if getOption(options, 'set_org_unit') is not None:
        DEFS['--set-org-unit'] = getOption(options, 'set_org_unit')
    if getOption(options, 'set_common_name') is not None:
        DEFS['--set-common-name'] = getOption(options, 'set_common_name')
    if getOption(options, 'set_hostname') is not None:
        DEFS['--set-hostname'] = getOption(options, 'set_hostname')

    if getOption(options, 'set_common_name') is not None:
        DEFS['--set-common-name'] = getOption(options, 'set_common_name')
    else:
        DEFS['--set-common-name'] = DEFS['--set-hostname']

    if getOption(options, 'set_email') is not None:
        DEFS['--set-email'] = getOption(options, 'set_email')
    DEFS['--set-cname'] = getOption(options, 'set_cname')  # this is list

    # remap to options object
    setOption(options, 'set_country', DEFS['--set-country'])
    setOption(options, 'set_state', DEFS['--set-state'])
    setOption(options, 'set_city', DEFS['--set-city'])
    setOption(options, 'set_org', DEFS['--set-org'])
    setOption(options, 'set_org_unit', DEFS['--set-org-unit'])
    setOption(options, 'set_common_name', DEFS['--set-common-name'])
    setOption(options, 'set_email', DEFS['--set-email'])
    setOption(options, 'set_cname', DEFS['--set-cname'])


CONF_TEMPLATE_CA = """\
# katello-ca-openssl.cnf
#---------------------------------------------------------------------------
# Katello Management autogenerated openSSL configuration file.
#---------------------------------------------------------------------------

[ ca ]
default_ca              = CA_default

[ CA_default ]
default_bits            = 2048
x509_extensions         = ca_x509_extensions
dir                     = %s
database                = $dir/index.txt
serial                  = $dir/serial

# how closely we follow policy
policy                  = policy_optional
copy_extensions         = copy

[ policy_optional ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

#---------------------------------------------------------------------------

[ req ]
default_bits            = 2048
distinguished_name      = req_distinguished_name
prompt                  = no
x509_extensions         = req_ca_x509_extensions

[ req_distinguished_name ]
%s

[ req_ca_x509_extensions ]
basicConstraints = CA:true
keyUsage = digitalSignature, keyEncipherment, keyCertSign, cRLSign
extendedKeyUsage = serverAuth, clientAuth
nsCertType = server, sslCA
# PKIX recommendations harmless if included in all certificates.
nsComment               = "Katello SSL Tool Generated Certificate"
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid, issuer:always

[ req_server_x509_extensions ]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
nsCertType = server
# PKIX recommendations harmless if included in all certificates.
nsComment               = "Katello SSL Tool Generated Certificate"
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid, issuer:always

[ req_client_x509_extensions ]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
nsCertType = client
# PKIX recommendations harmless if included in all certificates.
nsComment               = "Katello SSL Tool Generated Certificate"
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid, issuer:always
#===========================================================================
"""


CONF_TEMPLATE_SERVER = """\
# katello-server-openssl.cnf
#---------------------------------------------------------------------------
# Katello Management autogenerated openSSL configuration file.
#---------------------------------------------------------------------------
[ req ]
default_bits            = 2048
distinguished_name      = req_distinguished_name
prompt                  = no
x509_extensions         = req_server_x509_extensions
req_extensions          = v3_req

[ req_distinguished_name ]
%s

[ req_server_x509_extensions ]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
nsCertType = %s
# PKIX recommendations harmless if included in all certificates.
nsComment               = "Katello SSL Tool Generated Certificate, got it?"
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid, issuer:always

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# Some CAs do not yet support subjectAltName in CSRs.
# Instead the additional names are form entries on web
# pages where one requests the certificate...
subjectAltName          = @alt_names

[alt_names]
%s
#===========================================================================
"""


def gen_req_alt_names(hostname, cnames=None):
    """ generates the alt_names section of the *-openssl.cnf file """
    dnsname = [hostname]
    if cnames:
        dnsname.extend(cnames)

    result = ''
    for i, name in enumerate(dnsname, 1):
        result += "DNS.%d = %s\n" % (i, name)
    return result


def gen_req_distinguished_name(d):
    """ generates the req_distinguished section of the *-openssl.cnf file """
    result = ""
    keys = ('C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress')
    for key in keys:
        if key in d and d[key].strip():
            result += '{0: <24}= {1}\n'.format(key, d[key].strip())
        else:
            result += '#{0: <24}= ""\n'.format(key)

    return result


def figureSerial(caCertFilename, serialFilename, indexFilename):
    """ for our purposes we allow the same serial number for server certs
        BUT WE DO NOT ALLOW server certs and CA certs to share the same
        serial number.

        We blow away the index.txt file each time because we are less
        concerned with matching serials/signatures between server.crt's.
    """

    # what serial # is the ca cert using (we need to increment from that)
    command = ['/usr/bin/openssl', 'x509', '-noout', '-serial', '-in', caCertFilename]
    output = subprocess.check_output(command, universal_newlines=True)
    assert '=' in output
    ca_serial = int(output.rstrip().split('=', 1)[1], 16)

    # initialize the serial value (starting at whatever is in
    # serialFilename or 1)
    serial = 1
    if os.path.exists(serialFilename):
        with open(serialFilename, 'r') as serial_fp:
            content = serial_fp.read().strip()
            if content:
                serial = int(serial, 16)

    # make sure it is at least 1 more than the CA's serial code always
    # REMEMBER: openssl will incremented the serial number each time
    # as well.
    serial = max(serial, ca_serial + 1)

    # create the serial file if it doesn't exist
    # write the digits to this file
    with open(serialFilename, 'w') as serial_fp:
        serial_fp.write(format_serial(serial)+'\n')
    os.chmod(serialFilename, 0o600)

    # truncate the index.txt file. Less likely to have unneccessary clashes.
    with open(indexFilename, 'w'):
        pass
    os.chmod(indexFilename, 0o600)
    return serial


def parse_config(path):
    """ yank all the pertinent ssl data from a previously generated openssl.cnf.
    """

    d = {}
    keys = ('C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress')

    try:
        with open(path, 'r') as fo:
            for line in fo:
                if line.strip() == '[ req_distinguished_name ]':
                    break

            for line in fo:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    break

                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.rstrip()
                    if key in keys:
                        d[key] = value.lstrip()
    except IOError:
        pass

    return d


def save_config(filename, d, is_ca, verbosity=0):
    """ d == commandline dictionary """

    mapping = {
        '--set-country': 'C',
        '--set-state': 'ST',
        '--set-city': 'L',
        '--set-org': 'O',
        '--set-org-unit': 'OU',
        '--set-common-name': 'CN',
        '--set-email': 'emailAddress',
    }

    rdn = {mapping[key]: value.strip() for key, value in d.items() if key in mapping}
    request = gen_req_distinguished_name(rdn)

    if is_ca:
        openssl_cnf = CONF_TEMPLATE_CA % (os.path.dirname(filename)+'/', request)
    else:
        alt_names = gen_req_alt_names(rdn['CN'], d.get('--set-cname'))
        openssl_cnf = CONF_TEMPLATE_SERVER % (request, d['--purpose'], alt_names)

    try:
        rotated = rotateFile(filepath=filename, verbosity=verbosity)
        if verbosity >= 0 and rotated:
            print("Rotated: %s --> %s" % (os.path.basename(filename), os.path.basename(rotated)))
    except ValueError:
        pass

    with open(filename, 'w') as config_fp:
        config_fp.write(openssl_cnf)
    os.chmod(filename, 0o600)
    return openssl_cnf


##
# generated RPM "configuration" dumping ground:
##
POST_UNINSTALL_SCRIPT = """\
if [ \$1 = 0 ]; then
    # The following steps are copied from mod_ssl's postinstall scriptlet
    # Make sure the permissions are okay
    umask 077

    if [ ! -f /etc/httpd/conf/ssl.key/server.key ] ; then
        /usr/bin/openssl genrsa -rand /proc/apm:/proc/cpuinfo:/proc/dma:/proc/filesystems:/proc/interrupts:/proc/ioports:/proc/pci:/proc/rtc:/proc/uptime 1024 > /etc/httpd/conf/ssl.key/server.key 2> /dev/null
    fi

    if [ ! -f /etc/httpd/conf/ssl.crt/server.crt ] ; then
        cat << EOF | /usr/bin/openssl req -new -key /etc/httpd/conf/ssl.key/server.key -x509 -days 365 -out /etc/httpd/conf/ssl.crt/server.crt 2>/dev/null
--
SomeState
SomeCity
SomeOrganization
SomeOrganizationalUnit
localhost.localdomain
root@localhost.localdomain
EOF
    fi
    /sbin/service httpd graceful
    exit 0
fi
"""  # noqa: W605, E501

SERVER_RPM_SUMMARY = "Organizational server (httpd) SSL key-pair/key-set."
CA_CERT_RPM_SUMMARY = ("Organizational public SSL CA certificate "
                       "(client-side).")
