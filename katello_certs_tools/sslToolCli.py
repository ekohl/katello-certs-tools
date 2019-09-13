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
# katello-ssl-tool command line option module
#
# $Id$

# FIXME: the logic here is *WAY* too complicated. Need to simplify -taw

# language imports
import os
import sys

# utitily imports
from optparse import Option, OptionParser, make_option

# local imports
from katello_certs_tools.sslToolLib import daysTil18Jan2038, yearsTil18Jan2038, \
                       KatelloSslToolException, errnoGeneralError
from katello_certs_tools.sslToolConfig import figureDEFS_dirs, figureDEFS_CA, figureDEFS_server
from katello_certs_tools.sslToolConfig import figureDEFS_distinguishing
from katello_certs_tools.sslToolConfig import DEFS, getOption, reInitDEFS


#
# option lists.
# stitched together later to give a known list of commands.
#

def _getOptionsTree(defs):
    """ passing in the defaults dictionary (which is not static)
        build the options tree dependent on whats on the commandline
    """

    _optCAKeyPassword = make_option('-p', '--password', action='store', type="string", help='CA password or password file location')  # noqa: E501
    _optCaKey = make_option('--ca-key', action='store', type="string", help='CA private key filename (default: %s)' % defs['--ca-key'])  # noqa: E501
    _optCaCert = make_option('--ca-cert', action='store', type="string", help='CA certificate filename (default: %s)' % defs['--ca-cert'])  # noqa: E501
    _optOtherCaCerts = make_option('--other-ca-certs', action='store', type="string", help='Comma separated list of paths to other public CA certificates to be included in ours')  # noqa: E501
    _optCaCertDir = make_option('--ca-cert-dir', action='store', type="string", help='Directory to deploy CA cert and key to.')  # noqa: E501

    _optCertExp = make_option('--cert-expiration', action='store', type="int", help='expiration of certificate (default: %s days)' % (int(defs['--cert-expiration'])))  # noqa: E501

    _optServerKey = make_option('--server-key', action='store', type="string", help="the web server's SSL private key filename (default: %s)" % defs['--server-key'])  # noqa: E501
    _optServerCertReq = make_option('--server-cert-req', action='store', type="string", help="location of the web server's SSL certificate request filename (default: %s)" % defs['--server-cert-req'])  # noqa: E501
    _optServerCert = make_option('--server-cert', action='store', type="string", help='the web server SSL certificate filename (default: %s)' % defs['--server-cert'])  # noqa: E501
    _optServerCertDir = make_option('--server-cert-dir', action='store', type="string", help='Directory to deploy server cert and key to.')  # noqa: E501

    _optCaForce = make_option('-f', '--force', action='store_true', help='forcibly create a new CA SSL private key and/or public certificate')  # noqa: E501

    _optCaKeyOnly = make_option('--key-only',    action='store_true', help='(rarely used) only generate a CA SSL private key. Review "--gen-ca --key-only --help" for more information.')  # noqa: E501
    _optCaCertOnly = make_option('--cert-only',   action='store_true', help='(rarely used) only generate a CA SSL public certificate. Review "--gen-ca --cert-only --help" for more information.')  # noqa: E501

    _optServerKeyOnly = make_option('--key-only',      action='store_true', help="""(rarely used) only generate the web server's SSL private key. Review "--gen-server --key-only --help" for more information.""")  # noqa: E501
    _optServerCertReqOnly = make_option('--cert-req-only', action='store_true', help="""(rarely used) only generate the web server's SSL certificate request. Review "--gen-server --cert-req-only --help" for more information.""")  # noqa: E501
    _optServerCertOnly = make_option('--cert-only',     action='store_true', help="""(rarely used) only generate the web server's SSL certificate. Review "--gen-server --cert-only --help" for more information.""")  # noqa: E501

    _optCaCertRpm = make_option('--ca-cert-rpm', action='store', type="string", help='(rarely changed) RPM name that houses the CA SSL public certificate (the base filename, not filename-version-release.noarch.rpm).')  # noqa: E501
    _optServerRpm = make_option('--server-rpm',  action='store', type="string", help="(rarely changed) RPM name that houses the web server's SSL key set (the base filename, not filename-version-release.noarch.rpm).")  # noqa: E501
    _optServerTar = make_option('--server-tar',  action='store', type="string", help="(rarely changed) name of tar archive of the web server's SSL key set and CA SSL public certificate that is used solely by the hosted RHN Proxy installation routines (the base filename, not filename-version-release.tar).")  # noqa: E501

    _optRpmPackager = make_option('--rpm-packager', action='store', type="string", help='(rarely used) packager of the generated RPM, such as "RHN Admin <rhn-admin@example.com>".')  # noqa: E501
    _optRpmVender = make_option('--rpm-vendor',     action='store', type="string", help='(rarely used) vendor of the generated RPM, such as "IS/IT Example Corp.".')  # noqa: E501

    _optRpmOnly = make_option('--rpm-only', action='store_true', help='(rarely used) only generate a deployable RPM. (and tar archive if used during the --gen-server step) Review "<baseoption> --rpm-only --help" for more information.')  # noqa: E501
    _optNoRpm = make_option('--no-rpm',   action='store_true', help='(rarely used) do everything *except* generate an RPM.')  # noqa: E501

    _optSetHostname = make_option('--set-hostname', action='store', type="string", help='hostname of the web server you are installing the key set on (default: %s)' % repr(defs['--set-hostname']))  # noqa: E501

    _optSetCname = make_option('--set-cname', action='append', type="string", help='cname alias of the web server, can be specified multiple times')  # noqa: E501

    _buildRpmOptions = [_optRpmPackager, _optRpmVender, _optRpmOnly]

    _genOptions = [
        make_option('-v', '--verbose', action='count', help='be verbose. Accumulative: -vvv means "be *really* verbose".'),
        make_option('-d', '--dir', action='store', help="build directory (default: %s)" % defs['--dir']),
        make_option('-q', '--quiet', action='store_true', help="be quiet. No output."),
        ]

    _genConfOptions = [
        make_option('--set-country',  action='store', type="string", help='2 letter country code (default: %s)' % repr(defs['--set-country'])),  # noqa: E501
        make_option('--set-state',    action='store', type="string", help='state or province (default: %s)' % repr(defs['--set-state'])),  # noqa: E501
        make_option('--set-city',     action='store', type="string", help='city or locality (default: %s)' % repr(defs['--set-city'])),  # noqa: E501
        make_option('--set-org',      action='store', type="string", help='organization or company name, such as "Red Hat Inc." (default: %s)' % repr(defs['--set-org'])),  # noqa: E501
        make_option('--set-org-unit', action='store', type="string", help='organizational unit, such as "RHN" (default: %s)' % repr(defs['--set-org-unit'])),  # noqa: E501
        make_option('--set-email',    action='store', type="string", help='email address (default: %s)' % repr(defs['--set-email'])),  # noqa: E501
        make_option('--set-common-name', action='store', type="string", help='common name (default: %s)' % repr(defs['--set-common-name'])),  # noqa: E501
        ]

    _caConfOptions = _genConfOptions

    _serverConfOptions = [_optSetHostname, _optSetCname] + _genConfOptions

    # CA generation options
    _caOptions = [
        _optCaForce,
        _optCAKeyPassword,
        _optCaKey,
        _optOtherCaCerts,
        _optCaCertDir
        ]

    # CA cert generation options
    _caCertOptions = [
        _optCaForce,
        _optCAKeyPassword,
        _optCaKey,
        _optCaCert,
        _optOtherCaCerts,
        _optCaCertDir,
        _optCertExp,
        ] + _caConfOptions

    # server key generation options
    _serverKeyOptions = [
        _optServerKey,
        ]

    # server cert req generation options
    _serverCertReqOptions = [
        _optServerKey,
        _optServerCertReq,
        _optServerCertDir
        ]

    # server cert generation options
    _serverCertOptions = [
        _optCAKeyPassword,
        _optCaCert,
        _optCaKey,
        _optServerCertReq,
        _optCaCertDir,
        Option('--startdate',  action='store', type="string", default=defs['--startdate'], help="start date for the web server's SSL certificate validity (format: YYMMDDHHMMSSZ - where Z is a letter; default is 1 week ago: %s)" % defs['--startdate']),  # noqa: E501
        _optServerCert,
        _optServerCertDir,
        _optCertExp,
        ]

    # the base options
    _optGenCa = make_option('--gen-ca', action='store_true', help='generate a Certificate Authority (CA) key pair and public RPM. Review "--gen-ca --help" for more information.')  # noqa: E501
    _optGenServer = make_option("--gen-server", action='store_true', help="""generate the web server's SSL key set, RPM and tar archive. Review "--gen-server --help" for more information.""")  # noqa: E501
    _optGenClient = make_option("--gen-client", action='store_true', help="""generate the client SSL key set, RPM and tar archive. Review "--gen-client --help" for more information.""")  # noqa: E501

    # CA build option tree set possibilities
    _caSet = [_optGenCa] + _caOptions + _caCertOptions \
        + _genOptions + [_optCaKeyOnly, _optCaCertOnly] + _buildRpmOptions \
        + [_optCaCertRpm, _optNoRpm]
    _caKeyOnlySet = [_optGenCa] + _caOptions + _genOptions \
        + [_optCaKeyOnly]
    _caCertOnlySet = [_optGenCa] + _caOptions + _caCertOptions \
        + _genOptions + [_optCaCertOnly]
    _caRpmOnlySet = [_optGenCa, _optCaKey, _optCaCert, _optCaCertDir, _optOtherCaCerts] \
        + _buildRpmOptions + [_optCaCertRpm] + _genOptions  # noqa: E501

    # server build option tree set possibilities
    _serverSet = [_optGenServer, _optGenClient] + _serverKeyOptions + _serverCertReqOptions \
        + _serverCertOptions + _serverConfOptions + _genOptions \
        + [_optServerKeyOnly, _optServerCertReqOnly, _optServerCertOnly, _optServerCertDir] \
        + _buildRpmOptions + [_optServerRpm, _optServerTar, _optNoRpm]
    _serverKeyOnlySet = [_optGenServer, _optGenClient] + _serverKeyOptions \
        + _genOptions + [_optServerKeyOnly]
    _serverCertReqOnlySet = [_optGenServer, _optGenClient] + _serverKeyOptions \
        + _serverCertReqOptions + _serverConfOptions \
        + _genOptions + [_optServerCertReqOnly]
    _serverCertOnlySet = [_optGenServer, _optGenClient] + _serverCertOptions \
        + _genOptions + [_optServerCertOnly]  # noqa: E501
    _serverRpmOnlySet = [_optGenServer, _optGenClient, _optServerKey, _optServerCertReq, _optServerCert, _optServerCertDir, _optSetHostname, _optSetCname] \
        + _buildRpmOptions + [_optServerRpm, _optServerTar] + _genOptions  # noqa: E501

    optionsTree = {
        '--gen-ca': _caSet,
        '--gen-server': _serverSet,
        '--gen-client': _serverSet,
        }

    # quick check about the --*-only options
    _onlyOpts = set(['--key-only', '--cert-req-only', '--cert-only', '--rpm-only'])
    _onlyIntersection = set(sys.argv) & _onlyOpts
    if len(_onlyIntersection) > 1:
        sys.stderr.write("""\
ERROR: cannot use these options in combination:
       %s\n""" % repr(_onlyIntersection))
        sys.exit(errnoGeneralError)
    _onlyIntersection = set(sys.argv) & set(['--rpm-only', '--no-rpm'])
    if len(_onlyIntersection) > 1:
        sys.stderr.write("""\
ERROR: cannot use these options in combination:
       %s\n""" % repr(_onlyIntersection))
        sys.exit(errnoGeneralError)
    _onlyIntersection = set(sys.argv) & set(['--gen-client', '--gen-server'])
    if len(_onlyIntersection) > 1:
        sys.stderr.write("""\
ERROR: cannot use these options in combination:
       %s\n""" % repr(_onlyIntersection))
        sys.exit(errnoGeneralError)

    if '--key-only' in sys.argv:
        optionsTree['--gen-ca'] = _caKeyOnlySet
        optionsTree['--gen-server'] = _serverKeyOnlySet
        optionsTree['--gen-client'] = _serverKeyOnlySet
    elif '--cert-only' in sys.argv:
        optionsTree['--gen-ca'] = _caCertOnlySet
        optionsTree['--gen-server'] = _serverCertOnlySet
        optionsTree['--gen-client'] = _serverCertOnlySet
    elif '--cert-req-key-only' in sys.argv:
        optionsTree['--gen-server'] = _serverCertReqOnlySet
        optionsTree['--gen-client'] = _serverCertReqOnlySet
    elif '--rpm-only' in sys.argv:
        optionsTree['--gen-ca'] = _caRpmOnlySet
        optionsTree['--gen-server'] = _serverRpmOnlySet
        optionsTree['--gen-client'] = _serverRpmOnlySet

    baseOptions = [_optGenCa, _optGenServer, _optGenClient]
    return optionsTree, baseOptions


# custom usage text
_progName = os.path.basename(sys.argv[0])
BASE_USAGE = """\
%s [options]

 step 1 %s --gen-ca [sub-options]

 step 2 %s --gen-server [sub-options]

 step 3 %s --gen-client [sub-options]

The two options listed above are "base options". For more help about
a particular option, just add --help to either one, such as:
%s --gen-ca --help

If confused, please refer to the man page or other documentation
for sample usage.\
""" % tuple([_progName]*5)
OTHER_USAGE = """\
%s [options]

If confused, please refer to the man page or other documentation
for sample usage.\
""" % _progName


def _getOptionList(defs):
    """ stitch together the commandline given rules set in optionsTree
        and the grouping logic.
    """

    optionsTree, baseOptions = _getOptionsTree(defs)
    optionsList = []
    usage = OTHER_USAGE

    argIntersection = set(sys.argv) & set(optionsTree.keys())

    if len(argIntersection) == 1:
        optionsList = optionsTree[argIntersection[0]]

    elif len(argIntersection) > 1:
        # disallow multiple base options on the same commandline
        sys.stderr.write("""\
ERROR: cannot use these options in combination:
       %s
      (%s --help)\n""" % (argIntersection, _progName))
        sys.exit(errnoGeneralError)

    else:
        # if *no* base options on he commandline, clear on the list
        # and tag on a --help
        optionsList = baseOptions
        usage = BASE_USAGE
        if '--help' not in sys.argv:
            sys.argv.append('--help')

    return optionsList, usage


def optionParse():
    """ We parse in 3 steps:
        (1) parse options
        (2) set the defaults based on any options we override on the commandline
            - this is nice for things like (what dir we are working in etc).
        (3) reparse the options with defaults set

        Reset the default values DEFS given the options found.
    """

    # force certain "first options". Not beautiful but it works.
    if len(sys.argv) > 1:
        if sys.argv[1] not in ('-h', '--help', '--gen-ca', '--gen-server', '--gen-client'):
            # first option was not something we understand. Force a base --help
            del(sys.argv[1:])
            sys.argv.append('--help')

    if '--gen-ca' in sys.argv:
        reInitDEFS(1)
    else:
        reInitDEFS(0)
    ##
    # STEP 1: preliminarily parse options
    ##
    # print 'XXX STEP1'

    optionList, usage = _getOptionList(DEFS)

    optionListNoHelp = optionList[:]
    fake_help = Option("-h", "--help", action="count", help='')
    optionListNoHelp.append(fake_help)
    options, args = OptionParser(option_list=optionListNoHelp, add_help_option=0).parse_args()

    ##
    # STEP 2: repopulate DEFS dict based on commandline
    #         and the *-openssl.cnf files
    ##
    # print 'XXX STEP2'
    figureDEFS_dirs(options)            # build directory structure
    figureDEFS_CA(options)              # CA key set stuff
    figureDEFS_server(options)          # server key set stuff
    figureDEFS_distinguishing(options)  # distinguishing name stuff

    ##
    # STEP 3: reparse options again only if --help is in the commandline
    #         so that we can give a --help with correct defaults set.
    ##
    # print 'XXX STEP3'

    if '-h' in sys.argv or '--help' in sys.argv:
        # DEFS should be mapped with new values now... let's reparse the options.
        # The correct help text should be presented and all defaults
        # should be mapped as expected.
        optionList, usage = _getOptionList(DEFS)
        options, args = OptionParser(option_list=optionList, usage=usage).parse_args()

    # we take no extra commandline arguments that are not linked to an option
    if args:
        sys.stderr.write("\nERROR: these arguments make no sense in this "
                         "context (try --help): %s\n" % repr(args))
        sys.exit(errnoGeneralError)

    return options


class CertExpTooShortException(KatelloSslToolException):
    "certificate expiration must be at least 1 day"


class CertExpTooLongException(KatelloSslToolException):
    "cert expiration cannot be > 1 year before the 32-bit overflow (in days)"


class InvalidCountryCodeException(KatelloSslToolException):
    "invalid country code. Probably != 2 characters in length."


def processCommandline():
    options = optionParse()

    _maxDays = daysTil18Jan2038()

    cert_expiration = getOption(options, 'cert_expiration')
    if cert_expiration:
        if cert_expiration < 1:
            raise CertExpTooShortException(
                    "certificate expiration must be at least 1 day")
        if cert_expiration > _maxDays:
            raise CertExpTooLongException(
                    "certificate expiration cannot exceed %s days "
                    "(~%.2f years)\n"
                    % (int(_maxDays), yearsTil18Jan2038()))

    country = getOption(options, 'set_country')
    if country is not None and (country == '' or len(country) != 2):
        raise InvalidCountryCodeException(
                "country code must be exactly two characters, such as 'US'")

    if options.quiet:
        options.verbose = -1
    if not options.verbose:
        options.verbose = 0

    return options
