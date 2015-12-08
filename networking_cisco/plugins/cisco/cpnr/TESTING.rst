Testing CPNR DHCP/DNS Drivers
=============================================================

Overview
--------

The unit tests in openstack-cisco-cpnrdhcp-driver/tests/unit are meant to be
run statically (i.e. without running the code).

Unit Testing
------------

Tox is used to test for any pep8 errors in the code, and for unit tests.
Testr is used by tox to run unit tests.

To run pep8/unit tests:

    tox

To run pep8 checking:

    tox -e pep8

To run unit tests:

    tox -e py27

To run an individual unit test:

    tox -e py27 <test_name>

For example:

    tox -e py27 test_model.TestModel.test_recover_networks

All commands above should be run from the same directory as tox.ini.
