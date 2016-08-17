# blockstack-integration-tests

End-to-end Blockstack test framework


Setup
-----

You need to install all the dependencies in order to run the integration tests.
One way to do that without cluttering your global installation is to make a
virtual Python environment to install into:

    $ cd blockstack-integration-tests/
    $ virtualenv env/
    $ source env/bin/activate

Then you can install the integration tests which will also pull in all
dependencies, do note that this might take quite a while (several minutes):

    $ python setup.py install


How to run
----------

You can run individual scenario tests by using `blockstack-test-scenario` and
the test you want to run:

    $ bin/blockstack-test-scenario blockstack_integration_tests.scenarios.nameop_parsing

This will print out a lot of debug information while running.  If the test was
successfull it will print out `SUCCESS` at the end.

There is also a script `blockstack-test-all` that will run all the tests in a
lot less verbose way and log the output and data of each test into files in a
directory:

    $ blockstack-test-all output/ blockstack_integration_tests/tests_skip.txt

In the previous example the script will create the `output/` folder for you
if it doesn't exist.  The second argument gives a list of files to skip, it's
smart to use `blockstack_integration_tests/tests_skip.txt` because they contain
tests that's currently meant to be skipped.


Troubleshooting
---------------

The tests are not fully stable.  Some can work on second run. Many tests also
seems to always fail.  There might be more setup required.
