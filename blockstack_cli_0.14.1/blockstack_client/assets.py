#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

# static assets built-in to the client 

import urllib
import urllib2

# format: appname, app_fqu, auth-finish URL, auth-abort URL
# comments are for integration testing
APP_SIGNIN_PAGE_TEMPLATE = """
{}
<!--go_back={}-->
<html>
    <head></head>
    <body>
        Sign into application '{}' from '{}'?<br>
        {}
        <a href="{}">Go back</a>
    </body>
</html>
"""

# format: appname, app_fqu, API calls, auth-finish URL
# comments are for integration testing
APP_MAKE_ACCOUNT_PAGE_TEMPLATE = """
<!--create_account={}-->
<!--go_back={}-->
<html>
    <head></head>
    <body>
        Create application account for '{}' from '{}' and sign in?<br>
        Requested permissions: {}<br>
        <a href="{}">Create account and sign in</a><br>
        <a href="{}">Go back</a><br>
    </body>
</html>
"""

# format: account-list
APP_HOME_PAGE_TEMPLATE = """
<html>
    <head></head>
    <body>
        Identity page home.<br>
        Accounts: {}<br>
    </body>
</html>
"""

# format: error message
APP_ERROR_PAGE_TEMPLATE = """
<html>
    <head></head>
    <body>
        Error: {}<br>
    </body>
</html>
"""

def asset_make_signin_page( appname, app_fqu, user_id_urls, auth_abort_url ):
    """
    Generate and return the HTML for creating an app session.
    """
    signin_comments = '\n'.join( '<!--signin={}-->'.format(user_url) for user_url in user_id_urls )
    user_id_url_info = [(user_id_url, user_id_url.split("/")[-1]) for user_id_url in user_id_urls]

    signin_links = '<br>\n'.join( '<a href="{}">Signin as {}</a>'.format( url[0], url[1] ) for url in user_id_url_info )

    return APP_SIGNIN_PAGE_TEMPLATE.format(signin_comments, auth_abort_url, appname, app_fqu, signin_links, auth_abort_url )


def asset_make_account_page( appname, app_fqu, api_methods, auth_finish_url, auth_abort_url ):
    """
    Generate and return the HTML for creating an app account, followed by an app session
    """
    return APP_MAKE_ACCOUNT_PAGE_TEMPLATE.format(auth_finish_url, auth_abort_url, appname, app_fqu, ",".join(api_methods), auth_finish_url, auth_abort_url)


def asset_make_home_page( account_list ):
    """
    Generate and return the HTML page for showing the list of accounts
    """
    return APP_HOME_PAGE_TEMPLATE.format( ",".join(account_list) )


def asset_make_error_page( error_msg, stack_trace=None ):
    """
    Generate and return an HTML page showing an error and optional stack trace
    """
    if stack_trace is not None:
        error_msg += "<br>{}".format(stack_trace)

    return APP_ERROR_PAGE_TEMPLATE.format(error_msg)

