# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Resolver.

    Resolver is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Resolver is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Resolver. If not, see <http://www.gnu.org/licenses/>.
"""

SITES = {
    'twitter': {
        'base_url': 'https://twitter.com/',
        'html_query': {
            'class': 'permalink-inner permalink-tweet-container'
        }
    },
    'facebook': {
        'base_url': 'https://facebook.com/',
        'html_query': {
            'class': '_5pbx userContent'
        }
    },
    'facebook-www': {
        'base_url': 'https://www.facebook.com/',
        'html_query': {
            'class': '_5pbx userContent'
        }
    },
    'github': {
        'base_url': 'https://gist.github.com/',
        'html_query': {
            'class': 'blob-wrapper data type-markdown js-blob-data'
        }
    },
    'hackernews': {
        'base_url': 'https://news.ycombinator.com/user?id=',
        'html_query': {
        }
    },
    'instagram': {
        'base_url': 'http://instagram.com/',
        'html_query': {
        }
    },
    'linkedin': {
        'base_url': 'https://www.linkedin.com/in/',
        'html_query': {
        }
    },
    'stackoverflow': {
        'base_url': 'http://stackoverflow.com/users/',
        'html_query': {
        }
    },
    'angellist': {
        'base_url': 'https://angel.co/',
        'html_query': {
        }
    },
}

UNSUPPORTED_SITES = {
    'googleplus': {
        'base_url': 'https://plus.google.com/',
        'html_query': {
            'title': True
        }
    },
    'reddit': {
        'base_url': 'http://www.reddit.com/user/',
        'html_query': {
        }
    }
}
