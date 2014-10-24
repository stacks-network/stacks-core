SITES = {
    'twitter': {
        'base_url': 'https://twitter.com/',
        'html_query': {
            'class': 'permalink-inner permalink-tweet-container'
        }
    },
    'facebook': {
        'base_url': 'https://www.facebook.com/',
        'html_query': {
            'class': 'userContentWrapper _5pcr _3ccb'
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