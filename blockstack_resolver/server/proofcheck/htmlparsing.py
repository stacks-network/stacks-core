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

from bs4 import BeautifulSoup
from .sites import SITES

GITHUB_CONTENT_TAG = 'blob instapaper_body'
GITHUB_DESCRIPTION_TAG = 'repository-description'
GITHUB_FILE_TAG = 'blob-wrapper data type-text'


def get_github_text(raw_html):
    html = BeautifulSoup(raw_html, "html.parser")

    gist_description = html.body.find('div', attrs={'class': GITHUB_CONTENT_TAG})

    if gist_description is not None:
        gist_description = gist_description.text
    else:
        gist_description = html.body.find('div', attrs={'class': GITHUB_DESCRIPTION_TAG})

        if gist_description is not None:
            gist_description = gist_description.text
        else:
            gist_description = ''

    file_text = html.body.find('div', attrs={'class': GITHUB_FILE_TAG})

    if file_text is not None:
        file_text = file_text.text
    else:
        file_text = ''

    search_text = gist_description + ' ' + file_text

    return search_text


def get_search_text(service, raw_html):
    if service == 'facebook':
        raw_html = raw_html.replace('<!--', '').replace('-->', '')

    html_soup = BeautifulSoup(raw_html, "html.parser")

    if service in SITES:
        query_data = SITES[service]['html_query']
        search_text = ''
        if 'class' in query_data:
            search_results = html_soup.body.find('div', class_=query_data['class'])
            if search_results:
                search_text = search_results.text
        elif 'title' in query_data:
            search_results = html_soup.title.string
        else:
            search_results = html_soup.body
            if search_results:
                search_text = search_results.text

    return search_text


def get_twitter_url(raw_html):

    soup = BeautifulSoup(raw_html, "html.parser")

    try:
        url = soup.find("meta", {"property": "og:url"})['content']
    except:
        url = ''

    return url