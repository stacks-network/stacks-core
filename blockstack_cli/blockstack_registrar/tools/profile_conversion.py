# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""


def convert_v1_to_v2(profile):

    new_profile = {}

    if 'v' in profile:
        new_profile['v'] = '0.2'

    if 'website' in profile:
        new_profile['website'] = profile['website']

    if 'bio' in profile:
        new_profile['bio'] = profile['bio']
    if 'github' in profile:
        new_profile['github'] = profile['github']

    if 'instagram' in profile:
        new_profile['instagram'] = {"username": profile['instagram']}

    if 'twitter' in profile:
        new_profile['twitter'] = {"username": profile['twitter']}

    if 'cover' in profile:
        new_profile['cover'] = {"url": profile['cover']}

    if 'avatar' in profile:
        new_profile['avatar'] = {"url": profile['avatar']}

    if 'bitcoin' in profile:
        new_profile['bitcoin'] = {"address": profile['bitcoin']}

    if 'linkedin' in profile:
        new_profile['linkedin'] = {"url": profile['linkedin']}

    if 'name' in profile:
        new_profile['name'] = {"formatted": profile['name']}

    if 'facebook' in profile:
        new_profile['facebook'] = {"username": profile['facebook']}

    if 'location' in profile:
        new_profile['location'] = {"formatted": profile['location']}

    if 'angellist' in profile:
        new_profile['angellist'] = {"username": profile['angellist']}

    if 'bitmessage' in profile:
        new_profile['bitmessage'] = {"address": profile['bitmessage']}

    if 'pgp' in profile:
        new_profile['pgp'] = profile['pgp']

    return new_profile
