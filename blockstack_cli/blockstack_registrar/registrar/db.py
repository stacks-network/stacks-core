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

from pymongo import MongoClient

from .config import WEBAPP_DB_URI, API_DB_URI, QUEUE_DB_URI

webapp_db = MongoClient(WEBAPP_DB_URI).get_default_database()
users = webapp_db.user
registrations = webapp_db.user_registration
updates = webapp_db.profile_update

c = MongoClient()
state_diff = c['namespace'].state_diff

queue_db = MongoClient(QUEUE_DB_URI)['registrar']
register_queue = queue_db.register_queue
update_queue = queue_db.update_queue

# to-do: rename this from 'migration'
registrar_users = c['migration'].migration_users
registrar_addresses = c['migration'].registrar_addresses

api_db = MongoClient(API_DB_URI).get_default_database()


def get_db_user_from_id(entry):

    user_id = entry['user_id']
    user = users.find_one({"_id": user_id})

    if user is None:
        return None

    if not user['username_activated']:
        return None

    return user
