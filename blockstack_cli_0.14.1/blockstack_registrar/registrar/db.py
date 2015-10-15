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
from registrar.config import MONGODB_URI, INDEXDB_URI, AWSDB_URI

remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user
registrations = remote_db.user_registration


c = MongoClient(INDEXDB_URI)
state_diff = c['namespace'].state_diff

aws_db = MongoClient(AWSDB_URI)['registrar']
register_queue = aws_db.queue
