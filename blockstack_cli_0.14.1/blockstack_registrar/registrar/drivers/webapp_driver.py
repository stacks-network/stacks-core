# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
import traceback

from pymongo import MongoClient

from blockstack_profiles import is_profile_in_legacy_format

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../../")

sys.path.insert(0, parent_dir)

from registrar.config import DEFAULT_NAMESPACE, RATE_LIMIT
from registrar.config import MINIMUM_LENGTH_NAME
from registrar.config import IGNORE_NAMES_STARTING_WITH
from registrar.config import SECRET_KEY

from registrar.utils import get_hash, check_banned_email, nmc_to_btc_address
from registrar.utils import config_log, ignoreRegistration
from registrar.utils import pretty_print as pprint
from registrar.utils import whiteListedUser, cleanup_email
from registrar.utils import validRegistrationEmail

from registrar.states import registrationComplete, nameRegistered
from registrar.states import profileonBlockchain, profileonDHT
from registrar.states import profilePublished, ownerName
from registrar.server import RegistrarServer

from registrar.network import refresh_resolver

from registrar.crypto.bip38 import bip38_decrypt

"""
    Webapp Driver file that has all necessary functions for
    using registrar with webapp data
"""

log = config_log(__name__)

try:
    # incoming requests from a web app
    WEBAPP_DB_URI = os.environ['WEBAPP_DB_URI']
    WALLET_SECRET = os.environ['WALLET_SECRET']
except:
    log.debug("webapp_driver env variables not defined")
    exit(0)

webapp_db = MongoClient(WEBAPP_DB_URI).get_default_database()


def get_db_user_from_id(entry, users):
    """ Helper function for DB
    """

    user_id = entry['user_id']
    user = users.find_one({"_id": user_id})

    if user is None:
        return None

    if not user['username_activated']:
        return None

    return user


def convert_profile_format(user):

    if is_profile_in_legacy_format(user['profile']):
        data_value = user['profile']
    else:
        if 'zone_file' in user:
            data_value = user['zone_file']
        else:
            data_value = {}

    return data_value


class WebappDriver(object):
    """ Registrar driver for webapp
    """

    def __init__(self):

        self.users = webapp_db.user
        self.registrations = webapp_db.user_registration
        self.updates = webapp_db.profile_update
        self.exports = webapp_db.name_export
        self.registrar_server = RegistrarServer()
        self.email_list = []

    def populate_email_list(self):
        """ Initialize the email list, saving unique emails
            for pending registrations
        """

        counter = 0

        for new_user in self.registrations.find(no_cursor_timeout=True):

            counter += 1
            print counter

            #continue

            user = get_db_user_from_id(new_user, self.users)

            cleaned_email = cleanup_email(user['email'])

            self.email_list.append(cleaned_email)

    def process_new_users(self, nameop=None, spam_protection=False,
                          live_delete=False):
        """
            Process new registrations coming in on the webapp
        """

        counter = 0
        self.registrar_server.reset_flag()

        self.populate_email_list()

        for new_user in self.registrations.find(no_cursor_timeout=True):

            user = get_db_user_from_id(new_user, self.users)

            if not self.validUser(user, new_user):

                live_delete = False
                if live_delete:
                    log.debug("Removing %s" % user['username'])
                    self.registrations.remove({"user_id": new_user['user_id']})
                continue

            if whiteListedUser(user['email'], user['profile']):
                log.debug("White-listed: %s" % user['email'])
            else:
                log.debug("Not registering: %s" % user['email'])
                #continue

            fqu = user['username'] + "." + DEFAULT_NAMESPACE
            transfer_address = nmc_to_btc_address(user['namecoin_address'])

            data_value = convert_profile_format(user)

            log.debug("Processing: %s" % fqu)

            if registrationComplete(fqu, data_value, transfer_address):
                log.debug("Registration complete %s. Removing." % fqu)
                self.registrations.remove({"user_id": new_user['user_id']})
                refresh_resolver(user['username'])
            else:
                try:
                    self.registrar_server.process_nameop(fqu, data_value,
                                                         transfer_address,
                                                         nameop=nameop)
                except:
                    log.debug(traceback.print_exc())

    def validUser(self, user, new_user):
        """
            Check if the given @user should be processed or ignored

            Returns True or False
        """

        if user is None:
            log.debug("No such user, need to remove: %s" % new_user)
            #self.registrations.remove({'_id': new_user['_id']})
            return False

        # for spam protection
        if check_banned_email(user['email']):
            log.debug("SPAM: Need to delete %s, %s" % (user['email'], user['username']))
            #self.remove_registration_entry(user['username'])
            return False

        # test for minimum name length
        if len(user['username']) < MINIMUM_LENGTH_NAME:
            log.debug("Expensive name %s. Skipping." % user['username'])
            return False

        # test for ignoring names starting with certain patterns
        if ignoreRegistration(user['username'], IGNORE_NAMES_STARTING_WITH):
            log.debug("Ignoring: %s" % user['username'])
            return False

        if not validRegistrationEmail(user['email'], self.email_list):
            log.debug("Email rejected by filter: %s" % user['email'])
            #self.remove_registration_entry(user['username'])
            return True

        return True

    def update_users(self, spam_protection=False, reprocess_username=None):
        """
            Process new profile updates from the webapp
        """

        counter = 0
        self.registrar_server.reset_flag()

        for new_user in self.updates.find(no_cursor_timeout=True):

            user = get_db_user_from_id(new_user, self.users)

            if user is None:
                continue

            # for spam protection
            if check_banned_email(user['email']):
                if spam_protection:
                    log.debug("Deleting spam: %s, %s" % (user['email'], user['username']))
                    self.updates.remove({"user_id": new_user['user_id']})
                else:
                    log.debug("Need to delete %s, %s" % (user['email'], user['username']))
                continue

            # mode for reprocessing a single user, ignore others
            if reprocess_username is not None:
                if user['username'] != reprocess_username:
                    #log.debug("Ignoring: %s" % user['username'])
                    continue

            fqu = user['username'] + "." + DEFAULT_NAMESPACE
            btc_address = nmc_to_btc_address(user['namecoin_address'])

            data_value = convert_profile_format(user)

            encrypted_privkey = new_user['encrypted_private_key']
            hex_privkey = bip38_decrypt(str(encrypted_privkey), WALLET_SECRET)

            if nameRegistered(fqu):

                if profilePublished(fqu, data_value):
                    log.debug("Profile match, removing: %s" % fqu)
                    self.updates.remove({"user_id": new_user['user_id']})

                    refresh_resolver(user['username'])
                else:
                    log.debug("Processing: %s, %s" % (fqu, user['email']))
                    try:
                        self.registrar_server.process_subsidized_nameop(fqu,
                                                                owner_privkey=hex_privkey,
                                                                profile=data_value,
                                                                nameop='update')
                    except Exception as e:
                        log.debug(e)
            else:

                log.debug("Not registered: %s" % fqu)

    def transfer_users(self, spam_protection=False, reprocess_username=None):
        """
            Process new transfer from the webapp
        """

        counter = 0
        self.registrar_server.reset_flag()

        for new_user in self.exports.find(no_cursor_timeout=True):

            user = get_db_user_from_id(new_user, self.users)

            if user is None:
                continue

            # add spam protection here

            # mode for reprocessing a single user, ignore others
            if reprocess_username is not None:
                if user['username'] != reprocess_username:
                    continue

            fqu = user['username'] + "." + DEFAULT_NAMESPACE

            transfer_address = new_user['recipient_address']

            try:
                encrypted_privkey = new_user['encrypted_private_key']
                hex_privkey = bip38_decrypt(str(encrypted_privkey), WALLET_SECRET)
            except:
                log.debug("no private key")
                #self.exports.remove({"user_id": new_user['user_id']})
            else:
                log.debug("To export: %s to %s" % (fqu, transfer_address))

            if nameRegistered(fqu):

                if ownerName(fqu, transfer_address):
                    log.debug("Name transferred, removing: %s" % fqu)
                    self.exports.remove({"user_id": new_user['user_id']})

                    refresh_resolver(user['username'])
                else:
                    log.debug("Processing: %s, %s" % (fqu, user['email']))
                    #try:
                    self.registrar_server.process_subsidized_nameop(fqu,
                                                                owner_privkey=hex_privkey,
                                                                transfer_address=transfer_address,
                                                                nameop='transfer', profile="")
                    #except Exception as e:
                    #    log.debug(e)
            else:

                log.debug("Not registered: %s" % fqu)

    def remove_registration_entry(self, username):

        check_user = self.users.find_one({"username": username})

        user_id = check_user['_id']

        check_register = self.registrations.find_one({"user_id": user_id})

        if check_register is None or check_user is None:
            log.debug("No such user")
        else:
            log.debug("Removing: %s" % username)
            self.registrations.remove({"user_id": user_id})

    def remove_user(self, username):

        check_user = self.users.find_one({"username": username})

        if check_user is None or '_id' not in check_user:
            log.debug("No such user")
        else:
            log.debug("Removing: %s" % username)
            #self.users.remove({"user_id": check_user['_id']})

    def reprocess_user(self, username, nameop=None):

        user = self.users.find_one({"username": username})

        if not self.validUser(user, None):
            log.debug("Need to remove: %s" % username)
            return

        if whiteListedUser(user['email'], user['profile']):
            log.debug("White-listed: %s" % user['email'])
        else:
            log.debug("Not registering: %s" % user['email'])
            #return

        fqu = user['username'] + "." + DEFAULT_NAMESPACE
        transfer_address = nmc_to_btc_address(user['namecoin_address'])

        data_value = convert_profile_format(user)

        log.debug("Reprocessing user: %s" % fqu)

        self.registrar_server.process_nameop(fqu, data_value,
                                             transfer_address,
                                             nameop=nameop)

    def release_username(self, username, new_owner):

        user = self.users.find_one({"username": new_owner})

        fqu = username + "." + DEFAULT_NAMESPACE
        transfer_address = nmc_to_btc_address(user['namecoin_address'])
        profile = user['profile']

        self.registrar_server.release_username(fqu, profile,
                                               transfer_address)

    def change_username(self, username, new_username):

        user = self.users.find_one({"username": username})
        user['username'] = new_username
        self.users.save(user)

    def change_email(self, current_email, new_email):

        user = self.users.find_one({"email": current_email})
        user['email'] = new_email
        self.users.save(user)

    def display_stats(self):

        log.debug("Pending registrations: %s" % self.registrations.find().count())
        log.debug("Pending updates: %s" % self.updates.find().count())

    def display_userinfo(self, username=None, email=None):

        if username is None and email is None:
            log.debug("Provide username or email")
            return
        elif username is not None:
            user = self.users.find_one({"username": username})
            pprint(user)
        elif email is not None:
            user = self.users.find_one({"email": email})
            pprint(user)

        return user['profile'], user['ecdsa_public_key']

    def display_current_states(self):
        """
            Display current states of all pending registrations
        """

        counter_register = 0
        counter_update = 0
        counter_dht = 0
        counter_transfer = 0

        for new_user in self.registrations.find(no_cursor_timeout=True):

            user = get_db_user_from_id(new_user, self.users)

            if not self.validUser(user, new_user):
                continue

            fqu = user['username'] + "." + DEFAULT_NAMESPACE
            transfer_address = nmc_to_btc_address(user['namecoin_address'])
            profile = user['profile']

            if not nameRegistered(fqu):
                counter_register += 1

            elif not profileonBlockchain(fqu, profile):
                counter_update += 1

            elif not profileonDHT(fqu, profile):
                counter_dht += 1

            elif not ownerName(fqu, transfer_address):
                counter_transfer += 1

        log.debug("Pending registrations: %s" % counter_register)
        log.debug("Pending updates: %s" % counter_update)
        log.debug("Pending DHT writes: %s" % counter_dht)
        log.debug("Pending transfers: %s" % counter_transfer)
