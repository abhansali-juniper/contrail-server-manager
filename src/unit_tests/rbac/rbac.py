import datetime
import errno
import gevent
import json
import os
import socket
import sys
import unittest

from beaker.middleware import SessionMiddleware
import bottle
from cork import Cork
from cork.backends import SQLiteBackend
import requests

from server_mgr_db import ServerMgrDb as db
from server_mgr_main import VncServerManager


# Class to mock VncServerManager
class mock_VncServerManager(VncServerManager):
    def __init__(self, db_file_name, access_log):
        # Connect to database
        self._serverDb = db(db_file_name)

        self._pipe_start_app = bottle.app()

        # SQLite Backend
        self._sqlite_backend = SQLiteBackend(
            filename=db_file_name, users_tname='user_table',
            roles_tname='role_table', pending_reg_tname='register_table')
        self._sqlite_backend._connection = self._serverDb._con
        self._backend = Cork(backend=self._sqlite_backend)

        # Create administrator role
        role_data = {'role': 'administrator', 'level': 100}
        self._serverDb.add_role(role_data=role_data)

        # Create admin user
        username = 'admin'
        password = 'c0ntrail123'
        role = 'administrator'
        tstamp = str(datetime.datetime.utcnow())
        h = self._backend._hash(username, password)
        h = h.decode('ascii')
        user_data = {'username': username, 'role': role, 'hash': h,
                     'email_addr': '', 'desc': '', 'creation_date': tstamp,
                     'last_login': tstamp}
        self._serverDb.add_user(user_data=user_data)

        # Session
        config = {
            'session.encrypt_key': 'dsfjlk234hiouhADSF',
            'session.type': 'cookie',
            'session.validate_key': 'sfklasd'
        }
        self._pipe_start_app = SessionMiddleware(wrap_app=self._pipe_start_app,
                                                 config=config)

        # Authentication logging
        self.ACCESS_LOG = access_log

        # Bottle routes
        bottle.route('/login', 'POST', self.inherited_login)

    def inherited_login(self):
        return VncServerManager.login(self)


# Utility function to get a free port for running bottle server.
def get_free_port():
    tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp_sock.bind(('', 0))
    free_port = tmp_sock.getsockname()[1]
    tmp_sock.close()

    return free_port
# end get_free_port


# Utility function to make test functions wait till server manager
# is up and running.
def block_till_port_listened(server_ip, server_port):
    svr_running = False
    while not svr_running:
        try:
            s = socket.create_connection((server_ip, server_port))
            s.close()
            svr_running = True
        except Exception as err:
            if err.errno == errno.ECONNREFUSED:
                print "port %s not up, retrying in 2 secs" % (server_port)
                gevent.sleep(2)
# end block_till_port_listened


# Function to launch server manager
def launch_server_manager(vnc_server_manager, host, port):
    # Start app
    pipe_start_app = vnc_server_manager._pipe_start_app
    bottle.run(app=pipe_start_app, host=host, port=port, quiet=True)


# Class to test RBAC
class TestRBAC(unittest.TestCase):
    DB_FILE_NAME = 'smgr_test_data.db'
    ACCESS_LOG = 'access.log'
    HOST = '127.0.0.1'

    # Set up environment for testing
    def setUp(self):
        # Delete temporary files
        try:
            os.remove(TestRBAC.DB_FILE_NAME)
            os.remove(TestRBAC.ACCESS_LOG)
        except:
            pass

        # Find free port
        self.port = get_free_port()
        self.http = 'http://%s:%s/' % (TestRBAC.HOST, self.port)

        # Launch server manager
        self.vncServerManager = mock_VncServerManager(
            db_file_name=TestRBAC.DB_FILE_NAME, access_log=TestRBAC.ACCESS_LOG)
        self.greenlet = gevent.spawn(launch_server_manager,
                                     self.vncServerManager, TestRBAC.HOST,
                                     self.port)

        # Wait until server manager is up
        block_till_port_listened(TestRBAC.HOST, self.port)

    # Tear down testing environment
    def tearDown(self):
        # Bring down server manager
        self.greenlet.kill()
        del self.greenlet
        del self.vncServerManager
        del self.port

        # Delete temporary files
        try:
            os.remove(TestRBAC.DB_FILE_NAME)
            os.remove(TestRBAC.ACCESS_LOG)
        except:
            pass

    # Test sufficient_perms when logged out
    def testSufficientPerms(self):
        result = self.vncServerManager.sufficient_perms()
        self.assertFalse(result)
        pass

    # Test determine_restrictions when logged out
    def testDetermineRestrictions(self):
        user_obj, username, is_admin, logged_in = \
                self.vncServerManager.determine_restrictions()
        self.assertIsNone(user_obj)
        self.assertIsNone(username)
        self.assertFalse(is_admin)
        self.assertFalse(logged_in)

    # Test login with invalid credentials
    def testLoginInvalid(self):
        # User doesn't exist
        credentials = {}
        credentials['username'] = 'wrong_username'
        credentials['password'] = 'wrong_password'
        response = requests.post('%slogin' % self.http,
                                 data=json.dumps(credentials),
                                 headers={'content-type': 'application/json'})
        self.assertEqual(response.content, 'Login failed.')

        # Wrong password for user who exists
        credentials = {}
        credentials['username'] = 'admin'
        credentials['password'] = 'wrong_password'
        response = requests.post('%slogin' % self.http,
                                 data=json.dumps(credentials),
                                 headers={'content-type': 'application/json'})
        self.assertEqual(response.content, 'Login failed.')

    # Test login with valid credentials
    def testLoginValid(self):
        # Default admin credentials
        credentials = {}
        credentials['username'] = 'admin'
        credentials['password'] = 'c0ntrail123'
        response = requests.post('%slogin' % self.http,
                                data=json.dumps(credentials),
                                headers={'content-type': 'application/json'})
        self.assertEqual(response.content, 'Login successful.')


# TestSuite for RBAC
def rbac_suite():
    suite = unittest.TestSuite()
    suite.addTest(TestRBAC('testSufficientPerms'))
    suite.addTest(TestRBAC('testDetermineRestrictions'))
    suite.addTest(TestRBAC('testLoginInvalid'))
    suite.addTest(TestRBAC('testLoginValid'))
    return suite
