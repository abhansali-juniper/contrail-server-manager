import ast
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
import mock
from mock import PropertyMock
import requests

from server_mgr_db import ServerMgrDb as db
from server_mgr_logger import ServerMgrlogger
from server_mgr_logger import ServerMgrTransactionlogger as ServerMgrTlog
from server_mgr_main import VncServerManager


# Class to mock VncServerManager
class mock_VncServerManager(VncServerManager):
    def __init__(self, db_file_name, access_log):
        # Logger
        self._smgr_log = ServerMgrlogger()

        # Transaction logger
        self._smgr_trans_log = ServerMgrTlog()

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

        # Create user role
        role_data = {'role': 'user', 'level': 10}
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

        # Create user user
        username = 'user'
        password = 'c0ntrail123'
        role = 'user'
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
        bottle.route('/user', 'GET', self.inherited_get_user)
        bottle.route('/logout', 'GET', self.inherited_logout)
        bottle.route('/logout_success', 'GET',
                     self.inherited_get_logout_success)

        bottle.route('/login', 'POST', self.inherited_login)

    def inherited_get_user(self):
        return VncServerManager.get_user(self)

    def inherited_login(self):
        return VncServerManager.login(self)

    def inherited_logout(self):
        return VncServerManager.logout(self)

    def inherited_get_logout_success(self):
        return VncServerManager.get_logout_success(self)


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

    # Test sufficient_perms
    def testSufficientPerms(self):
        # When logged out
        result = self.vncServerManager.sufficient_perms()
        self.assertFalse(result)

        # When regular user
        with mock.patch('cork.Cork.current_user', new_callable=PropertyMock) \
                as mock_current_user:
            mock_current_user.return_value = \
                self.vncServerManager._backend.user('user')

            # Test all code paths
            result = self.vncServerManager.sufficient_perms(
                username='not_user')
            self.assertFalse(result)

            result = self.vncServerManager.sufficient_perms(role='admin',
                                                            fixed_role=True)
            self.assertFalse(result)

            result = self.vncServerManager.sufficient_perms(role='not_a_role')
            self.assertFalse(result)

            result = self.vncServerManager.sufficient_perms(role='admin')
            self.assertFalse(result)

            result = self.vncServerManager.sufficient_perms()
            self.assertTrue(result)

            result = self.vncServerManager.sufficient_perms(role='user')
            self.assertTrue(result)

    # Test determine_restrictions
    def testDetermineRestrictions(self):
        # When admin
        with mock.patch('cork.Cork.current_user', new_callable=PropertyMock) \
                as mock_current_user:
            mock_current_user.return_value = \
                self.vncServerManager._backend.user('admin')
            user_obj, username, is_admin, logged_in = \
                self.vncServerManager.determine_restrictions()
            self.assertIsNone(user_obj)
            self.assertIsNone(username)
            self.assertTrue(is_admin)
            self.assertTrue(logged_in)

        # When regular user
        with mock.patch('cork.Cork.current_user', new_callable=PropertyMock) \
                as mock_current_user:
            mock_current_user.return_value = \
                self.vncServerManager._backend.user('user')
            user_obj, username, is_admin, logged_in = \
                self.vncServerManager.determine_restrictions()
            self.assertEqual(user_obj.username, 'user')
            self.assertEqual(username, 'user')
            self.assertFalse(is_admin)
            self.assertTrue(logged_in)

        # When not logged in
        user_obj, username, is_admin, logged_in = \
            self.vncServerManager.determine_restrictions()
        self.assertIsNone(user_obj)
        self.assertIsNone(username)
        self.assertFalse(is_admin)
        self.assertFalse(logged_in)

    # Test current_user
    def testCurrentUser(self):
        # When logged in
        with mock.patch('cork.Cork.current_user', new_callable=PropertyMock) \
                as mock_current_user:
            mock_current_user.return_value = \
                self.vncServerManager._backend.user('user')
            result = self.vncServerManager.get_current_user()
            expected = dict()
            expected['user'] = 'user'
            self.assertEqual(result, expected)

        # When not logged in
        result = self.vncServerManager.get_current_user()
        expected = dict()
        self.assertEqual(result, expected)

    # Test login
    def testLogin(self):
        # User doesn't exist
        credentials = dict()
        credentials['username'] = 'wrong_username'
        credentials['password'] = 'wrong_password'
        response = requests.post('%slogin' % self.http,
                                 data=json.dumps(credentials),
                                 headers={'content-type': 'application/json'})
        self.assertEqual(response.content, 'Login failed.')

        # Wrong password for user who exists
        credentials = dict()
        credentials['username'] = 'admin'
        credentials['password'] = 'wrong_password'
        response = requests.post('%slogin' % self.http,
                                 data=json.dumps(credentials),
                                 headers={'content-type': 'application/json'})
        self.assertEqual(response.content, 'Login failed.')

        # Default admin credentials
        credentials = dict()
        credentials['username'] = 'admin'
        credentials['password'] = 'c0ntrail123'
        response = requests.post('%slogin' % self.http,
                                 data=json.dumps(credentials),
                                 headers={'content-type': 'application/json'})
        self.assertEqual(response.content, 'Login successful.')

    # Test logout
    def testLogout(self):
        # When not logged in
        response = requests.get('%slogout' % self.http)
        self.assertEqual(response.content, 'You are not logged in.')

        # When logged in
        credentials = {}
        credentials['username'] = 'admin'
        credentials['password'] = 'c0ntrail123'
        s = requests.Session()
        r1 = s.post('%slogin' % self.http, data=json.dumps(credentials),
               headers={'content-type': 'application/json'})
        self.assertEqual(r1.content, 'Login successful.')
        r2 = s.get('%slogout' % self.http)
        self.assertEqual(r2.content, 'Logout successful.')

    # Test get_user
    def testGetUser(self):
        # When not logged in
        response = requests.get('%suser' % self.http)
        self.assertEqual(response.content, 'Error: Insufficient permissions.')

        # When regular user
        credentials = dict()
        credentials['username'] = 'user'
        credentials['password'] = 'c0ntrail123'
        s = requests.Session()
        s.post('%slogin' % self.http, data=json.dumps(credentials),
                    headers={'content-type': 'application/json'})
        r = s.get('%suser' % self.http)
        user_dict = {"username": "user"}
        expected = dict()
        expected["user"] = [user_dict]
        returned_dict = ast.literal_eval(r.content)
        self.assertEqual(returned_dict, expected)


        # When admin user
        credentials = dict()
        credentials['username'] = 'admin'
        credentials['password'] = 'c0ntrail123'
        s = requests.Session()
        s.post('%slogin' % self.http, data=json.dumps(credentials),
                headers={'content-type': 'application/json'})
        r = s.get('%suser' % self.http)
        user_dict = {"username": "user"}
        admin_dict = {"username": "admin"}
        expected = dict()
        expected_users = [user_dict, admin_dict]
        expected["user"] = expected_users
        returned_dict = ast.literal_eval(r.content)
        returned_users = returned_dict.get("user", None)
        self.assertIsNotNone(returned_users)
        self.assertItemsEqual(expected_users, returned_users)

        '''
        self.assertTrue(type(returned_dict) is dict)
        returned_users = returned_dict.get("user", None)
        self.assertIsNotNone(returned_users)
        self.assertIn(user_dict, returned_users)
        self.assertIn(admin_dict, returned_users)
        '''

# TestSuite for RBAC
def rbac_suite():
    suite = unittest.TestSuite()
    suite.addTest(TestRBAC('testSufficientPerms'))
    suite.addTest(TestRBAC('testDetermineRestrictions'))
    suite.addTest(TestRBAC('testCurrentUser'))
    suite.addTest(TestRBAC('testLogin'))
    suite.addTest(TestRBAC('testLogout'))
    suite.addTest(TestRBAC('testGetUser'))
    return suite
