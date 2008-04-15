#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Helper CGI for logins/logout in the development application server.

This CGI has these parameters:

  continue: URL to redirect to after a login or logout has completed.
  email: Email address to set for the client.
  admin: If 'True', the client should be logged in as an admin.
  action: What action to take ('Login' or 'Logout').

To view the current user information and a form for logging in and out,
supply no parameters.
"""


import Cookie
import cgi
import os
import sys
import urllib
import logging
import sha
from django.utils import simplejson
from google.appengine.api import urlfetch


CONTINUE_PARAM = 'continue'
EMAIL_PARAM = 'email'
ADMIN_PARAM = 'admin'
ACTION_PARAM = 'action'

LOGOUT_ACTION = 'Logout'
LOGIN_ACTION = 'Login'

LOGOUT_PARAM = 'action=%s' % LOGOUT_ACTION

COOKIE_NAME = 'dev_appserver_login'

# changing this will invalidate all outstanding sessions
COOKIE_SECRET = 'so_super_secret_omg' 

def GetUserInfo(http_cookie, cookie_name=COOKIE_NAME):
  """Get the requestor's user info from the HTTP cookie in the CGI environment.

  Args:
    http_cookie: Value of the HTTP_COOKIE environment variable.
    cookie_name: Name of the cookie that stores the user info.

  Returns:
    Tuple (email, admin) where:
      email: The user's email address, if any.
      admin: True if the user is an admin; False otherwise.
  """
  cookie = Cookie.SimpleCookie(http_cookie)

  cookie_value = ''
  valid_cookie = True
  if cookie_name in cookie:
    cookie_value = cookie[cookie_name].value

  email, nickname, admin, hsh = (cookie_value.split(':') + ['', '', '', ''])[:4]

  if email == '':
    nickname = ''
    admin = ''
  else:
    vhsh = sha.new(email+nickname+admin+COOKIE_SECRET).hexdigest()
    if hsh != vhsh:
      logging.info(email+" had invalid cookie")
      valid_cookie = False
      # todo clear the cookie
      # redirect to os.environ['PATH_INFO'] with the cookier clearing?
    
  return email, nickname, (admin == 'True'), valid_cookie


def CreateCookieData(email, nickname, admin):
  """Creates cookie payload data.

  Args:
    email, nickname, admin: Parameters to incorporate into the cookie.

  Returns:
    String containing the cookie payload, with a validating hash
  """
  
  admin_string = 'False'
  if admin:
    admin_string = 'True'
  hsh = sha.new(email+nickname+admin_string+COOKIE_SECRET).hexdigest()
    
  return '%s:%s:%s:%s' % (email, nickname, admin_string, hsh)


def SetUserInfoCookie(email, nickname, admin, cookie_name=COOKIE_NAME):
  """Creates a cookie to set the user information for the requestor.

  Args:
    email: Email to set for the user.
    nickname: Nickname to set for the user.
    admin: True if the user should be admin; False otherwise.
    cookie_name: Name of the cookie that stores the user info.

  Returns:
    'Set-Cookie' header for setting the user info of the requestor.
  """
  
  cookie_value = CreateCookieData(email, nickname, admin)
  set_cookie = Cookie.SimpleCookie()
  set_cookie[cookie_name] = cookie_value
  set_cookie[cookie_name]['path'] = '/'
  return '%s\r\n' % set_cookie


def ClearUserInfoCookie(cookie_name=COOKIE_NAME):
  """Clears the user info cookie from the requestor, logging them out.

  Args:
    cookie_name: Name of the cookie that stores the user info.

  Returns:
    'Set-Cookie' header for clearing the user info of the requestor.
  """
  set_cookie = Cookie.SimpleCookie()
  set_cookie[cookie_name] = ''
  set_cookie[cookie_name]['path'] = '/'
  set_cookie[cookie_name]['max-age'] = '0'
  return '%s\r\n' % set_cookie


def LoginRedirect(login_url,
                  hostname,
                  port,
                  relative_url,
                  outfile):
  """Writes a login redirection URL to a user.

  Args:
    login_url: Relative URL which should be used for handling user logins.
    hostname: Name of the host on which the webserver is running.
    port: Port on which the webserver is running.
    relative_url: String containing the URL accessed.
    outfile: File-like object to which the response should be written.
  """
  dest_url = "http://%s:%s%s" % (hostname, port, relative_url)
  redirect_url = 'http://%s:%s%s?%s=%s' % (hostname,
                                           # port,
                                           '80',
                                           login_url,
                                           CONTINUE_PARAM,
                                           urllib.quote(dest_url))
  outfile.write('Status: 302 Requires login\r\n')
  outfile.write('Location: %s\r\n\r\n' % redirect_url)

def LoginServiceRedirect(dest_url, endpoint, ah_url, outfile):
  redirect_url = '%s?%s=%s' % (endpoint, 
                        CONTINUE_PARAM, 
                        urllib.quote('%s?%s=%s' %(ah_url,CONTINUE_PARAM,dest_url)))
                                           
  outfile.write('Status: 302 Redirecting to login service URL\r\n')
  outfile.write('Location: %s\r\n' % redirect_url)
  outfile.write('\r\n')

def Logout(continue_url, outfile):
  output_headers = []
  output_headers.append(ClearUserInfoCookie())  

  outfile.write('Status: 302 Redirecting to continue URL\r\n')
  for header in output_headers:
    outfile.write(header)
  outfile.write('Location: %s\r\n' % continue_url)
  outfile.write('\r\n')
  
  
def LoginFromAuth(token, continue_url, auth_endpoint, host, outfile):
  """Uses the auth token to fetch the userdata from appdrop, then sets the cookie"""
  output_headers = []
  
  auth_url = "%s?token=%s&app=%s" % (auth_endpoint,token,host)
  logging.info('fetching: '+auth_url)
  result = urlfetch.fetch(auth_url);
  logging.info('result: '+result.content)
  if (result.status_code == 200):
    userinfo = simplejson.loads(result.content)
    output_headers.append(SetUserInfoCookie(userinfo['email'], userinfo['nickname'], userinfo['admin']))
    

  outfile.write('Status: 302 Redirecting to continue URL\r\n')
  for header in output_headers:
    outfile.write(header)
  outfile.write('Location: %s\r\n' % continue_url)
  outfile.write('\r\n')


def main():
  """Runs the login and logout CGI redirector script."""
  form = cgi.FieldStorage()
  ah_path = os.environ['PATH_INFO']
  host = 'http://'+os.environ['SERVER_NAME']
  # if os.environ['SERVER_PORT'] != '80':
    # host = host + ":" + os.environ['SERVER_PORT']
  
  ah_login_url = host+ah_path
  
  action = form.getfirst(ACTION_PARAM)

  if action == None:
    action = 'Login'
  
  continue_url = form.getfirst(CONTINUE_PARAM, '')
  auth_token = form.getfirst('auth','')
  # todo these need changing on deploy
  # auth_endpoint = "http://localhost:3001/auth"
  # login_service_endpoint = "http://localhost:3001/login"
  auth_endpoint = "http://appdrop.com/auth"
  login_service_endpoint = "http://appdrop.com/login"
  
  if action.lower() == LOGOUT_ACTION.lower():
    Logout(continue_url, sys.stdout)
  elif auth_token == '':
    LoginServiceRedirect(continue_url, login_service_endpoint, ah_login_url, sys.stdout)
  else:
    LoginFromAuth(auth_token, continue_url, auth_endpoint, host, sys.stdout)

  return 0


if __name__ == '__main__':
  main()
