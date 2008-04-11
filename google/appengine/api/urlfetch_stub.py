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

"""Stub version of the urlfetch API, based on httplib."""



import httplib
import logging
import socket
import urlparse

from google.appengine.api import urlfetch_errors
from google.appengine.api import urlfetch_service_pb
from google.appengine.runtime import apiproxy_errors


class URLFetchServiceStub:
  """Stub version of the urlfetch API to be used with apiproxy_stub_map."""

  def MakeSyncCall(self, service, call, request, response):
    """The main RPC entry point.

    Arg:
      service: Must be 'urlfetch'.
      call: A string representing the rpc to make.  Must be part of
        URLFetchService.
      request: A protocol buffer of the type corresponding to 'call'.
      response: A protocol buffer of the type corresponding to 'call'.
    """
    assert service == 'urlfetch'
    assert request.IsInitialized()

    attr = getattr(self, '_Dynamic_' + call)
    attr(request, response)

  def _Dynamic_Fetch(self, request, response):
    """Trivial implementation of URLFetchService::Fetch().

    Args:
      request: the fetch to perform, a URLFetchRequest
      response: the fetch response, a URLFetchResponse
    """
    (protocol, host, path, parameters, query, fragment) = urlparse.urlparse(request.url())

    payload = ''
    if request.method() == urlfetch_service_pb.URLFetchRequest.GET:
      method = 'GET'
    elif request.method() == urlfetch_service_pb.URLFetchRequest.POST:
      method = 'POST'
      payload = request.payload()
    elif request.method() == urlfetch_service_pb.URLFetchRequest.HEAD:
      method = 'HEAD'
    elif request.method() == urlfetch_service_pb.URLFetchRequest.PUT:
      method = 'PUT'
      payload = request.payload()
    elif request.method() == urlfetch_service_pb.URLFetchRequest.HEAD:
      method = 'DELETE'
    else:
      logging.error('Invalid method: %s', request.method())
      raise apiproxy_errors.ApplicationError(
        urlfetch_service_pb.URLFetchServiceError.UNSPECIFIED_ERROR)

    if not (protocol == 'http' or protocol == 'https'):
      logging.error('Invalid protocol: %s', protocol)
      raise apiproxy_errors.ApplicationError(
        urlfetch_service_pb.URLFetchServiceError.INVALID_URL)

    url = urlparse.urlunparse(('', '', path, parameters, query, fragment))
    logging.debug('Fetching URL: %s', url)

    headers = {'Content-Length': len(payload),
               'Host': host,
               'Accept': '*/*',
               }
    for header in request.header_list():
      headers[header.key()] = header.value()

    logging.debug('Making HTTP request: host = %s, '
                  'url = %s, payload = %s, headers = %s',
                  host, url, payload, headers)

    try:
      if protocol == 'http':
        connection = httplib.HTTPConnection(host)
      elif protocol == 'https':
        connection = httplib.HTTPSConnection(host)
      else:
        raise apiproxy_errors.ApplicationError(
            urlfetch_service_pb.URLFetchServiceError.INVALID_URL)
      try:
        connection.request(method, url, payload, headers)
        http_response = connection.getresponse()
        http_response_data = http_response.read()
      finally:
        connection.close()
    except (httplib.error, socket.error, IOError), e:
      raise apiproxy_errors.ApplicationError(
        urlfetch_service_pb.URLFetchServiceError.FETCH_ERROR, str(e))

    max_response_length = 1 << 20;
    response.set_statuscode(http_response.status)
    response.set_content(http_response_data[:max_response_length])
    for header_key, header_value in http_response.getheaders():
      header_proto = response.add_header()
      header_proto.set_key(header_key)
      header_proto.set_value(header_value)

    if len(http_response_data) > max_response_length:
      response.set_contentwastruncated(True)
