/*
 * Copyright (c) 2018, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

'use strict';

const ClientResponse = require("./ClientResponse.js");
const http = require("http");
const https = require("https");
const queryString = require("querystring");
const url = require("url");

/**
 * RESTful WebService call builder. This provides the ability to call RESTful WebServices using a builder pattern to
 * set up all the necessary request information and parse the response.
 *
 * @constructor
 */
const RESTClient = function() {
  this.headers = {};
  this.parameters = null;
  this.restUrl = null;
  this.body = null;
  this.certificate = null;
  this.key = null;
  this.method = null;
};

RESTClient.constructor = RESTClient;
RESTClient.prototype = {
  /**
   * Sets the authorization header using a key
   *
   * @param {string} key The value of the authorization header.
   * @returns {RESTClient}
   */
  authorization: function(key) {
    this.header('Authorization', key);
    return this;
  },

  /**
   * Sets the authorization header using username and password
   *
   * @param {string} username
   * @param {string} password
   * @returns {RESTClient}
   */
  basicAuthorization: function(username, password) {
    if (username && password) {
      this.header('Authorization', 'Basic ' + new Buffer(username + ':' + password).toString('base64'));
    }
    return this;
  },

  /**
   * Sets the body of the client request.
   *
   * @param {Object} body The object to be written to the request body as JSON.
   * @returns {RESTClient}
   */
  setJSONBody: function(body) {
    this.body = JSON.stringify(body);
    this.header('Content-Type', 'application/json');
    this.header('Content-Length', Buffer.byteLength(this.body));
    return this;
  },

  /**
   * Sets the ssl certificate for request to https endpoints.
   *
   * @param {string} certificate
   * @returns {RESTClient}
   */
  setCertificate: function(certificate) {
    this.certificate = certificate;
    return this;
  },

  /**
   * Sets the http method to DELETE
   *
   * @returns {RESTClient}
   */
  delete: function() {
    this.method = 'DELETE';
    return this;
  },

  /**
   * Sets the http method to GET
   *
   * @returns {RESTClient}
   */
  get: function() {
    this.method = 'GET';
    return this;
  },

  /**
   * Sets the http method to POST
   *
   * @returns {RESTClient}
   */
  post: function() {
    this.method = 'POST';
    return this;
  },

  /**
   * Sets the http method to PUT
   *
   * @returns {RESTClient}
   */
  put: function() {
    this.method = 'PUT';
    return this;
  },

  /**
   * Creates the request to the REST API.  Takes a responseHandler which is a function that handles the response from
   * the REST API.
   *
   *  @callback responseHandler The response handler function callback.
   */
  go: function(responseHandler) {
    if (this.parameters) {
      if (this.restUrl.indexOf('?') === -1) {
        this.restUrl = this.restUrl + '?';
      }
      this.restUrl = this.restUrl + queryString.stringify(this.parameters);
    }
    const scheme = url.parse(this.restUrl);
    const myHttp = scheme.protocol === 'https:' ? https : http;

    let port = 443;
    if (scheme.port) {
      port = scheme.port;
    } else if (scheme.protocol === 'http:') {
      port = 80;
    }

    const options = {
      hostname: scheme.hostname,
      port: port,
      path: scheme.path,
      method: this.method,
      headers: this.headers
    };

    if (scheme.protocol === 'https:') {
      options.key = this.key;
      options.cert = this.certificate;
    }

    const clientResponse = new ClientResponse();
    const request = myHttp.request(options, function(response) {
      clientResponse.statusCode = response.statusCode;
      response.on('data', function(data) {
        let json = data;
        try {
          json = JSON.parse(data);
        } catch (err) {
        }
        if (clientResponse.wasSuccessful()) {
          clientResponse.successResponse = json;
        } else {
          clientResponse.errorResponse = json;
        }
      }).on('error', function(error) {
        clientResponse.exception = error;
      }).on('exception', function(exception) {
        clientResponse.exception = exception;
      }).on('end', function() {
        responseHandler(clientResponse);
      });
    });
    request.on('error', function(error) {
      clientResponse.statusCode = 500;
      clientResponse.exception = error;
      responseHandler(clientResponse);
    });
    request.end(this.body);
  },

  /**
   * Creates a header field in the format 'key' : value
   *
   * @param {string} key
   * @param {Object} value
   * @returns {RESTClient}
   */
  header: function(key, value) {
    this.headers[key] = value;
    return this;
  },

  /**
   * Sets the entire header field.
   *
   * @param {string} headers The headers in a JSON object of key value pairs.
   * @returns {RESTClient}
   */
  setHeaders: function(headers) {
    this.headers = headers;
    return this;
  },

  /**
   * Sets the ssl key for request to https endpoints.
   * @param {string} key
   * @returns {RESTClient}
   */
  setKey: function(key) {
    this.key = key;
    return this;
  },

  /**
   * Sets the uri of the REST request
   * @param {?string} uri
   * @returns {RESTClient}
   */
  uri: function(uri) {
    if (uri === null || typeof this.restUrl === 'undefined') {
      return this;
    }

    if (this.restUrl.charAt(this.restUrl.length - 1) === '/' && uri.charAt(0) === '/') {
      this.restUrl = this.restUrl + uri.substring(1);
    } else if (this.restUrl.charAt(this.restUrl.length - 1) !== '/' && uri.charAt(0) !== '/') {
      this.restUrl = this.restUrl + '/' + uri;
    } else {
      this.restUrl = this.restUrl + uri;
    }

    return this;
  },

  /**
   * Sets the host of the REST request.
   *
   * @param {string} url
   * @returns {RESTClient}
   */
  setUrl: function(url) {
    this.restUrl = url;
    return this;
  },

  /**
   * Adds url parameters to the REST request.
   *
   * @param {!string} name The name of the parameter.
   * @param {?string|Object|number} value The value of the URL parameter, may be a string, object or number.
   * @returns {RESTClient}
   */
  urlParameter: function(name, value) {
    if (value !== null && typeof value !== 'undefined') {
      if (this.parameters === null) {
        this.parameters = {};
      }
      const values = this.parameters[name];
      if (values === undefined) {
        this.parameters[name] = [];
      }
      if (typeof value === 'object') {
        for (let v in value) {
          if (value.hasOwnProperty(v)) {
            this.parameters[name].push(value[v]);
          }
        }
      } else {
        this.parameters[name].push(value);
      }
    }
    return this;
  },

  /**
   * Adds a url path segments to the REST request.
   *
   * @param {?string} segment
   * @returns {RESTClient}
   */
  urlSegment: function(segment) {
    if (segment !== null && typeof segment !== 'undefined') {
      if (this.restUrl.charAt(this.restUrl.length - 1) !== '/') {
        this.restUrl = this.restUrl + '/';
      }
      this.restUrl = this.restUrl + segment;
    }
    return this;
  }
};

module.exports = RESTClient;