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

/**
 * A client response that provides the status code and the response of an REST API call.
 *
 * @constructor
 */
const ClientResponse = function() {
  this.statusCode = null;
  this.errorResponse = null;
  this.successResponse = null;
  this.exception = null;
};

ClientResponse.constructor = ClientResponse;
ClientResponse.prototype = {

  /**
   * @returns {boolean} return true if the request was successful.
   */
  wasSuccessful: function() {
    return this.statusCode >= 200 && this.statusCode <= 299 && this.exception === null;
  }
};

module.exports = ClientResponse;