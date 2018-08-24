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

/* jshint mocha:     true  */

'use strict';

const fusionauth = require('../index');
const RESTClient = fusionauth.RESTClient;
const chai = require('chai');
let client;

describe('#RESTClient()', function() {
  it('Basic Authorization is Base64 Encoded', () => {
    client = new RESTClient().basicAuthorization('user', 'secret');
    chai.assert.equal(client.headers.Authorization, 'Basic dXNlcjpzZWNyZXQ=', client.headers.Authorization);
  });
});