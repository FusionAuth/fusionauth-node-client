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
const FusionAuthClient = fusionauth.FusionAuthClient;
const chai = require("chai");
let client;

describe('#FusionAuthClient()', function() {

  beforeEach(function() {
    client = new FusionAuthClient('bf69486b-4733-4470-a592-f1bfce7af580', 'http://fusionauth.local');
    return client.deleteApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0')
        .then(() => {
          const applicationRequest = {'application': {'name': 'Node.js FusionAuth Client'}};
          return client.createApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0', applicationRequest);
        })
        .then((response) => {
          chai.assert.strictEqual(response.statusCode, 200);
          chai.assert.isNotNull(response.successResponse);
        })
        .catch((response) => {
          if (response.statusCode === 404) {
            const applicationRequest = {'application': {'name': 'Node.js FusionAuth Client'}};
            return client.createApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0', applicationRequest);
          } else {
            console.info(response);
            console.info(response.statusCode);
            if (response.errorResponse) {
              console.error(JSON.stringify(response.errorResponse, null, 2));
            } else {
              console.error(response.exception);
            }
            chai.assert.isNotNull(null, 'Failed to setup FusionAuth');
          }
        });
  });

  it('Retrieve and Update System Configuration', () => {
    return client.retrieveSystemConfiguration()
        .then((clientResponse) => {
          chai.assert.strictEqual(clientResponse.statusCode, 200);
          chai.assert.isNotNull(clientResponse.successResponse);
          chai.expect(clientResponse.successResponse).to.have.property('systemConfiguration');
          const systemConfiguration = clientResponse.successResponse.systemConfiguration;
          chai.expect(systemConfiguration).to.have.property('emailConfiguration');
          chai.expect(systemConfiguration).to.have.property('failedAuthenticationConfiguration');
          chai.expect(systemConfiguration).to.have.property('jwtConfiguration');
          // Modify the System Configuration and assert the change.
          systemConfiguration.jwtConfiguration.issuer = 'node.fusionauth.io';
          return client.updateSystemConfiguration({'systemConfiguration': systemConfiguration});
        })
        .then((clientResponse) => {
          chai.assert.strictEqual(clientResponse.statusCode, 200);
          chai.assert.isNotNull(clientResponse.successResponse);
          chai.expect(clientResponse.successResponse).to.have.property('systemConfiguration');
          const systemConfiguration = clientResponse.successResponse.systemConfiguration;
          chai.expect(systemConfiguration).to.have.property('jwtConfiguration');
          chai.assert.equal('node.fusionauth.io', systemConfiguration.jwtConfiguration.issuer);
        });
  });

  it('Create and Delete a User', () => {
    return client.createUser(null, {
          'user': {
            'email': 'nodejs@fusionauth.io',
            'firstName': 'Jäne',
            'password': 'password'
          },
          'skipVerification': true
        })
        .then((clientResponse) => {
          chai.assert.strictEqual(clientResponse.statusCode, 200);
          chai.assert.isNotNull(clientResponse.successResponse);
          chai.expect(clientResponse.successResponse).to.have.property('user');
          chai.expect(clientResponse.successResponse.user).to.have.property('id');
          return client.deleteUser(clientResponse.successResponse.user.id);
        })
        .then((clientResponse) => {
          chai.assert.strictEqual(clientResponse.statusCode, 200);
          chai.assert.isNull(clientResponse.successResponse);
          return client.retrieveUserByEmail('nodejs@fusionauth.io');
        })
        .catch((clientResponse) => {
          if (clientResponse.statusCode === 400) {
            console.error(JSON.stringify(clientResponse.errorResponse, null, 2));
          }

          chai.assert.strictEqual(clientResponse.statusCode, 404);
        });
  });

});