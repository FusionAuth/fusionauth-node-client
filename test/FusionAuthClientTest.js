/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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

const tenantId = '65323339-6137-6531-3135-316238623265';
let client;

describe('#FusionAuthClient()', function() {

  beforeEach(async () => {
    const fusionauthUrl = process.env.FUSIONAUTH_URL || "https://local.fusionauth.io";
    const fusionauthApiKey = process.env.FUSIONAUTH_API_KEY || "bf69486b-4733-4470-a592-f1bfce7af580";
    client = new FusionAuthClient(fusionauthApiKey, fusionauthUrl);
    let response = await client.retrieveTenants();

    let desiredTenant = response.successResponse.tenants.find((tenant) => {
      return tenant.id === tenantId
    });

    if (!desiredTenant) {
      let defaultTenant = response.successResponse.tenants.find((tenant) => {
        return tenant.name === "Default"
      });
      defaultTenant.id = null;
      defaultTenant.name = "NodeJS Tenant";
      response = await client.createTenant(tenantId, {tenant: defaultTenant});
      chai.assert.isTrue(response.wasSuccessful(), "Failed to create the tenant");
    }

    // All future requests will use this now
    client.setTenantId(tenantId);

    try {
      await client.deleteApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0');
    } catch (ignore) {
    }

    // Cleanup the user (just in case a test partially failed)
    try {
      response = await client.retrieveUserByEmail("nodejs@fusionauth.io")
      if (response.wasSuccessful()) {
        await client.deleteUser(response.successResponse.user.id)
      }
    } catch (ignore) {
    }

    /** @type {ApplicationRequest} */
    const applicationRequest = {application: {name: 'Node.js FusionAuth Client'}};
    response = await client.createApplication('e5e2b0b3-c329-4b08-896c-d4f9f612b5c0', applicationRequest);

    chai.assert.strictEqual(response.statusCode, 200, "Failed to create the application");
    chai.assert.isNotNull(response.successResponse);
  });

  it('retrieveTenantTest', async () => {
    let response = await client.retrieveTenant(tenantId);
    chai.assert.isTrue(response.wasSuccessful());
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

  it('Patch a User', () => {
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

                   return client.patchUser(clientResponse.successResponse.user.id, {user: {
                       firstName: "Jan"
                     }}).then((clientResponse) => {
                       chai.assert.strictEqual(clientResponse.statusCode, 200);
                       chai.assert.isNotNull(clientResponse.successResponse);
                       chai.expect(clientResponse.successResponse).to.have.property('user');
                       chai.expect(clientResponse.successResponse.user).to.have.property('id');
                       chai.expect(clientResponse.successResponse.user.firstName).to.equal("Jan");
                   });
                  });
  });

});