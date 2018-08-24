/*
 * Copyright (c) 2018, FusionAuth, All Rights Reserved
 */

/* jshint mocha:     true  */

'use strict';

const fusionauth = require('../index');
const chai = require('chai');

describe('#JWTManager()', function() {
  it('Simple revoke and isValid', () => {
    fusionauth.JWTManager.revoke('759e9db6-39a6-4089-9861-48813118a853', 600);
    chai.assert.isTrue(fusionauth.JWTManager.isValid({
      'sub': '759e9db6-39a6-4089-9861-48813118a853',
      'exp': Date.now()
    }));
    chai.assert.isTrue(fusionauth.JWTManager.isValid({
      'sub': '00000000-0000-0000-0000-000000000001',
      'exp': Date.now()
    }));
  });
});