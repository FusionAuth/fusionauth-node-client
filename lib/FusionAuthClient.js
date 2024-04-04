/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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

const RESTClient = require('./RESTClient.js');
var Promise = require('promise');
var querystring = require('querystring');

const FusionAuthClient = function(apiKey, host) {
  this.apiKey = apiKey;
  this.host = host;
  this.tenantId = null;
};

FusionAuthClient.constructor = FusionAuthClient;
//noinspection JSUnusedGlobalSymbols
FusionAuthClient.prototype = {

  setTenantId: function(tenantId) {
    this.tenantId = tenantId;
    return this;
  },

  /**
   * Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
   * "actioner". Both user ids are required in the request object.
   *
   * @param {ActionRequest} request The action request that includes all the information about the action being taken including
   *    the Id of the action, any options and the duration (if applicable).
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  actionUser: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Activates the FusionAuth Reactor using a license Id and optionally a license text (for air-gapped deployments)
   *
   * @param {ReactorRequest} request An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  activateReactor: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/reactor')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Adds a user to an existing family. The family Id must be specified.
   *
   * @param {UUIDString} familyId The Id of the family.
   * @param {FamilyRequest} request The request object that contains all the information used to determine which user to add to the family.
   * @return {Promise<ClientResponse<FamilyResponse>>} A Promise for the FusionAuth call.
   */
  addUserToFamily: function(familyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family')
          .urlSegment(familyId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Approve a device grant.
   *
   * @param {?string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
   * @param {?string} client_secret (Optional) The client secret. This value will be required if client authentication is enabled.
   * @param {string} token The access token used to identify the user.
   * @param {string} user_code The end-user verification code.
   * @return {Promise<ClientResponse<DeviceApprovalResponse>>} A Promise for the FusionAuth call.
   */
  approveDevice: function(client_id, client_secret, token, user_code) {
    var body = {
      client_id: client_id,
      client_secret: client_secret,
      token: token,
      user_code: user_code
    };
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/oauth2/device/approve')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Cancels the user action.
   *
   * @param {UUIDString} actionId The action Id of the action to cancel.
   * @param {ActionRequest} request The action request that contains the information about the cancellation.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  cancelAction: function(actionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlSegment(actionId)
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
   * and they clicked on a link to reset their password.
   * 
   * As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
   * the value in the request body.
   *
   * @param {string} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
   * @param {ChangePasswordRequest} request The change password request that contains all the information used to change the password.
   * @return {Promise<ClientResponse<ChangePasswordResponse>>} A Promise for the FusionAuth call.
   */
  changePassword: function(changePasswordId, request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/change-password')
          .urlSegment(changePasswordId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Changes a user's password using their identity (loginId and password). Using a loginId instead of the changePasswordId
   * bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
   * method.
   *
   * @param {ChangePasswordRequest} request The change password request that contains all the information used to change the password.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  changePasswordByIdentity: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/change-password')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
   * When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   * your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
   * 
   * An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   *
   * @param {string} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  checkChangePasswordUsingId: function(changePasswordId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/change-password')
          .urlSegment(changePasswordId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
   * When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   * your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
   * 
   * An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  checkChangePasswordUsingJWT: function(encodedJWT) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/change-password')
          .authorization('Bearer ' + encodedJWT)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
   * When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   * your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
   * 
   * An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   *
   * @param {string} loginId The loginId of the User that you intend to change the password for.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  checkChangePasswordUsingLoginId: function(loginId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/change-password')
          .urlParameter('username', loginId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Make a Client Credentials grant request to obtain an access token.
   *
   * @param {?string} client_id (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {?string} client_secret (Optional) The client secret used to authenticate this request.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {?string} scope (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.
   * @return {Promise<ClientResponse<AccessToken>>} A Promise for the FusionAuth call.
   */
  clientCredentialsGrant: function(client_id, client_secret, scope) {
    var body = {
      client_id: client_id,
      client_secret: client_secret,
      grant_type: "client_credentials",
      scope: scope
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/token')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Adds a comment to the user's account.
   *
   * @param {UserCommentRequest} request The request object that contains all the information used to create the user comment.
   * @return {Promise<ClientResponse<UserCommentResponse>>} A Promise for the FusionAuth call.
   */
  commentOnUser: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/comment')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
   *
   * @param {WebAuthnLoginRequest} request An object containing data necessary for completing the authentication ceremony
   * @return {Promise<ClientResponse<WebAuthnAssertResponse>>} A Promise for the FusionAuth call.
   */
  completeWebAuthnAssertion: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/webauthn/assert')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
   *
   * @param {WebAuthnLoginRequest} request An object containing data necessary for completing the authentication ceremony
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  completeWebAuthnLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/webauthn/login')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
   *
   * @param {WebAuthnRegisterCompleteRequest} request An object containing data necessary for completing the registration ceremony
   * @return {Promise<ClientResponse<WebAuthnRegisterCompleteResponse>>} A Promise for the FusionAuth call.
   */
  completeWebAuthnRegistration: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn/register/complete')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
   * an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted 
   * to that API key.
   * 
   * If an API key is locked to a tenant, it can only create API Keys for that same tenant.
   *
   * @param {?UUIDString} keyId (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.
   * @param {APIKeyRequest} request The request object that contains all the information needed to create the APIKey.
   * @return {Promise<ClientResponse<APIKeyResponse>>} A Promise for the FusionAuth call.
   */
  createAPIKey: function(keyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/api-key')
          .urlSegment(keyId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
   *
   * @param {?UUIDString} applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
   * @param {ApplicationRequest} request The request object that contains all the information used to create the application.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  createApplication: function(applicationId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a new role for an application. You must specify the Id of the application you are creating the role for.
   * You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
   *
   * @param {UUIDString} applicationId The Id of the application to create the role on.
   * @param {?UUIDString} roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
   * @param {ApplicationRequest} request The request object that contains all the information used to create the application role.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  createApplicationRole: function(applicationId, roleId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("role")
          .urlSegment(roleId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
   * make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
   * written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
   *
   * @param {AuditLogRequest} request The request object that contains all the information used to create the audit log entry.
   * @return {Promise<ClientResponse<AuditLogResponse>>} A Promise for the FusionAuth call.
   */
  createAuditLog: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/audit-log')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
   *
   * @param {?UUIDString} connectorId (Optional) The Id for the connector. If not provided a secure random UUID will be generated.
   * @param {ConnectorRequest} request The request object that contains all the information used to create the connector.
   * @return {Promise<ClientResponse<ConnectorResponse>>} A Promise for the FusionAuth call.
   */
  createConnector: function(connectorId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/connector')
          .urlSegment(connectorId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
   *
   * @param {?UUIDString} consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
   * @param {ConsentRequest} request The request object that contains all the information used to create the consent.
   * @return {Promise<ClientResponse<ConsentResponse>>} A Promise for the FusionAuth call.
   */
  createConsent: function(consentId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent')
          .urlSegment(consentId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
   *
   * @param {?UUIDString} emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
   * @param {EmailTemplateRequest} request The request object that contains all the information used to create the email template.
   * @return {Promise<ClientResponse<EmailTemplateResponse>>} A Promise for the FusionAuth call.
   */
  createEmailTemplate: function(emailTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template')
          .urlSegment(emailTemplateId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
   *
   * @param {?UUIDString} entityId (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.
   * @param {EntityRequest} request The request object that contains all the information used to create the Entity.
   * @return {Promise<ClientResponse<EntityResponse>>} A Promise for the FusionAuth call.
   */
  createEntity: function(entityId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
   *
   * @param {?UUIDString} entityTypeId (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.
   * @param {EntityTypeRequest} request The request object that contains all the information used to create the Entity Type.
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  createEntityType: function(entityTypeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a new permission for an entity type. You must specify the Id of the entity type you are creating the permission for.
   * You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
   *
   * @param {UUIDString} entityTypeId The Id of the entity type to create the permission on.
   * @param {?UUIDString} permissionId (Optional) The Id of the permission. If not provided a secure random UUID will be generated.
   * @param {EntityTypeRequest} request The request object that contains all the information used to create the permission.
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  createEntityTypePermission: function(entityTypeId, permissionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .urlSegment("permission")
          .urlSegment(permissionId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a family with the user Id in the request as the owner and sole member of the family. You can optionally specify an Id for the
   * family, if not provided one will be generated.
   *
   * @param {?UUIDString} familyId (Optional) The Id for the family. If not provided a secure random UUID will be generated.
   * @param {FamilyRequest} request The request object that contains all the information used to create the family.
   * @return {Promise<ClientResponse<FamilyResponse>>} A Promise for the FusionAuth call.
   */
  createFamily: function(familyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family')
          .urlSegment(familyId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
   *
   * @param {?UUIDString} formId (Optional) The Id for the form. If not provided a secure random UUID will be generated.
   * @param {FormRequest} request The request object that contains all the information used to create the form.
   * @return {Promise<ClientResponse<FormResponse>>} A Promise for the FusionAuth call.
   */
  createForm: function(formId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form')
          .urlSegment(formId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
   *
   * @param {?UUIDString} fieldId (Optional) The Id for the form field. If not provided a secure random UUID will be generated.
   * @param {FormFieldRequest} request The request object that contains all the information used to create the form field.
   * @return {Promise<ClientResponse<FormFieldResponse>>} A Promise for the FusionAuth call.
   */
  createFormField: function(fieldId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form/field')
          .urlSegment(fieldId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
   *
   * @param {?UUIDString} groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
   * @param {GroupRequest} request The request object that contains all the information used to create the group.
   * @return {Promise<ClientResponse<GroupResponse>>} A Promise for the FusionAuth call.
   */
  createGroup: function(groupId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group')
          .urlSegment(groupId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a member in a group.
   *
   * @param {MemberRequest} request The request object that contains all the information used to create the group member(s).
   * @return {Promise<ClientResponse<MemberResponse>>} A Promise for the FusionAuth call.
   */
  createGroupMembers: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group/member')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
   *
   * @param {?UUIDString} accessControlListId (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.
   * @param {IPAccessControlListRequest} request The request object that contains all the information used to create the IP Access Control List.
   * @return {Promise<ClientResponse<IPAccessControlListResponse>>} A Promise for the FusionAuth call.
   */
  createIPAccessControlList: function(accessControlListId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/ip-acl')
          .urlSegment(accessControlListId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
   *
   * @param {?UUIDString} identityProviderId (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.
   * @param {IdentityProviderRequest} request The request object that contains all the information used to create the identity provider.
   * @return {Promise<ClientResponse<IdentityProviderResponse>>} A Promise for the FusionAuth call.
   */
  createIdentityProvider: function(identityProviderId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .urlSegment(identityProviderId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
   *
   * @param {?UUIDString} lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
   * @param {LambdaRequest} request The request object that contains all the information used to create the lambda.
   * @return {Promise<ClientResponse<LambdaResponse>>} A Promise for the FusionAuth call.
   */
  createLambda: function(lambdaId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .urlSegment(lambdaId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
   *
   * @param {?UUIDString} messageTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
   * @param {MessageTemplateRequest} request The request object that contains all the information used to create the message template.
   * @return {Promise<ClientResponse<MessageTemplateResponse>>} A Promise for the FusionAuth call.
   */
  createMessageTemplate: function(messageTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template')
          .urlSegment(messageTemplateId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
   *
   * @param {?UUIDString} messengerId (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.
   * @param {MessengerRequest} request The request object that contains all the information used to create the messenger.
   * @return {Promise<ClientResponse<MessengerResponse>>} A Promise for the FusionAuth call.
   */
  createMessenger: function(messengerId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/messenger')
          .urlSegment(messengerId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a new custom OAuth scope for an application. You must specify the Id of the application you are creating the scope for.
   * You can optionally specify an Id for the OAuth scope on the URL, if not provided one will be generated.
   *
   * @param {UUIDString} applicationId The Id of the application to create the OAuth scope on.
   * @param {?UUIDString} scopeId (Optional) The Id of the OAuth scope. If not provided a secure random UUID will be generated.
   * @param {ApplicationOAuthScopeRequest} request The request object that contains all the information used to create the OAuth OAuth scope.
   * @return {Promise<ClientResponse<ApplicationOAuthScopeResponse>>} A Promise for the FusionAuth call.
   */
  createOAuthScope: function(applicationId, scopeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("scope")
          .urlSegment(scopeId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
   *
   * @param {?UUIDString} tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
   * @param {TenantRequest} request The request object that contains all the information used to create the tenant.
   * @return {Promise<ClientResponse<TenantResponse>>} A Promise for the FusionAuth call.
   */
  createTenant: function(tenantId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
   *
   * @param {?UUIDString} themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
   * @param {ThemeRequest} request The request object that contains all the information used to create the theme.
   * @return {Promise<ClientResponse<ThemeResponse>>} A Promise for the FusionAuth call.
   */
  createTheme: function(themeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme')
          .urlSegment(themeId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
   *
   * @param {?UUIDString} userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
   * @param {UserRequest} request The request object that contains all the information used to create the user.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  createUser: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
   * that the user action can be applied to any user.
   *
   * @param {?UUIDString} userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
   * @param {UserActionRequest} request The request object that contains all the information used to create the user action.
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  createUserAction: function(userActionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
   * successfully. Anytime after that the user action reason can be used.
   *
   * @param {?UUIDString} userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
   * @param {UserActionReasonRequest} request The request object that contains all the information used to create the user action reason.
   * @return {Promise<ClientResponse<UserActionReasonResponse>>} A Promise for the FusionAuth call.
   */
  createUserActionReason: function(userActionReasonId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action-reason')
          .urlSegment(userActionReasonId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a single User consent.
   *
   * @param {?UUIDString} userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
   * @param {UserConsentRequest} request The request that contains the user consent information.
   * @return {Promise<ClientResponse<UserConsentResponse>>} A Promise for the FusionAuth call.
   */
  createUserConsent: function(userConsentId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/consent')
          .urlSegment(userConsentId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Link an external user from a 3rd party identity provider to a FusionAuth user.
   *
   * @param {IdentityProviderLinkRequest} request The request object that contains all the information used to link the FusionAuth user.
   * @return {Promise<ClientResponse<IdentityProviderLinkResponse>>} A Promise for the FusionAuth call.
   */
  createUserLink: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/link')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
   *
   * @param {?UUIDString} webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
   * @param {WebhookRequest} request The request object that contains all the information used to create the webhook.
   * @return {Promise<ClientResponse<WebhookResponse>>} A Promise for the FusionAuth call.
   */
  createWebhook: function(webhookId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webhook')
          .urlSegment(webhookId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deactivates the application with the given Id.
   *
   * @param {UUIDString} applicationId The Id of the application to deactivate.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deactivateApplication: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deactivates the FusionAuth Reactor.
   *
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deactivateReactor: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/reactor')
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deactivates the user with the given Id.
   *
   * @param {UUIDString} userId The Id of the user to deactivate.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deactivateUser: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deactivates the user action with the given Id.
   *
   * @param {UUIDString} userActionId The Id of the user action to deactivate.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deactivateUserAction: function(userActionId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deactivates the users with the given ids.
   *
   * @param {Array<string>} userIds The ids of the users to deactivate.
   * @return {Promise<ClientResponse<UserDeleteResponse>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to deactivateUsersByIds, use that method instead.
   */
  deactivateUsers: function(userIds) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/bulk')
          .urlParameter('userId', userIds)
          .urlParameter('dryRun', false)
          .urlParameter('hardDelete', false)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deactivates the users with the given ids.
   *
   * @param {Array<string>} userIds The ids of the users to deactivate.
   * @return {Promise<ClientResponse<UserDeleteResponse>>} A Promise for the FusionAuth call.
   */
  deactivateUsersByIds: function(userIds) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/bulk')
          .urlParameter('userId', userIds)
          .urlParameter('dryRun', false)
          .urlParameter('hardDelete', false)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the API key for the given Id.
   *
   * @param {UUIDString} keyId The Id of the authentication API key to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteAPIKey: function(keyId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/api-key')
          .urlSegment(keyId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
   * delete the application, any registrations for that application, metrics and reports for the application, all the
   * roles for the application, and any other data associated with the application. This operation could take a very
   * long time, depending on the amount of data in your database.
   *
   * @param {UUIDString} applicationId The Id of the application to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteApplication: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlParameter('hardDelete', true)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
   * permanently removes the given role from all users that had it.
   *
   * @param {UUIDString} applicationId The Id of the application that the role belongs to.
   * @param {UUIDString} roleId The Id of the role to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteApplicationRole: function(applicationId, roleId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("role")
          .urlSegment(roleId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the connector for the given Id.
   *
   * @param {UUIDString} connectorId The Id of the connector to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteConnector: function(connectorId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/connector')
          .urlSegment(connectorId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the consent for the given Id.
   *
   * @param {UUIDString} consentId The Id of the consent to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteConsent: function(consentId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent')
          .urlSegment(consentId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the email template for the given Id.
   *
   * @param {UUIDString} emailTemplateId The Id of the email template to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteEmailTemplate: function(emailTemplateId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template')
          .urlSegment(emailTemplateId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the Entity for the given Id.
   *
   * @param {UUIDString} entityId The Id of the Entity to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteEntity: function(entityId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes an Entity Grant for the given User or Entity.
   *
   * @param {UUIDString} entityId The Id of the Entity that the Entity Grant is being deleted for.
   * @param {?UUIDString} recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
   * @param {?UUIDString} userId (Optional) The Id of the User that the Entity Grant is for.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteEntityGrant: function(entityId, recipientEntityId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .urlSegment("grant")
          .urlParameter('recipientEntityId', recipientEntityId)
          .urlParameter('userId', userId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the Entity Type for the given Id.
   *
   * @param {UUIDString} entityTypeId The Id of the Entity Type to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteEntityType: function(entityTypeId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
   * permanently removes the given permission from all grants that had it.
   *
   * @param {UUIDString} entityTypeId The Id of the entityType the the permission belongs to.
   * @param {UUIDString} permissionId The Id of the permission to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteEntityTypePermission: function(entityTypeId, permissionId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .urlSegment("permission")
          .urlSegment(permissionId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the form for the given Id.
   *
   * @param {UUIDString} formId The Id of the form to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteForm: function(formId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form')
          .urlSegment(formId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the form field for the given Id.
   *
   * @param {UUIDString} fieldId The Id of the form field to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteFormField: function(fieldId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form/field')
          .urlSegment(fieldId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the group for the given Id.
   *
   * @param {UUIDString} groupId The Id of the group to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteGroup: function(groupId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group')
          .urlSegment(groupId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Removes users as members of a group.
   *
   * @param {MemberDeleteRequest} request The member request that contains all the information used to remove members to the group.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteGroupMembers: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group/member')
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the IP Access Control List for the given Id.
   *
   * @param {UUIDString} ipAccessControlListId The Id of the IP Access Control List to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteIPAccessControlList: function(ipAccessControlListId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/ip-acl')
          .urlSegment(ipAccessControlListId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the identity provider for the given Id.
   *
   * @param {UUIDString} identityProviderId The Id of the identity provider to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteIdentityProvider: function(identityProviderId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .urlSegment(identityProviderId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the key for the given Id.
   *
   * @param {UUIDString} keyId The Id of the key to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteKey: function(keyId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key')
          .urlSegment(keyId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the lambda for the given Id.
   *
   * @param {UUIDString} lambdaId The Id of the lambda to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteLambda: function(lambdaId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .urlSegment(lambdaId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the message template for the given Id.
   *
   * @param {UUIDString} messageTemplateId The Id of the message template to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteMessageTemplate: function(messageTemplateId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template')
          .urlSegment(messageTemplateId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the messenger for the given Id.
   *
   * @param {UUIDString} messengerId The Id of the messenger to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteMessenger: function(messengerId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/messenger')
          .urlSegment(messengerId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Hard deletes a custom OAuth scope. This action will cause tokens that contain the deleted scope to be rejected.
   * OAuth workflows that are still requesting the deleted OAuth scope may fail depending on the application's unknown scope policy.
   *
   * @param {UUIDString} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUIDString} scopeId The Id of the OAuth scope to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteOAuthScope: function(applicationId, scopeId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("scope")
          .urlSegment(scopeId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the user registration for the given user and application.
   *
   * @param {UUIDString} userId The Id of the user whose registration is being deleted.
   * @param {UUIDString} applicationId The Id of the application to remove the registration for.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteRegistration: function(userId, applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/registration')
          .urlSegment(userId)
          .urlSegment(applicationId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
   *
   * @param {UUIDString} userId The Id of the user whose registration is being deleted.
   * @param {UUIDString} applicationId The Id of the application to remove the registration for.
   * @param {RegistrationDeleteRequest} request The request body that contains the event information.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteRegistrationWithRequest: function(userId, applicationId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/registration')
          .urlSegment(userId)
          .urlSegment(applicationId)
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
   * with the tenant and everything under the tenant (applications, users, etc).
   *
   * @param {UUIDString} tenantId The Id of the tenant to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteTenant: function(tenantId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the tenant for the given Id asynchronously.
   * This method is helpful if you do not want to wait for the delete operation to complete.
   *
   * @param {UUIDString} tenantId The Id of the tenant to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteTenantAsync: function(tenantId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .urlParameter('async', true)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
   * with the tenant and everything under the tenant (applications, users, etc).
   *
   * @param {UUIDString} tenantId The Id of the tenant to delete.
   * @param {TenantDeleteRequest} request The request object that contains all the information used to delete the user.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteTenantWithRequest: function(tenantId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the theme for the given Id.
   *
   * @param {UUIDString} themeId The Id of the theme to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteTheme: function(themeId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme')
          .urlSegment(themeId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
   * with the user.
   *
   * @param {UUIDString} userId The Id of the user to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteUser: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .urlParameter('hardDelete', true)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
   * the action being applied to any users.
   *
   * @param {UUIDString} userActionId The Id of the user action to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteUserAction: function(userActionId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .urlParameter('hardDelete', true)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the user action reason for the given Id.
   *
   * @param {UUIDString} userActionReasonId The Id of the user action reason to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteUserActionReason: function(userActionReasonId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action-reason')
          .urlSegment(userActionReasonId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
   *
   * @param {UUIDString} identityProviderId The unique Id of the identity provider.
   * @param {string} identityProviderUserId The unique Id of the user in the 3rd party identity provider to unlink.
   * @param {UUIDString} userId The unique Id of the FusionAuth user to unlink.
   * @return {Promise<ClientResponse<IdentityProviderLinkResponse>>} A Promise for the FusionAuth call.
   */
  deleteUserLink: function(identityProviderId, identityProviderUserId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/link')
          .urlParameter('identityProviderId', identityProviderId)
          .urlParameter('identityProviderUserId', identityProviderUserId)
          .urlParameter('userId', userId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
   * with the user.
   *
   * @param {UUIDString} userId The Id of the user to delete (required).
   * @param {UserDeleteSingleRequest} request The request object that contains all the information used to delete the user.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteUserWithRequest: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the users with the given ids, or users matching the provided JSON query or queryString.
   * The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
   * 
   * This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
   * Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
   *
   * @param {UserDeleteRequest} request The UserDeleteRequest.
   * @return {Promise<ClientResponse<UserDeleteResponse>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to deleteUsersByQuery, use that method instead.
   */
  deleteUsers: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/bulk')
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the users with the given ids, or users matching the provided JSON query or queryString.
   * The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
   * 
   * This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
   * Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
   *
   * @param {UserDeleteRequest} request The UserDeleteRequest.
   * @return {Promise<ClientResponse<UserDeleteResponse>>} A Promise for the FusionAuth call.
   */
  deleteUsersByQuery: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/bulk')
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the WebAuthn credential for the given Id.
   *
   * @param {UUIDString} id The Id of the WebAuthn credential to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteWebAuthnCredential: function(id) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn')
          .urlSegment(id)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Deletes the webhook for the given Id.
   *
   * @param {UUIDString} webhookId The Id of the webhook to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  deleteWebhook: function(webhookId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webhook')
          .urlSegment(webhookId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Disable two-factor authentication for a user.
   *
   * @param {UUIDString} userId The Id of the User for which you're disabling two-factor authentication.
   * @param {string} methodId The two-factor method identifier you wish to disable
   * @param {string} code The two-factor code used verify the the caller knows the two-factor secret.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  disableTwoFactor: function(userId, methodId, code) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/two-factor')
          .urlSegment(userId)
          .urlParameter('methodId', methodId)
          .urlParameter('code', code)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Disable two-factor authentication for a user using a JSON body rather than URL parameters.
   *
   * @param {UUIDString} userId The Id of the User for which you're disabling two-factor authentication.
   * @param {TwoFactorDisableRequest} request The request information that contains the code and methodId along with any event information.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  disableTwoFactorWithRequest: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/two-factor')
          .urlSegment(userId)
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Enable two-factor authentication for a user.
   *
   * @param {UUIDString} userId The Id of the user to enable two-factor authentication.
   * @param {TwoFactorRequest} request The two-factor enable request information.
   * @return {Promise<ClientResponse<TwoFactorResponse>>} A Promise for the FusionAuth call.
   */
  enableTwoFactor: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/two-factor')
          .urlSegment(userId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Exchanges an OAuth authorization code for an access token.
   * Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
   *
   * @param {string} code The authorization code returned on the /oauth2/authorize response.
   * @param {?string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {?string} client_secret (Optional) The client secret. This value will be required if client authentication is enabled.
   * @param {string} redirect_uri The URI to redirect to upon a successful request.
   * @return {Promise<ClientResponse<AccessToken>>} A Promise for the FusionAuth call.
   */
  exchangeOAuthCodeForAccessToken: function(code, client_id, client_secret, redirect_uri) {
    var body = {
      code: code,
      client_id: client_id,
      client_secret: client_secret,
      grant_type: "authorization_code",
      redirect_uri: redirect_uri
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/token')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Exchanges an OAuth authorization code and code_verifier for an access token.
   * Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
   *
   * @param {string} code The authorization code returned on the /oauth2/authorize response.
   * @param {?string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {?string} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
   * @param {string} redirect_uri The URI to redirect to upon a successful request.
   * @param {string} code_verifier The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.
   * @return {Promise<ClientResponse<AccessToken>>} A Promise for the FusionAuth call.
   */
  exchangeOAuthCodeForAccessTokenUsingPKCE: function(code, client_id, client_secret, redirect_uri, code_verifier) {
    var body = {
      code: code,
      client_id: client_id,
      client_secret: client_secret,
      grant_type: "authorization_code",
      redirect_uri: redirect_uri,
      code_verifier: code_verifier
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/token')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Exchange a Refresh Token for an Access Token.
   * If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
   *
   * @param {string} refresh_token The refresh token that you would like to use to exchange for an access token.
   * @param {?string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {?string} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
   * @param {?string} scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
   * @param {?string} user_code (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
   * @return {Promise<ClientResponse<AccessToken>>} A Promise for the FusionAuth call.
   */
  exchangeRefreshTokenForAccessToken: function(refresh_token, client_id, client_secret, scope, user_code) {
    var body = {
      refresh_token: refresh_token,
      client_id: client_id,
      client_secret: client_secret,
      grant_type: "refresh_token",
      scope: scope,
      user_code: user_code
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/token')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Exchange a refresh token for a new JWT.
   *
   * @param {RefreshRequest} request The refresh request.
   * @return {Promise<ClientResponse<JWTRefreshResponse>>} A Promise for the FusionAuth call.
   */
  exchangeRefreshTokenForJWT: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/refresh')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Exchange User Credentials for a Token.
   * If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
   *
   * @param {string} username The login identifier of the user. The login identifier can be either the email or the username.
   * @param {string} password The user’s password.
   * @param {?string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {?string} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
   * @param {?string} scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
   * @param {?string} user_code (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
   * @return {Promise<ClientResponse<AccessToken>>} A Promise for the FusionAuth call.
   */
  exchangeUserCredentialsForAccessToken: function(username, password, client_id, client_secret, scope, user_code) {
    var body = {
      username: username,
      password: password,
      client_id: client_id,
      client_secret: client_secret,
      grant_type: "password",
      scope: scope,
      user_code: user_code
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/token')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
   *
   * @param {ForgotPasswordRequest} request The request that contains the information about the user so that they can be emailed.
   * @return {Promise<ClientResponse<ForgotPasswordResponse>>} A Promise for the FusionAuth call.
   */
  forgotPassword: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/forgot-password')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
   * email to the User. This API may be used to collect the verificationId for use with a third party system.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @return {Promise<ClientResponse<VerifyEmailResponse>>} A Promise for the FusionAuth call.
   */
  generateEmailVerificationId: function(email) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/verify-email')
          .urlParameter('email', email)
          .urlParameter('sendVerifyEmail', false)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Generate a new RSA or EC key pair or an HMAC secret.
   *
   * @param {?UUIDString} keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
   * @param {KeyRequest} request The request object that contains all the information used to create the key.
   * @return {Promise<ClientResponse<KeyResponse>>} A Promise for the FusionAuth call.
   */
  generateKey: function(keyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key/generate')
          .urlSegment(keyId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
   * email to the User. This API may be used to collect the verificationId for use with a third party system.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @param {UUIDString} applicationId The Id of the application to be verified.
   * @return {Promise<ClientResponse<VerifyRegistrationResponse>>} A Promise for the FusionAuth call.
   */
  generateRegistrationVerificationId: function(email, applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/verify-registration')
          .urlParameter('email', email)
          .urlParameter('sendVerifyPasswordEmail', false)
          .urlParameter('applicationId', applicationId)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes. 
   *
   * @param {UUIDString} userId The Id of the user to generate new Two Factor recovery codes.
   * @return {Promise<ClientResponse<TwoFactorRecoveryCodeResponse>>} A Promise for the FusionAuth call.
   */
  generateTwoFactorRecoveryCodes: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/two-factor/recovery-code')
          .urlSegment(userId)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
   * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
   * application such as Google Authenticator.
   *
   * @return {Promise<ClientResponse<SecretResponse>>} A Promise for the FusionAuth call.
   */
  generateTwoFactorSecret: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/two-factor/secret')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
   * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
   * application such as Google Authenticator.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @return {Promise<ClientResponse<SecretResponse>>} A Promise for the FusionAuth call.
   */
  generateTwoFactorSecretUsingJWT: function(encodedJWT) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/two-factor/secret')
          .authorization('Bearer ' + encodedJWT)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
   * login systems.
   *
   * @param {IdentityProviderLoginRequest} request The third-party login request that contains information from the third-party login
   *    providers that FusionAuth uses to reconcile the user's account.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  identityProviderLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/identity-provider/login')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Import an existing RSA or EC key pair or an HMAC secret.
   *
   * @param {?UUIDString} keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
   * @param {KeyRequest} request The request object that contains all the information used to create the key.
   * @return {Promise<ClientResponse<KeyResponse>>} A Promise for the FusionAuth call.
   */
  importKey: function(keyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key/import')
          .urlSegment(keyId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
   * expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
   * Application. This is done to increases the insert performance.
   * 
   * Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
   * explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
   * body with specific validation errors. This will slow the request down but will allow you to identify the cause of
   * the failure. See the validateDbConstraints request parameter.
   *
   * @param {RefreshTokenImportRequest} request The request that contains all the information about all the refresh tokens to import.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  importRefreshTokens: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/refresh-token/import')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
   * that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
   * increases the insert performance.
   * 
   * Therefore, if you encounter an error due to a database key violation, the response will likely offer
   * a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
   * body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
   * the validateDbConstraints request parameter.
   *
   * @param {ImportRequest} request The request that contains all the information about all the users to import.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  importUsers: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/import')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Import a WebAuthn credential
   *
   * @param {WebAuthnCredentialImportRequest} request An object containing data necessary for importing the credential
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  importWebAuthnCredential: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn/import')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Inspect an access token issued as the result of the User based grant such as the Authorization Code Grant, Implicit Grant, the User Credentials Grant or the Refresh Grant.
   *
   * @param {string} client_id The unique client identifier. The client Id is the Id of the FusionAuth Application for which this token was generated.
   * @param {string} token The access token returned by this OAuth provider as the result of a successful client credentials grant.
   * @return {Promise<ClientResponse<IntrospectResponse>>} A Promise for the FusionAuth call.
   */
  introspectAccessToken: function(client_id, token) {
    var body = {
      client_id: client_id,
      token: token
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/introspect')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Inspect an access token issued as the result of the Client Credentials Grant.
   *
   * @param {string} token The access token returned by this OAuth provider as the result of a successful client credentials grant.
   * @return {Promise<ClientResponse<IntrospectResponse>>} A Promise for the FusionAuth call.
   */
  introspectClientCredentialsAccessToken: function(token) {
    var body = {
      token: token
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/introspect')
          .setFormBody(body)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
   * access token is properly signed and not expired.
   * <p>
   * This API may be used in an SSO configuration to issue new tokens for another application after the user has
   * obtained a valid token from authentication.
   *
   * @param {UUIDString} applicationId The Application Id for which you are requesting a new access token be issued.
   * @param {string} encodedJWT The encoded JWT (access token).
   * @param {?string} refreshToken (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
   *    <p>The target application represented by the applicationId request parameter must have refresh
   *    tokens enabled in order to receive a refresh token in the response.</p>
   * @return {Promise<ClientResponse<IssueResponse>>} A Promise for the FusionAuth call.
   */
  issueJWT: function(applicationId, encodedJWT, refreshToken) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/issue')
          .authorization('Bearer ' + encodedJWT)
          .urlParameter('applicationId', applicationId)
          .urlParameter('refreshToken', refreshToken)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Authenticates a user to FusionAuth. 
   * 
   * This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
   *
   * @param {LoginRequest} request The login request that contains the user credentials used to log them in.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  login: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/login')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
   * FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
   * application where they no longer have a session. This helps correctly track login counts, times and helps with
   * reporting.
   *
   * @param {UUIDString} userId The Id of the user that was logged in.
   * @param {UUIDString} applicationId The Id of the application that they logged into.
   * @param {?string} callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
   *    the IP address will be that of the client or last proxy that sent the request.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  loginPing: function(userId, applicationId, callerIPAddress) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/login')
          .urlSegment(userId)
          .urlSegment(applicationId)
          .urlParameter('ipAddress', callerIPAddress)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
   * FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
   * application where they no longer have a session. This helps correctly track login counts, times and helps with
   * reporting.
   *
   * @param {LoginPingRequest} request The login request that contains the user credentials used to log them in.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  loginPingWithRequest: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/login')
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
   * client and revoke the refresh token stored. This API does nothing if the request does not contain an access
   * token or refresh token cookies.
   *
   * @param {boolean} global When this value is set to true all the refresh tokens issued to the owner of the
   *    provided token will be revoked.
   * @param {?string} refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
   *    If provided this takes precedence over the cookie.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  logout: function(global, refreshToken) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/logout')
          .urlParameter('global', global)
          .urlParameter('refreshToken', refreshToken)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
   * client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
   *
   * @param {LogoutRequest} request The request object that contains all the information used to logout the user.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  logoutWithRequest: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/logout')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
   * by a registered identity provider. A 404 indicates the domain is not managed.
   *
   * @param {string} domain The domain or email address to lookup.
   * @return {Promise<ClientResponse<LookupResponse>>} A Promise for the FusionAuth call.
   */
  lookupIdentityProvider: function(domain) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/lookup')
          .urlParameter('domain', domain)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
   * action.
   *
   * @param {UUIDString} actionId The Id of the action to modify. This is technically the user action log id.
   * @param {ActionRequest} request The request that contains all the information about the modification.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  modifyAction: function(actionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlSegment(actionId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Complete a login request using a passwordless code
   *
   * @param {PasswordlessLoginRequest} request The passwordless login request that contains all the information used to complete login.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  passwordlessLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/passwordless/login')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates an authentication API key by given id
   *
   * @param {UUIDString} keyId The Id of the authentication key. If not provided a secure random api key will be generated.
   * @param {APIKeyRequest} request The request object that contains all the information needed to create the APIKey.
   * @return {Promise<ClientResponse<APIKeyResponse>>} A Promise for the FusionAuth call.
   */
  patchAPIKey: function(keyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/api-key')
          .urlSegment(keyId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the application with the given Id.
   *
   * @param {UUIDString} applicationId The Id of the application to update.
   * @param {ApplicationRequest} request The request that contains just the new application information.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  patchApplication: function(applicationId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the application role with the given Id for the application.
   *
   * @param {UUIDString} applicationId The Id of the application that the role belongs to.
   * @param {UUIDString} roleId The Id of the role to update.
   * @param {ApplicationRequest} request The request that contains just the new role information.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  patchApplicationRole: function(applicationId, roleId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("role")
          .urlSegment(roleId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the connector with the given Id.
   *
   * @param {UUIDString} connectorId The Id of the connector to update.
   * @param {ConnectorRequest} request The request that contains just the new connector information.
   * @return {Promise<ClientResponse<ConnectorResponse>>} A Promise for the FusionAuth call.
   */
  patchConnector: function(connectorId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/connector')
          .urlSegment(connectorId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the consent with the given Id.
   *
   * @param {UUIDString} consentId The Id of the consent to update.
   * @param {ConsentRequest} request The request that contains just the new consent information.
   * @return {Promise<ClientResponse<ConsentResponse>>} A Promise for the FusionAuth call.
   */
  patchConsent: function(consentId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent')
          .urlSegment(consentId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the email template with the given Id.
   *
   * @param {UUIDString} emailTemplateId The Id of the email template to update.
   * @param {EmailTemplateRequest} request The request that contains just the new email template information.
   * @return {Promise<ClientResponse<EmailTemplateResponse>>} A Promise for the FusionAuth call.
   */
  patchEmailTemplate: function(emailTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template')
          .urlSegment(emailTemplateId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the Entity Type with the given Id.
   *
   * @param {UUIDString} entityTypeId The Id of the Entity Type to update.
   * @param {EntityTypeRequest} request The request that contains just the new Entity Type information.
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  patchEntityType: function(entityTypeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the group with the given Id.
   *
   * @param {UUIDString} groupId The Id of the group to update.
   * @param {GroupRequest} request The request that contains just the new group information.
   * @return {Promise<ClientResponse<GroupResponse>>} A Promise for the FusionAuth call.
   */
  patchGroup: function(groupId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group')
          .urlSegment(groupId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the identity provider with the given Id.
   *
   * @param {UUIDString} identityProviderId The Id of the identity provider to update.
   * @param {IdentityProviderRequest} request The request object that contains just the updated identity provider information.
   * @return {Promise<ClientResponse<IdentityProviderResponse>>} A Promise for the FusionAuth call.
   */
  patchIdentityProvider: function(identityProviderId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .urlSegment(identityProviderId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the available integrations.
   *
   * @param {IntegrationRequest} request The request that contains just the new integration information.
   * @return {Promise<ClientResponse<IntegrationResponse>>} A Promise for the FusionAuth call.
   */
  patchIntegrations: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/integration')
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the lambda with the given Id.
   *
   * @param {UUIDString} lambdaId The Id of the lambda to update.
   * @param {LambdaRequest} request The request that contains just the new lambda information.
   * @return {Promise<ClientResponse<LambdaResponse>>} A Promise for the FusionAuth call.
   */
  patchLambda: function(lambdaId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .urlSegment(lambdaId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the message template with the given Id.
   *
   * @param {UUIDString} messageTemplateId The Id of the message template to update.
   * @param {MessageTemplateRequest} request The request that contains just the new message template information.
   * @return {Promise<ClientResponse<MessageTemplateResponse>>} A Promise for the FusionAuth call.
   */
  patchMessageTemplate: function(messageTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template')
          .urlSegment(messageTemplateId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the messenger with the given Id.
   *
   * @param {UUIDString} messengerId The Id of the messenger to update.
   * @param {MessengerRequest} request The request that contains just the new messenger information.
   * @return {Promise<ClientResponse<MessengerResponse>>} A Promise for the FusionAuth call.
   */
  patchMessenger: function(messengerId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/messenger')
          .urlSegment(messengerId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the custom OAuth scope with the given Id for the application.
   *
   * @param {UUIDString} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUIDString} scopeId The Id of the OAuth scope to update.
   * @param {ApplicationOAuthScopeRequest} request The request that contains just the new OAuth scope information.
   * @return {Promise<ClientResponse<ApplicationOAuthScopeResponse>>} A Promise for the FusionAuth call.
   */
  patchOAuthScope: function(applicationId, scopeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("scope")
          .urlSegment(scopeId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the registration for the user with the given Id and the application defined in the request.
   *
   * @param {UUIDString} userId The Id of the user whose registration is going to be updated.
   * @param {RegistrationRequest} request The request that contains just the new registration information.
   * @return {Promise<ClientResponse<RegistrationResponse>>} A Promise for the FusionAuth call.
   */
  patchRegistration: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/registration')
          .urlSegment(userId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the system configuration.
   *
   * @param {SystemConfigurationRequest} request The request that contains just the new system configuration information.
   * @return {Promise<ClientResponse<SystemConfigurationResponse>>} A Promise for the FusionAuth call.
   */
  patchSystemConfiguration: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system-configuration')
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the tenant with the given Id.
   *
   * @param {UUIDString} tenantId The Id of the tenant to update.
   * @param {TenantRequest} request The request that contains just the new tenant information.
   * @return {Promise<ClientResponse<TenantResponse>>} A Promise for the FusionAuth call.
   */
  patchTenant: function(tenantId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the theme with the given Id.
   *
   * @param {UUIDString} themeId The Id of the theme to update.
   * @param {ThemeRequest} request The request that contains just the new theme information.
   * @return {Promise<ClientResponse<ThemeResponse>>} A Promise for the FusionAuth call.
   */
  patchTheme: function(themeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme')
          .urlSegment(themeId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the user with the given Id.
   *
   * @param {UUIDString} userId The Id of the user to update.
   * @param {UserRequest} request The request that contains just the new user information.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  patchUser: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the user action with the given Id.
   *
   * @param {UUIDString} userActionId The Id of the user action to update.
   * @param {UserActionRequest} request The request that contains just the new user action information.
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  patchUserAction: function(userActionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, the user action reason with the given Id.
   *
   * @param {UUIDString} userActionReasonId The Id of the user action reason to update.
   * @param {UserActionReasonRequest} request The request that contains just the new user action reason information.
   * @return {Promise<ClientResponse<UserActionReasonResponse>>} A Promise for the FusionAuth call.
   */
  patchUserActionReason: function(userActionReasonId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action-reason')
          .urlSegment(userActionReasonId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates, via PATCH, a single User consent by Id.
   *
   * @param {UUIDString} userConsentId The User Consent Id
   * @param {UserConsentRequest} request The request that contains just the new user consent information.
   * @return {Promise<ClientResponse<UserConsentResponse>>} A Promise for the FusionAuth call.
   */
  patchUserConsent: function(userConsentId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/consent')
          .urlSegment(userConsentId)
          .setJSONBody(request)
          .patch()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Reactivates the application with the given Id.
   *
   * @param {UUIDString} applicationId The Id of the application to reactivate.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  reactivateApplication: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlParameter('reactivate', true)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Reactivates the user with the given Id.
   *
   * @param {UUIDString} userId The Id of the user to reactivate.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  reactivateUser: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .urlParameter('reactivate', true)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Reactivates the user action with the given Id.
   *
   * @param {UUIDString} userActionId The Id of the user action to reactivate.
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  reactivateUserAction: function(userActionId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .urlParameter('reactivate', true)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
   *
   * @param {IdentityProviderLoginRequest} request The reconcile request that contains the data to reconcile the User.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  reconcileJWT: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/reconcile')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
   * reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
   * if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
   *  ensure the index immediately current before making a query request to the search index.
   *
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  refreshEntitySearchIndex: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/search')
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
   * reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
   * if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
   *  ensure the index immediately current before making a query request to the search index.
   *
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  refreshUserSearchIndex: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/search')
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Regenerates any keys that are used by the FusionAuth Reactor.
   *
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  regenerateReactorKeys: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/reactor')
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
   * will create the user as well as register them for the application. This is called a Full Registration. However, if
   * you only provide the UserRegistration object, then the user must already exist and they will be registered for the
   * application. The user Id can also be provided and it will either be used to look up an existing user or it will be
   * used for the newly created User.
   *
   * @param {?UUIDString} userId (Optional) The Id of the user being registered for the application and optionally created.
   * @param {RegistrationRequest} request The request that optionally contains the User and must contain the UserRegistration.
   * @return {Promise<ClientResponse<RegistrationResponse>>} A Promise for the FusionAuth call.
   */
  register: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/registration')
          .urlSegment(userId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will 
   * increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless 
   * instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index. 
   * 
   * You have been warned.
   *
   * @param {ReindexRequest} request The request that contains the index name.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  reindex: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/reindex')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Removes a user from the family with the given id.
   *
   * @param {UUIDString} familyId The Id of the family to remove the user from.
   * @param {UUIDString} userId The Id of the user to remove from the family.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  removeUserFromFamily: function(familyId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family')
          .urlSegment(familyId)
          .urlSegment(userId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Re-sends the verification email to the user.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @return {Promise<ClientResponse<VerifyEmailResponse>>} A Promise for the FusionAuth call.
   */
  resendEmailVerification: function(email) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/verify-email')
          .urlParameter('email', email)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
   * instead of the tenant configuration.
   *
   * @param {UUIDString} applicationId The unique Application Id to used to resolve an application specific email template.
   * @param {string} email The email address of the user that needs a new verification email.
   * @return {Promise<ClientResponse<VerifyEmailResponse>>} A Promise for the FusionAuth call.
   */
  resendEmailVerificationWithApplicationTemplate: function(applicationId, email) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/verify-email')
          .urlParameter('applicationId', applicationId)
          .urlParameter('email', email)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Re-sends the application registration verification email to the user.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @param {UUIDString} applicationId The Id of the application to be verified.
   * @return {Promise<ClientResponse<VerifyRegistrationResponse>>} A Promise for the FusionAuth call.
   */
  resendRegistrationVerification: function(email, applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/verify-registration')
          .urlParameter('email', email)
          .urlParameter('applicationId', applicationId)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves an authentication API key for the given id
   *
   * @param {UUIDString} keyId The Id of the API key to retrieve.
   * @return {Promise<ClientResponse<APIKeyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveAPIKey: function(keyId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/api-key')
          .urlSegment(keyId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
   *
   * @param {UUIDString} actionId The Id of the action to retrieve.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveAction: function(actionId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlSegment(actionId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
   * and inactive as well as non-time based actions.
   *
   * @param {UUIDString} userId The Id of the user to fetch the actions for.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveActions: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
   *
   * @param {UUIDString} userId The Id of the user to fetch the actions for.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveActionsPreventingLogin: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlParameter('userId', userId)
          .urlParameter('preventingLogin', true)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the actions for the user with the given Id that are currently active.
   * An active action means one that is time based and has not been canceled, and has not ended.
   *
   * @param {UUIDString} userId The Id of the user to fetch the actions for.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveActiveActions: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlParameter('userId', userId)
          .urlParameter('active', true)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the application for the given Id or all the applications if the Id is null.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveApplication: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the applications.
   *
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveApplications: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves a single audit log for the given Id.
   *
   * @param {number} auditLogId The Id of the audit log to retrieve.
   * @return {Promise<ClientResponse<AuditLogResponse>>} A Promise for the FusionAuth call.
   */
  retrieveAuditLog: function(auditLogId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/audit-log')
          .urlSegment(auditLogId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the connector with the given Id.
   *
   * @param {UUIDString} connectorId The Id of the connector.
   * @return {Promise<ClientResponse<ConnectorResponse>>} A Promise for the FusionAuth call.
   */
  retrieveConnector: function(connectorId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/connector')
          .urlSegment(connectorId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the connectors.
   *
   * @return {Promise<ClientResponse<ConnectorResponse>>} A Promise for the FusionAuth call.
   */
  retrieveConnectors: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/connector')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the Consent for the given Id.
   *
   * @param {UUIDString} consentId The Id of the consent.
   * @return {Promise<ClientResponse<ConsentResponse>>} A Promise for the FusionAuth call.
   */
  retrieveConsent: function(consentId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent')
          .urlSegment(consentId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the consent.
   *
   * @return {Promise<ClientResponse<ConsentResponse>>} A Promise for the FusionAuth call.
   */
  retrieveConsents: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the daily active user report between the two instants. If you specify an application id, it will only
   * return the daily active counts for that application.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @return {Promise<ClientResponse<DailyActiveUserReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveDailyActiveReport: function(applicationId, start, end) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/daily-active-user')
          .urlParameter('applicationId', applicationId)
          .urlParameter('start', start)
          .urlParameter('end', end)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
   *
   * @param {?UUIDString} emailTemplateId (Optional) The Id of the email template.
   * @return {Promise<ClientResponse<EmailTemplateResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEmailTemplate: function(emailTemplateId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template')
          .urlSegment(emailTemplateId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a preview of the email template provided in the request. This allows you to preview an email template that
   * hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
   * will create the preview based on whatever is given.
   *
   * @param {PreviewRequest} request The request that contains the email template and optionally a locale to render it in.
   * @return {Promise<ClientResponse<PreviewResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEmailTemplatePreview: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template/preview')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the email templates.
   *
   * @return {Promise<ClientResponse<EmailTemplateResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEmailTemplates: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the Entity for the given Id.
   *
   * @param {UUIDString} entityId The Id of the Entity.
   * @return {Promise<ClientResponse<EntityResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEntity: function(entityId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves an Entity Grant for the given Entity and User/Entity.
   *
   * @param {UUIDString} entityId The Id of the Entity.
   * @param {?UUIDString} recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
   * @param {?UUIDString} userId (Optional) The Id of the User that the Entity Grant is for.
   * @return {Promise<ClientResponse<EntityGrantResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEntityGrant: function(entityId, recipientEntityId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .urlSegment("grant")
          .urlParameter('recipientEntityId', recipientEntityId)
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the Entity Type for the given Id.
   *
   * @param {UUIDString} entityTypeId The Id of the Entity Type.
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEntityType: function(entityTypeId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the Entity Types.
   *
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEntityTypes: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves a single event log for the given Id.
   *
   * @param {number} eventLogId The Id of the event log to retrieve.
   * @return {Promise<ClientResponse<EventLogResponse>>} A Promise for the FusionAuth call.
   */
  retrieveEventLog: function(eventLogId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/event-log')
          .urlSegment(eventLogId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the families that a user belongs to.
   *
   * @param {UUIDString} userId The User's id
   * @return {Promise<ClientResponse<FamilyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveFamilies: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family')
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the members of a family by the unique Family Id.
   *
   * @param {UUIDString} familyId The unique Id of the Family.
   * @return {Promise<ClientResponse<FamilyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveFamilyMembersByFamilyId: function(familyId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family')
          .urlSegment(familyId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the form with the given Id.
   *
   * @param {UUIDString} formId The Id of the form.
   * @return {Promise<ClientResponse<FormResponse>>} A Promise for the FusionAuth call.
   */
  retrieveForm: function(formId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form')
          .urlSegment(formId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the form field with the given Id.
   *
   * @param {UUIDString} fieldId The Id of the form field.
   * @return {Promise<ClientResponse<FormFieldResponse>>} A Promise for the FusionAuth call.
   */
  retrieveFormField: function(fieldId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form/field')
          .urlSegment(fieldId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the forms fields
   *
   * @return {Promise<ClientResponse<FormFieldResponse>>} A Promise for the FusionAuth call.
   */
  retrieveFormFields: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form/field')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the forms.
   *
   * @return {Promise<ClientResponse<FormResponse>>} A Promise for the FusionAuth call.
   */
  retrieveForms: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the group for the given Id.
   *
   * @param {UUIDString} groupId The Id of the group.
   * @return {Promise<ClientResponse<GroupResponse>>} A Promise for the FusionAuth call.
   */
  retrieveGroup: function(groupId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group')
          .urlSegment(groupId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the groups.
   *
   * @return {Promise<ClientResponse<GroupResponse>>} A Promise for the FusionAuth call.
   */
  retrieveGroups: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the IP Access Control List with the given Id.
   *
   * @param {UUIDString} ipAccessControlListId The Id of the IP Access Control List.
   * @return {Promise<ClientResponse<IPAccessControlListResponse>>} A Promise for the FusionAuth call.
   */
  retrieveIPAccessControlList: function(ipAccessControlListId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/ip-acl')
          .urlSegment(ipAccessControlListId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the identity provider for the given Id or all the identity providers if the Id is null.
   *
   * @param {UUIDString} identityProviderId The identity provider Id.
   * @return {Promise<ClientResponse<IdentityProviderResponse>>} A Promise for the FusionAuth call.
   */
  retrieveIdentityProvider: function(identityProviderId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .urlSegment(identityProviderId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single 
   * identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request 
   * may return multiple identity providers.
   *
   * @param {IdentityProviderType} type The type of the identity provider.
   * @return {Promise<ClientResponse<IdentityProviderResponse>>} A Promise for the FusionAuth call.
   */
  retrieveIdentityProviderByType: function(type) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .urlParameter('type', type)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the identity providers.
   *
   * @return {Promise<ClientResponse<IdentityProviderResponse>>} A Promise for the FusionAuth call.
   */
  retrieveIdentityProviders: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the actions for the user with the given Id that are currently inactive.
   * An inactive action means one that is time based and has been canceled or has expired, or is not time based.
   *
   * @param {UUIDString} userId The Id of the user to fetch the actions for.
   * @return {Promise<ClientResponse<ActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveInactiveActions: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/action')
          .urlParameter('userId', userId)
          .urlParameter('active', false)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the applications that are currently inactive.
   *
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveInactiveApplications: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlParameter('inactive', true)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the user actions that are currently inactive.
   *
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveInactiveUserActions: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlParameter('inactive', true)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the available integrations.
   *
   * @return {Promise<ClientResponse<IntegrationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveIntegration: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/integration')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
   *
   * @param {string} keyId The Id of the public key (kid).
   * @return {Promise<ClientResponse<PublicKeyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveJWTPublicKey: function(keyId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/public-key')
          .urlParameter('kid', keyId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
   *
   * @param {string} applicationId The Id of the Application for which this key is used.
   * @return {Promise<ClientResponse<PublicKeyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveJWTPublicKeyByApplicationId: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/public-key')
          .urlParameter('applicationId', applicationId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
   *
   * @return {Promise<ClientResponse<PublicKeyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveJWTPublicKeys: function() {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/public-key')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
   *
   * @return {Promise<ClientResponse<JWKSResponse>>} A Promise for the FusionAuth call.
   */
  retrieveJsonWebKeySet: function() {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/.well-known/jwks.json')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the key for the given Id.
   *
   * @param {UUIDString} keyId The Id of the key.
   * @return {Promise<ClientResponse<KeyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveKey: function(keyId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key')
          .urlSegment(keyId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the keys.
   *
   * @return {Promise<ClientResponse<KeyResponse>>} A Promise for the FusionAuth call.
   */
  retrieveKeys: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the lambda for the given Id.
   *
   * @param {UUIDString} lambdaId The Id of the lambda.
   * @return {Promise<ClientResponse<LambdaResponse>>} A Promise for the FusionAuth call.
   */
  retrieveLambda: function(lambdaId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .urlSegment(lambdaId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the lambdas.
   *
   * @return {Promise<ClientResponse<LambdaResponse>>} A Promise for the FusionAuth call.
   */
  retrieveLambdas: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the lambdas for the provided type.
   *
   * @param {LambdaType} type The type of the lambda to return.
   * @return {Promise<ClientResponse<LambdaResponse>>} A Promise for the FusionAuth call.
   */
  retrieveLambdasByType: function(type) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .urlParameter('type', type)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the login report between the two instants. If you specify an application id, it will only return the
   * login counts for that application.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @return {Promise<ClientResponse<LoginReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveLoginReport: function(applicationId, start, end) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/login')
          .urlParameter('applicationId', applicationId)
          .urlParameter('start', start)
          .urlParameter('end', end)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
   *
   * @param {?UUIDString} messageTemplateId (Optional) The Id of the message template.
   * @return {Promise<ClientResponse<MessageTemplateResponse>>} A Promise for the FusionAuth call.
   */
  retrieveMessageTemplate: function(messageTemplateId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template')
          .urlSegment(messageTemplateId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a preview of the message template provided in the request, normalized to a given locale.
   *
   * @param {PreviewMessageTemplateRequest} request The request that contains the email template and optionally a locale to render it in.
   * @return {Promise<ClientResponse<PreviewMessageTemplateResponse>>} A Promise for the FusionAuth call.
   */
  retrieveMessageTemplatePreview: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template/preview')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the message templates.
   *
   * @return {Promise<ClientResponse<MessageTemplateResponse>>} A Promise for the FusionAuth call.
   */
  retrieveMessageTemplates: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the messenger with the given Id.
   *
   * @param {UUIDString} messengerId The Id of the messenger.
   * @return {Promise<ClientResponse<MessengerResponse>>} A Promise for the FusionAuth call.
   */
  retrieveMessenger: function(messengerId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/messenger')
          .urlSegment(messengerId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the messengers.
   *
   * @return {Promise<ClientResponse<MessengerResponse>>} A Promise for the FusionAuth call.
   */
  retrieveMessengers: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/messenger')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
   * return the monthly active counts for that application.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @return {Promise<ClientResponse<MonthlyActiveUserReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveMonthlyActiveReport: function(applicationId, start, end) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/monthly-active-user')
          .urlParameter('applicationId', applicationId)
          .urlParameter('start', start)
          .urlParameter('end', end)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves a custom OAuth scope.
   *
   * @param {UUIDString} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUIDString} scopeId The Id of the OAuth scope to retrieve.
   * @return {Promise<ClientResponse<ApplicationOAuthScopeResponse>>} A Promise for the FusionAuth call.
   */
  retrieveOAuthScope: function(applicationId, scopeId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("scope")
          .urlSegment(scopeId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the Oauth2 configuration for the application for the given Application Id.
   *
   * @param {UUIDString} applicationId The Id of the Application to retrieve OAuth configuration.
   * @return {Promise<ClientResponse<OAuthConfigurationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveOauthConfiguration: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("oauth-configuration")
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Returns the well known OpenID Configuration JSON document
   *
   * @return {Promise<ClientResponse<OpenIdConfiguration>>} A Promise for the FusionAuth call.
   */
  retrieveOpenIdConfiguration: function() {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/.well-known/openid-configuration')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
   * through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
   * 
   * This API does not require an API key.
   *
   * @return {Promise<ClientResponse<PasswordValidationRulesResponse>>} A Promise for the FusionAuth call.
   */
  retrievePasswordValidationRules: function() {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/tenant/password-validation-rules')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the password validation rules for a specific tenant.
   * 
   * This API does not require an API key.
   *
   * @param {UUIDString} tenantId The Id of the tenant.
   * @return {Promise<ClientResponse<PasswordValidationRulesResponse>>} A Promise for the FusionAuth call.
   */
  retrievePasswordValidationRulesWithTenantId: function(tenantId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/tenant/password-validation-rules')
          .urlSegment(tenantId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the children for the given parent email address.
   *
   * @param {string} parentEmail The email of the parent.
   * @return {Promise<ClientResponse<PendingResponse>>} A Promise for the FusionAuth call.
   */
  retrievePendingChildren: function(parentEmail) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family/pending')
          .urlParameter('parentEmail', parentEmail)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
   *
   * @param {string} pendingLinkId The pending link Id.
   * @param {UUIDString} userId The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.
   * @return {Promise<ClientResponse<IdentityProviderPendingLinkResponse>>} A Promise for the FusionAuth call.
   */
  retrievePendingLink: function(pendingLinkId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/link/pending')
          .urlSegment(pendingLinkId)
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the FusionAuth Reactor metrics.
   *
   * @return {Promise<ClientResponse<ReactorMetricsResponse>>} A Promise for the FusionAuth call.
   */
  retrieveReactorMetrics: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/reactor/metrics')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the FusionAuth Reactor status.
   *
   * @return {Promise<ClientResponse<ReactorResponse>>} A Promise for the FusionAuth call.
   */
  retrieveReactorStatus: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/reactor')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the last number of login records.
   *
   * @param {number} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
   * @param {number} limit (Optional, defaults to 10) The number of records to retrieve.
   * @return {Promise<ClientResponse<RecentLoginResponse>>} A Promise for the FusionAuth call.
   */
  retrieveRecentLogins: function(offset, limit) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/recent-login')
          .urlParameter('offset', offset)
          .urlParameter('limit', limit)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
   *
   * @param {UUIDString} tokenId The Id of the token.
   * @return {Promise<ClientResponse<RefreshTokenResponse>>} A Promise for the FusionAuth call.
   */
  retrieveRefreshTokenById: function(tokenId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlSegment(tokenId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the refresh tokens that belong to the user with the given Id.
   *
   * @param {UUIDString} userId The Id of the user.
   * @return {Promise<ClientResponse<RefreshTokenResponse>>} A Promise for the FusionAuth call.
   */
  retrieveRefreshTokens: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user registration for the user with the given Id and the given application id.
   *
   * @param {UUIDString} userId The Id of the user.
   * @param {UUIDString} applicationId The Id of the application.
   * @return {Promise<ClientResponse<RegistrationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveRegistration: function(userId, applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/registration')
          .urlSegment(userId)
          .urlSegment(applicationId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the registration report between the two instants. If you specify an application id, it will only return
   * the registration counts for that application.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @return {Promise<ClientResponse<RegistrationReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveRegistrationReport: function(applicationId, start, end) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/registration')
          .urlParameter('applicationId', applicationId)
          .urlParameter('start', start)
          .urlParameter('end', end)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of  
   * 404 indicates no re-index is in progress.
   *
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  retrieveReindexStatus: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/reindex')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the system configuration.
   *
   * @return {Promise<ClientResponse<SystemConfigurationResponse>>} A Promise for the FusionAuth call.
   */
  retrieveSystemConfiguration: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system-configuration')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the tenant for the given Id.
   *
   * @param {UUIDString} tenantId The Id of the tenant.
   * @return {Promise<ClientResponse<TenantResponse>>} A Promise for the FusionAuth call.
   */
  retrieveTenant: function(tenantId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the tenants.
   *
   * @return {Promise<ClientResponse<TenantResponse>>} A Promise for the FusionAuth call.
   */
  retrieveTenants: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the theme for the given Id.
   *
   * @param {UUIDString} themeId The Id of the theme.
   * @return {Promise<ClientResponse<ThemeResponse>>} A Promise for the FusionAuth call.
   */
  retrieveTheme: function(themeId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme')
          .urlSegment(themeId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the themes.
   *
   * @return {Promise<ClientResponse<ThemeResponse>>} A Promise for the FusionAuth call.
   */
  retrieveThemes: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the totals report. This contains all the total counts for each application and the global registration
   * count.
   *
   * @return {Promise<ClientResponse<TotalsReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveTotalReport: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/totals')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve two-factor recovery codes for a user.
   *
   * @param {UUIDString} userId The Id of the user to retrieve Two Factor recovery codes.
   * @return {Promise<ClientResponse<TwoFactorRecoveryCodeResponse>>} A Promise for the FusionAuth call.
   */
  retrieveTwoFactorRecoveryCodes: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/two-factor/recovery-code')
          .urlSegment(userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve a user's two-factor status.
   * 
   * This can be used to see if a user will need to complete a two-factor challenge to complete a login,
   * and optionally identify the state of the two-factor trust across various applications.
   *
   * @param {UUIDString} userId The user Id to retrieve the Two-Factor status.
   * @param {UUIDString} applicationId The optional applicationId to verify.
   * @param {string} twoFactorTrustId The optional two-factor trust Id to verify.
   * @return {Promise<ClientResponse<TwoFactorStatusResponse>>} A Promise for the FusionAuth call.
   */
  retrieveTwoFactorStatus: function(userId, applicationId, twoFactorTrustId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/two-factor/status')
          .urlParameter('userId', userId)
          .urlParameter('applicationId', applicationId)
          .urlSegment(twoFactorTrustId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user for the given Id.
   *
   * @param {UUIDString} userId The Id of the user.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUser: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
   * actions.
   *
   * @param {?UUIDString} userActionId (Optional) The Id of the user action.
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserAction: function(userActionId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
   * action reasons.
   *
   * @param {?UUIDString} userActionReasonId (Optional) The Id of the user action reason.
   * @return {Promise<ClientResponse<UserActionReasonResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserActionReason: function(userActionReasonId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action-reason')
          .urlSegment(userActionReasonId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the user action reasons.
   *
   * @return {Promise<ClientResponse<UserActionReasonResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserActionReasons: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action-reason')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the user actions.
   *
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserActions: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
   * password workflow has been initiated and you may not know the user's email or username.
   *
   * @param {string} changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserByChangePasswordId: function(changePasswordId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlParameter('changePasswordId', changePasswordId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user for the given email.
   *
   * @param {string} email The email of the user.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserByEmail: function(email) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlParameter('email', email)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user for the loginId. The loginId can be either the username or the email.
   *
   * @param {string} loginId The email or username of the user.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserByLoginId: function(loginId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlParameter('loginId', loginId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user for the given username.
   *
   * @param {string} username The username of the user.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserByUsername: function(username) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlParameter('username', username)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
   * password workflow has been initiated and you may not know the user's email or username.
   *
   * @param {string} verificationId The unique verification Id that has been set on the user object.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserByVerificationId: function(verificationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlParameter('verificationId', verificationId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve a user_code that is part of an in-progress Device Authorization Grant.
   * 
   * This API is useful if you want to build your own login workflow to complete a device grant.
   *
   * @param {string} client_id The client id.
   * @param {string} client_secret The client id.
   * @param {string} user_code The end-user verification code.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  retrieveUserCode: function(client_id, client_secret, user_code) {
    var body = {
      client_id: client_id,
      client_secret: client_secret,
      user_code: user_code
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/device/user-code')
          .setFormBody(body)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve a user_code that is part of an in-progress Device Authorization Grant.
   * 
   * This API is useful if you want to build your own login workflow to complete a device grant.
   * 
   * This request will require an API key.
   *
   * @param {string} user_code The end-user verification code.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  retrieveUserCodeUsingAPIKey: function(user_code) {
    var body = {
      user_code: user_code
    };
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/device/user-code')
          .setFormBody(body)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the comments for the user with the given Id.
   *
   * @param {UUIDString} userId The Id of the user.
   * @return {Promise<ClientResponse<UserCommentResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserComments: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/comment')
          .urlSegment(userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve a single User consent by Id.
   *
   * @param {UUIDString} userConsentId The User consent Id
   * @return {Promise<ClientResponse<UserConsentResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserConsent: function(userConsentId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/consent')
          .urlSegment(userConsentId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the consents for a User.
   *
   * @param {UUIDString} userId The User's Id
   * @return {Promise<ClientResponse<UserConsentResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserConsents: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/consent')
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Call the UserInfo endpoint to retrieve User Claims from the access token issued by FusionAuth.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @return {Promise<ClientResponse<UserinfoResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserInfoFromAccessToken: function(encodedJWT) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/userinfo')
          .authorization('Bearer ' + encodedJWT)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve a single Identity Provider user (link).
   *
   * @param {UUIDString} identityProviderId The unique Id of the identity provider.
   * @param {string} identityProviderUserId The unique Id of the user in the 3rd party identity provider.
   * @param {UUIDString} userId The unique Id of the FusionAuth user.
   * @return {Promise<ClientResponse<IdentityProviderLinkResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserLink: function(identityProviderId, identityProviderUserId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/link')
          .urlParameter('identityProviderId', identityProviderId)
          .urlParameter('identityProviderUserId', identityProviderUserId)
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
   *
   * @param {?UUIDString} identityProviderId (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.
   * @param {UUIDString} userId The unique Id of the user.
   * @return {Promise<ClientResponse<IdentityProviderLinkResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserLinksByUserId: function(identityProviderId, userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/link')
          .urlParameter('identityProviderId', identityProviderId)
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
   * login counts for that application.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @param {UUIDString} userId The userId id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @return {Promise<ClientResponse<LoginReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserLoginReport: function(applicationId, userId, start, end) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/login')
          .urlParameter('applicationId', applicationId)
          .urlParameter('userId', userId)
          .urlParameter('start', start)
          .urlParameter('end', end)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
   * login counts for that application.
   *
   * @param {?UUIDString} applicationId (Optional) The application id.
   * @param {string} loginId The userId id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @return {Promise<ClientResponse<LoginReportResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserLoginReportByLoginId: function(applicationId, loginId, start, end) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/report/login')
          .urlParameter('applicationId', applicationId)
          .urlParameter('loginId', loginId)
          .urlParameter('start', start)
          .urlParameter('end', end)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the last number of login records for a user.
   *
   * @param {UUIDString} userId The Id of the user.
   * @param {number} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
   * @param {number} limit (Optional, defaults to 10) The number of records to retrieve.
   * @return {Promise<ClientResponse<RecentLoginResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserRecentLogins: function(userId, offset, limit) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/recent-login')
          .urlParameter('userId', userId)
          .urlParameter('offset', offset)
          .urlParameter('limit', limit)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  retrieveUserUsingJWT: function(encodedJWT) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user')
          .authorization('Bearer ' + encodedJWT)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the FusionAuth version string.
   *
   * @return {Promise<ClientResponse<VersionResponse>>} A Promise for the FusionAuth call.
   */
  retrieveVersion: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/version')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the WebAuthn credential for the given Id.
   *
   * @param {UUIDString} id The Id of the WebAuthn credential.
   * @return {Promise<ClientResponse<WebAuthnCredentialResponse>>} A Promise for the FusionAuth call.
   */
  retrieveWebAuthnCredential: function(id) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn')
          .urlSegment(id)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all WebAuthn credentials for the given user.
   *
   * @param {UUIDString} userId The user's ID.
   * @return {Promise<ClientResponse<WebAuthnCredentialResponse>>} A Promise for the FusionAuth call.
   */
  retrieveWebAuthnCredentialsForUser: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn')
          .urlParameter('userId', userId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
   *
   * @param {?UUIDString} webhookId (Optional) The Id of the webhook.
   * @return {Promise<ClientResponse<WebhookResponse>>} A Promise for the FusionAuth call.
   */
  retrieveWebhook: function(webhookId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webhook')
          .urlSegment(webhookId)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves all the webhooks.
   *
   * @return {Promise<ClientResponse<WebhookResponse>>} A Promise for the FusionAuth call.
   */
  retrieveWebhooks: function() {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webhook')
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revokes refresh tokens.
   * 
   * Usage examples:
   *   - Delete a single refresh token, pass in only the token.
   *       revokeRefreshToken(token)
   * 
   *   - Delete all refresh tokens for a user, pass in only the userId.
   *       revokeRefreshToken(null, userId)
   * 
   *   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
   *       revokeRefreshToken(null, userId, applicationId)
   * 
   *   - Delete all refresh tokens for an application
   *       revokeRefreshToken(null, null, applicationId)
   * 
   * Note: <code>null</code> may be handled differently depending upon the programming language.
   * 
   * See also: (method names may vary by language... but you'll figure it out)
   * 
   *  - revokeRefreshTokenById
   *  - revokeRefreshTokenByToken
   *  - revokeRefreshTokensByUserId
   *  - revokeRefreshTokensByApplicationId
   *  - revokeRefreshTokensByUserIdForApplication
   *
   * @param {?string} token (Optional) The refresh token to delete.
   * @param {?UUIDString} userId (Optional) The user Id whose tokens to delete.
   * @param {?UUIDString} applicationId (Optional) The application Id of the tokens to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshToken: function(token, userId, applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlParameter('token', token)
          .urlParameter('userId', userId)
          .urlParameter('applicationId', applicationId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
   *
   * @param {UUIDString} tokenId The unique Id of the token to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshTokenById: function(tokenId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlSegment(tokenId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
   *
   * @param {string} token The refresh token to delete.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshTokenByToken: function(token) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlParameter('token', token)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revoke all refresh tokens that belong to an application by applicationId.
   *
   * @param {UUIDString} applicationId The unique Id of the application that you want to delete all refresh tokens for.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshTokensByApplicationId: function(applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlParameter('applicationId', applicationId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revoke all refresh tokens that belong to a user by user Id.
   *
   * @param {UUIDString} userId The unique Id of the user that you want to delete all refresh tokens for.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshTokensByUserId: function(userId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlParameter('userId', userId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
   *
   * @param {UUIDString} userId The unique Id of the user that you want to delete all refresh tokens for.
   * @param {UUIDString} applicationId The unique Id of the application that you want to delete refresh tokens for.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshTokensByUserIdForApplication: function(userId, applicationId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .urlParameter('userId', userId)
          .urlParameter('applicationId', applicationId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
   * and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
   *
   * @param {RefreshTokenRevokeRequest} request The request information used to revoke the refresh tokens.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeRefreshTokensWithRequest: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/refresh')
          .setJSONBody(request)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Revokes a single User consent by Id.
   *
   * @param {UUIDString} userConsentId The User Consent Id
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  revokeUserConsent: function(userConsentId) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/consent')
          .urlSegment(userConsentId)
          .delete()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches applications with the specified criteria and pagination.
   *
   * @param {ApplicationSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<ApplicationSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchApplications: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches the audit logs with the specified criteria and pagination.
   *
   * @param {AuditLogSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<AuditLogSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchAuditLogs: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/audit-log/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches consents with the specified criteria and pagination.
   *
   * @param {ConsentSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<ConsentSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchConsents: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches email templates with the specified criteria and pagination.
   *
   * @param {EmailTemplateSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<EmailTemplateSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchEmailTemplates: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches entities with the specified criteria and pagination.
   *
   * @param {EntitySearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<EntitySearchResponse>>} A Promise for the FusionAuth call.
   */
  searchEntities: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the entities for the given ids. If any Id is invalid, it is ignored.
   *
   * @param {Array<string>} ids The entity ids to search for.
   * @return {Promise<ClientResponse<EntitySearchResponse>>} A Promise for the FusionAuth call.
   */
  searchEntitiesByIds: function(ids) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/search')
          .urlParameter('ids', ids)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches Entity Grants with the specified criteria and pagination.
   *
   * @param {EntityGrantSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<EntityGrantSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchEntityGrants: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/grant/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches the entity types with the specified criteria and pagination.
   *
   * @param {EntityTypeSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<EntityTypeSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchEntityTypes: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches the event logs with the specified criteria and pagination.
   *
   * @param {EventLogSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<EventLogSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchEventLogs: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/event-log/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches group members with the specified criteria and pagination.
   *
   * @param {GroupMemberSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<GroupMemberSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchGroupMembers: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group/member/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches groups with the specified criteria and pagination.
   *
   * @param {GroupSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<GroupSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchGroups: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches the IP Access Control Lists with the specified criteria and pagination.
   *
   * @param {IPAccessControlListSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<IPAccessControlListSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchIPAccessControlLists: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/ip-acl/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches identity providers with the specified criteria and pagination.
   *
   * @param {IdentityProviderSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<IdentityProviderSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchIdentityProviders: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches keys with the specified criteria and pagination.
   *
   * @param {KeySearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<KeySearchResponse>>} A Promise for the FusionAuth call.
   */
  searchKeys: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches lambdas with the specified criteria and pagination.
   *
   * @param {LambdaSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<LambdaSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchLambdas: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches the login records with the specified criteria and pagination.
   *
   * @param {LoginRecordSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<LoginRecordSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchLoginRecords: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system/login-record/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches tenants with the specified criteria and pagination.
   *
   * @param {TenantSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<TenantSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchTenants: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches themes with the specified criteria and pagination.
   *
   * @param {ThemeSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<ThemeSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchThemes: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches user comments with the specified criteria and pagination.
   *
   * @param {UserCommentSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<UserCommentSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchUserComments: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/comment/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the users for the given ids. If any Id is invalid, it is ignored.
   *
   * @param {Array<string>} ids The user ids to search for.
   * @return {Promise<ClientResponse<SearchResponse>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to searchUsersByIds, use that method instead.
   */
  searchUsers: function(ids) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/search')
          .urlParameter('ids', ids)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the users for the given ids. If any Id is invalid, it is ignored.
   *
   * @param {Array<string>} ids The user ids to search for.
   * @return {Promise<ClientResponse<SearchResponse>>} A Promise for the FusionAuth call.
   */
  searchUsersByIds: function(ids) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/search')
          .urlParameter('ids', ids)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the users for the given search criteria and pagination.
   *
   * @param {SearchRequest} request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
   *    and sortFields.
   * @return {Promise<ClientResponse<SearchResponse>>} A Promise for the FusionAuth call.
   */
  searchUsersByQuery: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Retrieves the users for the given search criteria and pagination.
   *
   * @param {SearchRequest} request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
   *    and sortFields.
   * @return {Promise<ClientResponse<SearchResponse>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to searchUsersByQuery, use that method instead.
   */
  searchUsersByQueryString: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Searches webhooks with the specified criteria and pagination.
   *
   * @param {WebhookSearchRequest} request The search criteria and pagination information.
   * @return {Promise<ClientResponse<WebhookSearchResponse>>} A Promise for the FusionAuth call.
   */
  searchWebhooks: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webhook/search')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
   * pairs in the email template.
   *
   * @param {UUIDString} emailTemplateId The Id for the template.
   * @param {SendRequest} request The send email request that contains all the information used to send the email.
   * @return {Promise<ClientResponse<SendResponse>>} A Promise for the FusionAuth call.
   */
  sendEmail: function(emailTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/send')
          .urlSegment(emailTemplateId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
   *
   * @param {FamilyEmailRequest} request The request object that contains the parent email.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  sendFamilyRequestEmail: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/family/request')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Send a passwordless authentication code in an email to complete login.
   *
   * @param {PasswordlessSendRequest} request The passwordless send request that contains all the information used to send an email containing a code.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  sendPasswordlessCode: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/passwordless/send')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
   *
   * @param {TwoFactorSendRequest} request The request object that contains all the information used to send the code.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to sendTwoFactorCodeForEnableDisable, use that method instead.
   */
  sendTwoFactorCode: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/two-factor/send')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
   *
   * @param {TwoFactorSendRequest} request The request object that contains all the information used to send the code.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  sendTwoFactorCodeForEnableDisable: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/two-factor/send')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Send a Two Factor authentication code to allow the completion of Two Factor authentication.
   *
   * @param {string} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to sendTwoFactorCodeForLoginUsingMethod, use that method instead.
   */
  sendTwoFactorCodeForLogin: function(twoFactorId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/two-factor/send')
          .urlSegment(twoFactorId)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Send a Two Factor authentication code to allow the completion of Two Factor authentication.
   *
   * @param {string} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
   * @param {TwoFactorSendRequest} request The Two Factor send request that contains all the information used to send the Two Factor code to the user.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  sendTwoFactorCodeForLoginUsingMethod: function(twoFactorId, request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/two-factor/send')
          .urlSegment(twoFactorId)
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Begins a login request for a 3rd party login that requires user interaction such as HYPR.
   *
   * @param {IdentityProviderStartLoginRequest} request The third-party login request that contains information from the third-party login
   *    providers that FusionAuth uses to reconcile the user's account.
   * @return {Promise<ClientResponse<IdentityProviderStartLoginResponse>>} A Promise for the FusionAuth call.
   */
  startIdentityProviderLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider/start')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
   * Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
   *
   * @param {PasswordlessStartRequest} request The passwordless start request that contains all the information used to begin the passwordless login request.
   * @return {Promise<ClientResponse<PasswordlessStartResponse>>} A Promise for the FusionAuth call.
   */
  startPasswordlessLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/passwordless/start')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send 
   * API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned 
   * to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login 
   * API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
   * 
   * This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
   *
   * @param {TwoFactorStartRequest} request The Two-Factor start request that contains all the information used to begin the Two-Factor login request.
   * @return {Promise<ClientResponse<TwoFactorStartResponse>>} A Promise for the FusionAuth call.
   */
  startTwoFactorLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/two-factor/start')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Start a WebAuthn authentication ceremony by generating a new challenge for the user
   *
   * @param {WebAuthnStartRequest} request An object containing data necessary for starting the authentication ceremony
   * @return {Promise<ClientResponse<WebAuthnStartResponse>>} A Promise for the FusionAuth call.
   */
  startWebAuthnLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn/start')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Start a WebAuthn registration ceremony by generating a new challenge for the user
   *
   * @param {WebAuthnRegisterStartRequest} request An object containing data necessary for starting the registration ceremony
   * @return {Promise<ClientResponse<WebAuthnRegisterStartResponse>>} A Promise for the FusionAuth call.
   */
  startWebAuthnRegistration: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webauthn/register/start')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Complete login using a 2FA challenge
   *
   * @param {TwoFactorLoginRequest} request The login request that contains the user credentials used to log them in.
   * @return {Promise<ClientResponse<LoginResponse>>} A Promise for the FusionAuth call.
   */
  twoFactorLogin: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/two-factor/login')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates an API key by given id
   *
   * @param {UUIDString} apiKeyId The Id of the API key to update.
   * @param {APIKeyRequest} request The request object that contains all the information used to create the API Key.
   * @return {Promise<ClientResponse<APIKeyResponse>>} A Promise for the FusionAuth call.
   */
  updateAPIKey: function(apiKeyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/api-key')
          .urlSegment(apiKeyId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the application with the given Id.
   *
   * @param {UUIDString} applicationId The Id of the application to update.
   * @param {ApplicationRequest} request The request that contains all the new application information.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  updateApplication: function(applicationId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the application role with the given Id for the application.
   *
   * @param {UUIDString} applicationId The Id of the application that the role belongs to.
   * @param {UUIDString} roleId The Id of the role to update.
   * @param {ApplicationRequest} request The request that contains all the new role information.
   * @return {Promise<ClientResponse<ApplicationResponse>>} A Promise for the FusionAuth call.
   */
  updateApplicationRole: function(applicationId, roleId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("role")
          .urlSegment(roleId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the connector with the given Id.
   *
   * @param {UUIDString} connectorId The Id of the connector to update.
   * @param {ConnectorRequest} request The request object that contains all the new connector information.
   * @return {Promise<ClientResponse<ConnectorResponse>>} A Promise for the FusionAuth call.
   */
  updateConnector: function(connectorId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/connector')
          .urlSegment(connectorId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the consent with the given Id.
   *
   * @param {UUIDString} consentId The Id of the consent to update.
   * @param {ConsentRequest} request The request that contains all the new consent information.
   * @return {Promise<ClientResponse<ConsentResponse>>} A Promise for the FusionAuth call.
   */
  updateConsent: function(consentId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/consent')
          .urlSegment(consentId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the email template with the given Id.
   *
   * @param {UUIDString} emailTemplateId The Id of the email template to update.
   * @param {EmailTemplateRequest} request The request that contains all the new email template information.
   * @return {Promise<ClientResponse<EmailTemplateResponse>>} A Promise for the FusionAuth call.
   */
  updateEmailTemplate: function(emailTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/email/template')
          .urlSegment(emailTemplateId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the Entity with the given Id.
   *
   * @param {UUIDString} entityId The Id of the Entity to update.
   * @param {EntityRequest} request The request that contains all the new Entity information.
   * @return {Promise<ClientResponse<EntityResponse>>} A Promise for the FusionAuth call.
   */
  updateEntity: function(entityId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the Entity Type with the given Id.
   *
   * @param {UUIDString} entityTypeId The Id of the Entity Type to update.
   * @param {EntityTypeRequest} request The request that contains all the new Entity Type information.
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  updateEntityType: function(entityTypeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the permission with the given Id for the entity type.
   *
   * @param {UUIDString} entityTypeId The Id of the entityType that the permission belongs to.
   * @param {UUIDString} permissionId The Id of the permission to update.
   * @param {EntityTypeRequest} request The request that contains all the new permission information.
   * @return {Promise<ClientResponse<EntityTypeResponse>>} A Promise for the FusionAuth call.
   */
  updateEntityTypePermission: function(entityTypeId, permissionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity/type')
          .urlSegment(entityTypeId)
          .urlSegment("permission")
          .urlSegment(permissionId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the form with the given Id.
   *
   * @param {UUIDString} formId The Id of the form to update.
   * @param {FormRequest} request The request object that contains all the new form information.
   * @return {Promise<ClientResponse<FormResponse>>} A Promise for the FusionAuth call.
   */
  updateForm: function(formId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form')
          .urlSegment(formId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the form field with the given Id.
   *
   * @param {UUIDString} fieldId The Id of the form field to update.
   * @param {FormFieldRequest} request The request object that contains all the new form field information.
   * @return {Promise<ClientResponse<FormFieldResponse>>} A Promise for the FusionAuth call.
   */
  updateFormField: function(fieldId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/form/field')
          .urlSegment(fieldId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the group with the given Id.
   *
   * @param {UUIDString} groupId The Id of the group to update.
   * @param {GroupRequest} request The request that contains all the new group information.
   * @return {Promise<ClientResponse<GroupResponse>>} A Promise for the FusionAuth call.
   */
  updateGroup: function(groupId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group')
          .urlSegment(groupId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates a member in a group.
   *
   * @param {MemberRequest} request The request object that contains all the information used to create the group member(s).
   * @return {Promise<ClientResponse<MemberResponse>>} A Promise for the FusionAuth call.
   */
  updateGroupMembers: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/group/member')
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the IP Access Control List with the given Id.
   *
   * @param {UUIDString} accessControlListId The Id of the IP Access Control List to update.
   * @param {IPAccessControlListRequest} request The request that contains all the new IP Access Control List information.
   * @return {Promise<ClientResponse<IPAccessControlListResponse>>} A Promise for the FusionAuth call.
   */
  updateIPAccessControlList: function(accessControlListId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/ip-acl')
          .urlSegment(accessControlListId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the identity provider with the given Id.
   *
   * @param {UUIDString} identityProviderId The Id of the identity provider to update.
   * @param {IdentityProviderRequest} request The request object that contains the updated identity provider.
   * @return {Promise<ClientResponse<IdentityProviderResponse>>} A Promise for the FusionAuth call.
   */
  updateIdentityProvider: function(identityProviderId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/identity-provider')
          .urlSegment(identityProviderId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the available integrations.
   *
   * @param {IntegrationRequest} request The request that contains all the new integration information.
   * @return {Promise<ClientResponse<IntegrationResponse>>} A Promise for the FusionAuth call.
   */
  updateIntegrations: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/integration')
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the key with the given Id.
   *
   * @param {UUIDString} keyId The Id of the key to update.
   * @param {KeyRequest} request The request that contains all the new key information.
   * @return {Promise<ClientResponse<KeyResponse>>} A Promise for the FusionAuth call.
   */
  updateKey: function(keyId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/key')
          .urlSegment(keyId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the lambda with the given Id.
   *
   * @param {UUIDString} lambdaId The Id of the lambda to update.
   * @param {LambdaRequest} request The request that contains all the new lambda information.
   * @return {Promise<ClientResponse<LambdaResponse>>} A Promise for the FusionAuth call.
   */
  updateLambda: function(lambdaId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/lambda')
          .urlSegment(lambdaId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the message template with the given Id.
   *
   * @param {UUIDString} messageTemplateId The Id of the message template to update.
   * @param {MessageTemplateRequest} request The request that contains all the new message template information.
   * @return {Promise<ClientResponse<MessageTemplateResponse>>} A Promise for the FusionAuth call.
   */
  updateMessageTemplate: function(messageTemplateId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/message/template')
          .urlSegment(messageTemplateId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the messenger with the given Id.
   *
   * @param {UUIDString} messengerId The Id of the messenger to update.
   * @param {MessengerRequest} request The request object that contains all the new messenger information.
   * @return {Promise<ClientResponse<MessengerResponse>>} A Promise for the FusionAuth call.
   */
  updateMessenger: function(messengerId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/messenger')
          .urlSegment(messengerId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the OAuth scope with the given Id for the application.
   *
   * @param {UUIDString} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUIDString} scopeId The Id of the OAuth scope to update.
   * @param {ApplicationOAuthScopeRequest} request The request that contains all the new OAuth scope information.
   * @return {Promise<ClientResponse<ApplicationOAuthScopeResponse>>} A Promise for the FusionAuth call.
   */
  updateOAuthScope: function(applicationId, scopeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/application')
          .urlSegment(applicationId)
          .urlSegment("scope")
          .urlSegment(scopeId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the registration for the user with the given Id and the application defined in the request.
   *
   * @param {UUIDString} userId The Id of the user whose registration is going to be updated.
   * @param {RegistrationRequest} request The request that contains all the new registration information.
   * @return {Promise<ClientResponse<RegistrationResponse>>} A Promise for the FusionAuth call.
   */
  updateRegistration: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/registration')
          .urlSegment(userId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the system configuration.
   *
   * @param {SystemConfigurationRequest} request The request that contains all the new system configuration information.
   * @return {Promise<ClientResponse<SystemConfigurationResponse>>} A Promise for the FusionAuth call.
   */
  updateSystemConfiguration: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/system-configuration')
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the tenant with the given Id.
   *
   * @param {UUIDString} tenantId The Id of the tenant to update.
   * @param {TenantRequest} request The request that contains all the new tenant information.
   * @return {Promise<ClientResponse<TenantResponse>>} A Promise for the FusionAuth call.
   */
  updateTenant: function(tenantId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/tenant')
          .urlSegment(tenantId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the theme with the given Id.
   *
   * @param {UUIDString} themeId The Id of the theme to update.
   * @param {ThemeRequest} request The request that contains all the new theme information.
   * @return {Promise<ClientResponse<ThemeResponse>>} A Promise for the FusionAuth call.
   */
  updateTheme: function(themeId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/theme')
          .urlSegment(themeId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the user with the given Id.
   *
   * @param {UUIDString} userId The Id of the user to update.
   * @param {UserRequest} request The request that contains all the new user information.
   * @return {Promise<ClientResponse<UserResponse>>} A Promise for the FusionAuth call.
   */
  updateUser: function(userId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user')
          .urlSegment(userId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the user action with the given Id.
   *
   * @param {UUIDString} userActionId The Id of the user action to update.
   * @param {UserActionRequest} request The request that contains all the new user action information.
   * @return {Promise<ClientResponse<UserActionResponse>>} A Promise for the FusionAuth call.
   */
  updateUserAction: function(userActionId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action')
          .urlSegment(userActionId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the user action reason with the given Id.
   *
   * @param {UUIDString} userActionReasonId The Id of the user action reason to update.
   * @param {UserActionReasonRequest} request The request that contains all the new user action reason information.
   * @return {Promise<ClientResponse<UserActionReasonResponse>>} A Promise for the FusionAuth call.
   */
  updateUserActionReason: function(userActionReasonId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user-action-reason')
          .urlSegment(userActionReasonId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates a single User consent by Id.
   *
   * @param {UUIDString} userConsentId The User Consent Id
   * @param {UserConsentRequest} request The request that contains the user consent information.
   * @return {Promise<ClientResponse<UserConsentResponse>>} A Promise for the FusionAuth call.
   */
  updateUserConsent: function(userConsentId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/consent')
          .urlSegment(userConsentId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Updates the webhook with the given Id.
   *
   * @param {UUIDString} webhookId The Id of the webhook to update.
   * @param {WebhookRequest} request The request that contains all the new webhook information.
   * @return {Promise<ClientResponse<WebhookResponse>>} A Promise for the FusionAuth call.
   */
  updateWebhook: function(webhookId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/webhook')
          .urlSegment(webhookId)
          .setJSONBody(request)
          .put()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
   *
   * @param {UUIDString} entityId The Id of the Entity that the User/Entity is being granted access to.
   * @param {EntityGrantRequest} request The request object that contains all the information used to create the Entity Grant.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  upsertEntityGrant: function(entityId, request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/entity')
          .urlSegment(entityId)
          .urlSegment("grant")
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
   * If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
   *
   * @param {string} user_code The end-user verification code.
   * @param {string} client_id The client id.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  validateDevice: function(user_code, client_id) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/oauth2/device/validate')
          .urlParameter('user_code', user_code)
          .urlParameter('client_id', client_id)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
   * signed and not expired.
   * <p>
   * This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @return {Promise<ClientResponse<ValidateResponse>>} A Promise for the FusionAuth call.
   */
  validateJWT: function(encodedJWT) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/jwt/validate')
          .authorization('Bearer ' + encodedJWT)
          .get()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * It's a JWT vending machine!
   * 
   * Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form 
   * token that will contain what claims you provide.
   * <p>
   * The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
   * 
   * If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either 
   * by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
   *
   * @param {JWTVendRequest} request The request that contains all the claims for this JWT.
   * @return {Promise<ClientResponse<JWTVendResponse>>} A Promise for the FusionAuth call.
   */
  vendJWT: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/jwt/vend')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Confirms a email verification. The Id given is usually from an email sent to the user.
   *
   * @param {string} verificationId The email verification Id sent to the user.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to verifyEmailAddress and changed to take a JSON request body, use that method instead.
   */
  verifyEmail: function(verificationId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/verify-email')
          .urlSegment(verificationId)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Confirms a user's email address. 
   * 
   * The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
   * the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one. 
   * The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
   * two values together are able to confirm a user's email address and mark the user's email address as verified.
   *
   * @param {VerifyEmailRequest} request The request that contains the verificationId and optional one-time use code paired with the verificationId.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  verifyEmailAddress: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/verify-email')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Administratively verify a user's email address. Use this method to bypass email verification for the user.
   * 
   * The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
   *
   * @param {VerifyEmailRequest} request The request that contains the userId to verify.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  verifyEmailAddressByUserId: function(request) {
    return new Promise((resolve, reject) => {
      this._start()
          .uri('/api/user/verify-email')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Confirms an application registration. The Id given is usually from an email sent to the user.
   *
   * @param {string} verificationId The registration verification Id sent to the user.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   *
   * @deprecated This method has been renamed to verifyUserRegistration and changed to take a JSON request body, use that method instead.
   */
  verifyRegistration: function(verificationId) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/verify-registration')
          .urlSegment(verificationId)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /**
   * Confirms a user's registration. 
   * 
   * The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
   * the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one. 
   * The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
   * two values together are able to confirm a user's registration and mark the user's registration as verified.
   *
   * @param {VerifyRegistrationRequest} request The request that contains the verificationId and optional one-time use code paired with the verificationId.
   * @return {Promise<ClientResponse<void>>} A Promise for the FusionAuth call.
   */
  verifyUserRegistration: function(request) {
    return new Promise((resolve, reject) => {
      this._startAnonymous()
          .uri('/api/user/verify-registration')
          .setJSONBody(request)
          .post()
          .go(this._responseHandler(resolve, reject));
    });
  },

  /* ===================================================================================================================
   * Private methods
   * ===================================================================================================================*/

  /**
   * Require a parameter to be defined, if null or un-defined this throws an exception.
   * @param {Object} value The value that must be defined.
   * @param {string} name The name of the parameter.
   * @private
   */
  _requireNonNull: function(value, name) {
    if (typeof value === 'undefined' || value === null) {
      throw new Error(name + ' parameter is required.');
    }
  },

  /**
   * Returns a function to handle the promises for each call.
   *
   * @param {Function} resolve The promise's resolve function.
   * @param {Function} reject The promise's reject function.
   * @returns {Function} The function that will call either the resolve or reject functions based on the ClientResponse.
   * @private
   */
  _responseHandler: function(resolve, reject) {
    return function(response) {
      if (response.wasSuccessful()) {
        resolve(response);
      } else {
        reject(response);
      }
    };
  },

  /**
   * creates a rest client
   *
   * @returns {RESTClient} The RESTClient that will be used to call.
   * @private
   */
  _start: function() {
    return this._startAnonymous().authorization(this.apiKey);
  },

  _startAnonymous: function() {
    const client = new RESTClient().setUrl(this.host);

    if (this.tenantId !== null && typeof(this.tenantId) !== 'undefined') {
      client.header('X-FusionAuth-TenantId', this.tenantId);
    }

    return client;
  }
};

/**
 * A 128 bit UUID in string format "8-4-4-4-12", for example "58D5E212-165B-4CA0-909B-C86B9CEE0111".
 *
 * @typedef {string} UUIDString
 */

/**
 * Facebook social login provider.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} FacebookIdentityProvider
 * @extends BaseIdentityProvider<FacebookApplicationConfiguration>
 *
 * @property {string} [appId]
 * @property {string} [buttonText]
 * @property {string} [client_secret]
 * @property {string} [fields]
 * @property {IdentityProviderLoginMethod} [loginMethod]
 * @property {string} [permissions]
 */


/**
 * @typedef {Object} UniqueUsernameConfiguration
 * @extends Enableable
 *
 * @property {number} [numberOfDigits]
 * @property {char} [separator]
 * @property {UniqueUsernameStrategy} [strategy]
 */


/**
 * Models a set of localized Integers that can be stored as JSON.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} LocalizedIntegers
 * @extends Object<string, number>
 *
 */


/**
 * @readonly
 * @enum
 */
var XMLSignatureLocation = {
  Assertion: 'Assertion',
  Response: 'Response'
};

/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} EpicGamesApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * API request for sending out family requests to parent's.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} FamilyEmailRequest
 *
 * @property {string} [parentEmail]
 */


/**
 * Login API request object.
 *
 * @author Seth Musselman
 *
 * @typedef {Object} LoginRequest
 * @extends BaseLoginRequest
 *
 * @property {string} [loginId]
 * @property {string} [oneTimePassword]
 * @property {string} [password]
 * @property {string} [twoFactorTrustId]
 */


/**
 * Models a JWT Refresh Token.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} RefreshToken
 *
 * @property {UUIDString} [applicationId]
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {MetaData} [metaData]
 * @property {number} [startInstant]
 * @property {UUIDString} [tenantId]
 * @property {string} [token]
 * @property {UUIDString} [userId]
 */


/**
 * Forgot password request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ForgotPasswordRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [changePasswordId]
 * @property {string} [email]
 * @property {string} [loginId]
 * @property {boolean} [sendForgotPasswordEmail]
 * @property {Object<string, Object>} [state]
 * @property {string} [username]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LinkedInApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * Search request for Groups.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupSearchRequest
 *
 * @property {GroupSearchCriteria} [search]
 */


/**
 * @readonly
 * @enum
 */
var KeyAlgorithm = {
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512'
};

/**
 * @author Seth Musselman
 *
 * @typedef {Object} Application
 *
 * @property {ApplicationAccessControlConfiguration} [accessControlConfiguration]
 * @property {boolean} [active]
 * @property {AuthenticationTokenConfiguration} [authenticationTokenConfiguration]
 * @property {CleanSpeakConfiguration} [cleanSpeakConfiguration]
 * @property {Object<string, Object>} [data]
 * @property {ApplicationEmailConfiguration} [emailConfiguration]
 * @property {ApplicationExternalIdentifierConfiguration} [externalIdentifierConfiguration]
 * @property {ApplicationFormConfiguration} [formConfiguration]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {JWTConfiguration} [jwtConfiguration]
 * @property {LambdaConfiguration} [lambdaConfiguration]
 * @property {number} [lastUpdateInstant]
 * @property {LoginConfiguration} [loginConfiguration]
 * @property {ApplicationMultiFactorConfiguration} [multiFactorConfiguration]
 * @property {string} [name]
 * @property {OAuth2Configuration} [oauthConfiguration]
 * @property {PasswordlessConfiguration} [passwordlessConfiguration]
 * @property {RegistrationConfiguration} [registrationConfiguration]
 * @property {ApplicationRegistrationDeletePolicy} [registrationDeletePolicy]
 * @property {Array<ApplicationRole>} [roles]
 * @property {SAMLv2Configuration} [samlv2Configuration]
 * @property {Array<ApplicationOAuthScope>} [scopes]
 * @property {ObjectState} [state]
 * @property {UUIDString} [tenantId]
 * @property {UUIDString} [themeId]
 * @property {RegistrationUnverifiedOptions} [unverified]
 * @property {UUIDString} [verificationEmailTemplateId]
 * @property {VerificationStrategy} [verificationStrategy]
 * @property {boolean} [verifyRegistration]
 * @property {ApplicationWebAuthnConfiguration} [webAuthnConfiguration]
 */


/**
 * Form response.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} FormRequest
 *
 * @property {Form} [form]
 */


/**
 * The user action request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ActionRequest
 * @extends BaseEventRequest
 *
 * @property {ActionData} [action]
 * @property {boolean} [broadcast]
 */


/**
 * Entity grant API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityGrantResponse
 *
 * @property {EntityGrant} [grant]
 * @property {Array<EntityGrant>} [grants]
 */


/**
 * Models an event where a user's email is updated outside of a forgot / change password workflow.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserEmailUpdateEvent
 * @extends BaseEvent
 *
 * @property {string} [previousEmail]
 * @property {User} [user]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} HYPRApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [relyingPartyApplicationId]
 * @property {string} [relyingPartyURL]
 */


/**
 * A log for an event that happened to a User.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserComment
 *
 * @property {string} [comment]
 * @property {UUIDString} [commenterId]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {UUIDString} [userId]
 */


/**
 * WebAuthn Credential API response
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnCredentialResponse
 *
 * @property {WebAuthnCredential} [credential]
 * @property {Array<WebAuthnCredential>} [credentials]
 */


/**
 * Models the Refresh Token Revoke Event. This event might be for a single token, a user
 * or an entire application.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} JWTRefreshTokenRevokeEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {Object<UUIDString, number>} [applicationTimeToLiveInSeconds]
 * @property {RefreshToken} [refreshToken]
 * @property {User} [user]
 * @property {UUIDString} [userId]
 */


/**
 * The use type of a key.
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var KeyUse = {
  SignOnly: 'SignOnly',
  SignAndVerify: 'SignAndVerify',
  VerifyOnly: 'VerifyOnly'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorResponse
 *
 * @property {string} [code]
 * @property {Array<string>} [recoveryCodes]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginRecordSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {UUIDString} [applicationId]
 * @property {number} [end]
 * @property {number} [start]
 * @property {UUIDString} [userId]
 */


/**
 * Something that can be required and thus also optional. This currently extends Enableable because anything that is
 * required/optional is almost always enableable as well.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Requirable
 * @extends Enableable
 *
 * @property {boolean} [required]
 */


/**
 * Group Member Request
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} MemberRequest
 *
 * @property {Object<UUIDString, Array<GroupMember>>} [members]
 */


/**
 * Search criteria for Groups
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 * @property {UUIDString} [tenantId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordlessLoginRequest
 * @extends BaseLoginRequest
 *
 * @property {string} [code]
 * @property {string} [twoFactorTrustId]
 */


/**
 * A number identifying a cryptographic algorithm. Values should be registered with the <a
 * href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var CoseAlgorithmIdentifier = {
  ES256: 'SHA256withECDSA',
  ES384: 'SHA384withECDSA',
  ES512: 'SHA512withECDSA',
  RS256: 'SHA256withRSA',
  RS384: 'SHA384withRSA',
  RS512: 'SHA512withRSA',
  PS256: 'SHA-256',
  PS384: 'SHA-384',
  PS512: 'SHA-512'
};

/**
 * Information about a user event (login, register, etc) that helps identify the source of the event (location, device type, OS, etc).
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventInfo
 *
 * @property {Object<string, Object>} [data]
 * @property {string} [deviceDescription]
 * @property {string} [deviceName]
 * @property {string} [deviceType]
 * @property {string} [ipAddress]
 * @property {Location} [location]
 * @property {string} [os]
 * @property {string} [userAgent]
 */


/**
 * Theme API request object.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} ThemeRequest
 *
 * @property {UUIDString} [sourceThemeId]
 * @property {Theme} [theme]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventLogSearchRequest
 *
 * @property {EventLogSearchCriteria} [search]
 */


/**
 * Supply additional information about the Relying Party when creating a new credential
 *
 * @author Spencer Witt
 *
 * @typedef {Object} PublicKeyCredentialRelyingPartyEntity
 * @extends PublicKeyCredentialEntity
 *
 * @property {string} [id]
 */


/**
 * Entity grant API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityGrantRequest
 *
 * @property {EntityGrant} [grant]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordBreachDetection
 * @extends Enableable
 *
 * @property {BreachMatchMode} [matchMode]
 * @property {UUIDString} [notifyUserEmailTemplateId]
 * @property {BreachAction} [onLogin]
 */


/**
 * Models a set of localized Strings that can be stored as JSON.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} LocalizedStrings
 * @extends Object<string, string>
 *
 */


/**
 * Model a user event when a two-factor method has been added.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserTwoFactorMethodRemoveEvent
 * @extends BaseEvent
 *
 * @property {TwoFactorMethod} [method]
 * @property {User} [user]
 */


/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var Algorithm = {
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
  PS256: 'PS256',
  PS384: 'PS384',
  PS512: 'PS512',
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512',
  none: 'none'
};

/**

 *
 * @typedef {Object} BaseConnectorConfiguration
 *
 * @property {Object<string, Object>} [data]
 * @property {boolean} [debug]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {ConnectorType} [type]
 */


/**
 * Search request for entity grants.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityGrantSearchResponse
 *
 * @property {Array<EntityGrant>} [grants]
 * @property {number} [total]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlEntry
 *
 * @property {IPAccessControlEntryAction} [action]
 * @property {string} [endIPAddress]
 * @property {string} [startIPAddress]
 */


/**
 * Search request for webhooks
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebhookSearchRequest
 *
 * @property {WebhookSearchCriteria} [search]
 */


/**
 * @typedef {Object} SAMLv2SingleLogout
 * @extends Enableable
 *
 * @property {UUIDString} [keyId]
 * @property {string} [url]
 * @property {CanonicalizationMethod} [xmlSignatureC14nMethod]
 */


/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 JSON Web Key (JWK)
 * Section 4</a> and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518 JSON Web Algorithms (JWA)</a>.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} JSONWebKey
 *
 * @property {Algorithm} [alg]
 * @property {string} [crv]
 * @property {string} [d]
 * @property {string} [dp]
 * @property {string} [dq]
 * @property {string} [e]
 * @property {string} [kid]
 * @property {KeyType} [kty]
 * @property {string} [n]
 * @property {string} [p]
 * @property {string} [q]
 * @property {string} [qi]
 * @property {string} [use]
 * @property {string} [x]
 * @property {Array<string>} [x5c]
 * @property {string} [x5t]
 * @property {string} [x5t#S256]
 * @property {string} [y]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} AccessToken
 *
 * @property {string} [access_token]
 * @property {number} [expires_in]
 * @property {string} [id_token]
 * @property {string} [refresh_token]
 * @property {UUIDString} [refresh_token_id]
 * @property {string} [scope]
 * @property {TokenType} [token_type]
 * @property {UUIDString} [userId]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlListResponse
 *
 * @property {IPAccessControlList} [ipAccessControlList]
 * @property {Array<IPAccessControlList>} [ipAccessControlLists]
 */


/**
 * Group Member Delete Request
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} MemberDeleteRequest
 *
 * @property {Array<UUIDString>} [memberIds]
 * @property {Object<UUIDString, Array<UUIDString>>} [members]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} FormFieldValidator
 * @extends Enableable
 *
 * @property {string} [expression]
 */


/**
 * Available Integrations
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} Integrations
 *
 * @property {CleanSpeakConfiguration} [cleanspeak]
 * @property {KafkaConfiguration} [kafka]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderOauth2Configuration
 *
 * @property {string} [authorization_endpoint]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {ClientAuthenticationMethod} [clientAuthenticationMethod]
 * @property {string} [emailClaim]
 * @property {string} [emailVerifiedClaim]
 * @property {string} [issuer]
 * @property {string} [scope]
 * @property {string} [token_endpoint]
 * @property {string} [uniqueIdClaim]
 * @property {string} [userinfo_endpoint]
 * @property {string} [usernameClaim]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} DeviceApprovalResponse
 *
 * @property {string} [deviceGrantStatus]
 * @property {DeviceInfo} [deviceInfo]
 * @property {IdentityProviderLink} [identityProviderLink]
 * @property {UUIDString} [tenantId]
 * @property {UUIDString} [userId]
 */


/**
 * Models the User Login Success Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserLoginSuccessEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [authenticationType]
 * @property {UUIDString} [connectorId]
 * @property {UUIDString} [identityProviderId]
 * @property {string} [identityProviderName]
 * @property {string} [ipAddress]
 * @property {User} [user]
 */


/**
 * Lambda API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} LambdaResponse
 *
 * @property {Lambda} [lambda]
 * @property {Array<Lambda>} [lambdas]
 */


/**
 * @author Trevor Smith
 *
 * @readonly
 * @enum
 */
var ChangePasswordReason = {
  Administrative: 'Administrative',
  Breached: 'Breached',
  Expired: 'Expired',
  Validation: 'Validation'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserinfoResponse
 * @extends Object<string, Object>
 *
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWTVendResponse
 *
 * @property {string} [token]
 */


/**
 * Twitter social login provider.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwitterIdentityProvider
 * @extends BaseIdentityProvider<TwitterApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [consumerKey]
 * @property {string} [consumerSecret]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} BaseLoginRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [ipAddress]
 * @property {MetaData} [metaData]
 * @property {boolean} [newDevice]
 * @property {boolean} [noJWT]
 */


/**
 * Used to indicate what type of attestation was included in the authenticator response for a given WebAuthn credential at the time it was created
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var AttestationType = {
  basic: 'basic',
  self: 'self',
  attestationCa: 'attestationCa',
  anonymizationCa: 'anonymizationCa',
  none: 'none'
};

/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserDeleteEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * Registration delete API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} RegistrationDeleteRequest
 * @extends BaseEventRequest
 *
 */


/**
 * Key API request object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} KeyRequest
 *
 * @property {Key} [key]
 */


/**
 * Domain for a public key, key pair or an HMAC secret. This is used by KeyMaster to manage keys for JWTs, SAML, etc.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Key
 *
 * @property {KeyAlgorithm} [algorithm]
 * @property {string} [certificate]
 * @property {CertificateInformation} [certificateInformation]
 * @property {number} [expirationInstant]
 * @property {boolean} [hasPrivateKey]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {string} [issuer]
 * @property {string} [kid]
 * @property {number} [lastUpdateInstant]
 * @property {number} [length]
 * @property {string} [name]
 * @property {string} [privateKey]
 * @property {string} [publicKey]
 * @property {string} [secret]
 * @property {KeyType} [type]
 */


/**
 * COSE Elliptic Curve identifier to determine which elliptic curve to use with a given key
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var CoseEllipticCurve = {
  Reserved: 'Reserved',
  P256: 'P256',
  P384: 'P384',
  P521: 'P521',
  X25519: 'X25519',
  X448: 'X448',
  Ed25519: 'Ed25519',
  Ed448: 'Ed448',
  Secp256k1: 'Secp256k1'
};

/**
 * Models a family grouping of users.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Family
 *
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {Array<FamilyMember>} [members]
 */


/**
 * The phases of a time-based user action.
 *
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var UserActionPhase = {
  start: 'start',
  modify: 'modify',
  cancel: 'cancel',
  end: 'end'
};

/**
 * Models the User Deactivate Event.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserDeactivateEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * Interface for any object that can provide JSON Web key Information.
 *
 * @typedef {Object} JSONWebKeyInfoProvider
 *
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} OAuthResponse
 *
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} VersionResponse
 *
 * @property {string} [version]
 */


/**
 * The summary of the action that is preventing login to be returned on the login response.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginPreventedResponse
 *
 * @property {UUIDString} [actionerUserId]
 * @property {UUIDString} [actionId]
 * @property {number} [expiry]
 * @property {string} [localizedName]
 * @property {string} [localizedOption]
 * @property {string} [localizedReason]
 * @property {string} [name]
 * @property {string} [option]
 * @property {string} [reason]
 * @property {string} [reasonCode]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var FormDataType = {
  bool: 'bool',
  consent: 'consent',
  date: 'date',
  email: 'email',
  number: 'number',
  string: 'string'
};

/**
 * @typedef {Object} LoginRecordConfiguration
 *
 * @property {DeleteConfiguration} [delete]
 */


/**
 * @author Michael Sleevi
 *
 * @typedef {Object} MessageTemplateResponse
 *
 * @property {MessageTemplate} [messageTemplate]
 * @property {Array<MessageTemplate>} [messageTemplates]
 */


/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var ConsentStatus = {
  Active: 'Active',
  Revoked: 'Revoked'
};

/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var UnverifiedBehavior = {
  Allow: 'Allow',
  Gated: 'Gated'
};

/**
 * @author Brett Guy
 *
 * @typedef {Object} MessengerRequest
 *
 * @property {BaseMessengerConfiguration} [messenger]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} MessengerTransport
 *
 */


/**
 * Search request for Applications
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ApplicationSearchRequest
 * @extends ExpandableRequest
 *
 * @property {ApplicationSearchCriteria} [search]
 */


/**
 * Email template response.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EmailTemplateResponse
 *
 * @property {EmailTemplate} [emailTemplate]
 * @property {Array<EmailTemplate>} [emailTemplates]
 */


/**
 * @typedef {Object} ApplicationEmailConfiguration
 *
 * @property {UUIDString} [emailUpdateEmailTemplateId]
 * @property {UUIDString} [emailVerificationEmailTemplateId]
 * @property {UUIDString} [emailVerifiedEmailTemplateId]
 * @property {UUIDString} [forgotPasswordEmailTemplateId]
 * @property {UUIDString} [loginIdInUseOnCreateEmailTemplateId]
 * @property {UUIDString} [loginIdInUseOnUpdateEmailTemplateId]
 * @property {UUIDString} [loginNewDeviceEmailTemplateId]
 * @property {UUIDString} [loginSuspiciousEmailTemplateId]
 * @property {UUIDString} [passwordlessEmailTemplateId]
 * @property {UUIDString} [passwordResetSuccessEmailTemplateId]
 * @property {UUIDString} [passwordUpdateEmailTemplateId]
 * @property {UUIDString} [setPasswordEmailTemplateId]
 * @property {UUIDString} [twoFactorMethodAddEmailTemplateId]
 * @property {UUIDString} [twoFactorMethodRemoveEmailTemplateId]
 */


/**
 * Models the Group Member Update Complete Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberUpdateCompleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Array<GroupMember>} [members]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} AuditLogRequest
 * @extends BaseEventRequest
 *
 * @property {AuditLog} [auditLog]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} KafkaMessengerConfiguration
 * @extends BaseMessengerConfiguration
 *
 * @property {string} [defaultTopic]
 * @property {Object<string, string>} [producer]
 */


/**
 * Models action reasons.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionReason
 *
 * @property {string} [code]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {LocalizedStrings} [localizedTexts]
 * @property {string} [text]
 */


/**
 * Status for content like usernames, profile attributes, etc.
 *
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var ContentStatus = {
  ACTIVE: 'ACTIVE',
  PENDING: 'PENDING',
  REJECTED: 'REJECTED'
};

/**
 * @author Spencer Witt
 *
 * @typedef {Object} TenantWebAuthnWorkflowConfiguration
 * @extends Enableable
 *
 * @property {AuthenticatorAttachmentPreference} [authenticatorAttachmentPreference]
 * @property {UserVerificationRequirement} [userVerificationRequirement]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} TwoFactorDisableRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [code]
 * @property {string} [methodId]
 */


/**
 * Search criteria for Applications
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ApplicationSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 * @property {ObjectState} [state]
 * @property {UUIDString} [tenantId]
 */


/**
 * Configuration for the behavior of failed login attempts. This helps us protect against brute force password attacks.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} FailedAuthenticationConfiguration
 *
 * @property {FailedAuthenticationActionCancelPolicy} [actionCancelPolicy]
 * @property {number} [actionDuration]
 * @property {ExpiryUnit} [actionDurationUnit]
 * @property {boolean} [emailUser]
 * @property {number} [resetCountInSeconds]
 * @property {number} [tooManyAttempts]
 * @property {UUIDString} [userActionId]
 */


/**
 * This class contains the managed fields that are also put into the database during FusionAuth setup.
 * <p>
 * Internal Note: These fields are also declared in SQL in order to bootstrap the system. These need to stay in sync.
 * Any changes to these fields needs to also be reflected in mysql.sql and postgresql.sql
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ManagedFields
 *
 */


/**
 * API response for starting a WebAuthn authentication ceremony
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnStartResponse
 *
 * @property {PublicKeyCredentialRequestOptions} [options]
 */


/**
 * Models the User Login event that is suspicious.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserLoginSuspiciousEvent
 * @extends UserLoginSuccessEvent
 *
 * @property {Object<AuthenticationThreats>} [threatsDetected]
 */


/**
 * @typedef {Object} SAMLv2AssertionEncryptionConfiguration
 * @extends Enableable
 *
 * @property {string} [digestAlgorithm]
 * @property {string} [encryptionAlgorithm]
 * @property {string} [keyLocation]
 * @property {string} [keyTransportAlgorithm]
 * @property {UUIDString} [keyTransportEncryptionKeyId]
 * @property {string} [maskGenerationFunction]
 */


/**
 * @typedef {Object} LambdaConfiguration
 *
 * @property {UUIDString} [accessTokenPopulateId]
 * @property {UUIDString} [idTokenPopulateId]
 * @property {UUIDString} [samlv2PopulateId]
 * @property {UUIDString} [selfServiceRegistrationValidationId]
 * @property {UUIDString} [userinfoPopulateId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderResponse
 *
 * @property {BaseIdentityProvider<Object>} [identityProvider]
 * @property {Array<BaseIdentityProvider<Object>>} [identityProviders]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SecureIdentity
 *
 * @property {number} [breachedPasswordLastCheckedInstant]
 * @property {BreachedPasswordStatus} [breachedPasswordStatus]
 * @property {UUIDString} [connectorId]
 * @property {string} [encryptionScheme]
 * @property {number} [factor]
 * @property {UUIDString} [id]
 * @property {number} [lastLoginInstant]
 * @property {string} [password]
 * @property {ChangePasswordReason} [passwordChangeReason]
 * @property {boolean} [passwordChangeRequired]
 * @property {number} [passwordLastUpdateInstant]
 * @property {string} [salt]
 * @property {string} [uniqueUsername]
 * @property {string} [username]
 * @property {ContentStatus} [usernameStatus]
 * @property {boolean} [verified]
 * @property {number} [verifiedInstant]
 */


/**
 * Models the User Login event for a new device (un-recognized)
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserLoginNewDeviceEvent
 * @extends UserLoginSuccessEvent
 *
 */


/**
 * External JWT-only identity provider.
 *
 * @author Daniel DeGroff and Brian Pontarelli
 *
 * @typedef {Object} ExternalJWTIdentityProvider
 * @extends BaseIdentityProvider<ExternalJWTApplicationConfiguration>
 *
 * @property {Object<string, string>} [claimMap]
 * @property {UUIDString} [defaultKeyId]
 * @property {Object<string>} [domains]
 * @property {string} [headerKeyParameter]
 * @property {IdentityProviderOauth2Configuration} [oauth2]
 * @property {string} [uniqueIdentityClaim]
 */


/**
 * An email address.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EmailAddress
 *
 * @property {string} [address]
 * @property {string} [display]
 */


/**
 * Base class for requests that can contain event information. This event information is used when sending Webhooks or emails
 * during the transaction. The caller is responsible for ensuring that the event information is correct.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} BaseEventRequest
 *
 * @property {EventInfo} [eventInfo]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ApplicationWebAuthnWorkflowConfiguration
 * @extends Enableable
 *
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SecureGeneratorConfiguration
 *
 * @property {number} [length]
 * @property {SecureGeneratorType} [type]
 */


/**
 * @author Johnathon Wood
 *
 * @readonly
 * @enum
 */
var Oauth2AuthorizedURLValidationPolicy = {
  AllowWildcards: 'AllowWildcards',
  ExactMatch: 'ExactMatch'
};

/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} AuditLogSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {number} [end]
 * @property {string} [message]
 * @property {string} [newValue]
 * @property {string} [oldValue]
 * @property {string} [reason]
 * @property {number} [start]
 * @property {string} [user]
 */


/**
 * Search criteria for user comments.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} UserCommentSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [comment]
 * @property {UUIDString} [commenterId]
 * @property {UUIDString} [tenantId]
 * @property {UUIDString} [userId]
 */


/**
 * A policy for deleting Users based upon some external criteria.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} TimeBasedDeletePolicy
 * @extends Enableable
 *
 * @property {number} [enabledInstant]
 * @property {number} [numberOfDaysToRetain]
 */


/**
 * Search criteria for Email templates
 *
 * @author Mark Manes
 *
 * @typedef {Object} EmailTemplateSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 */


/**
 * Search request for Identity Providers
 *
 * @author Spencer Witt
 *
 * @typedef {Object} IdentityProviderSearchRequest
 *
 * @property {IdentityProviderSearchCriteria} [search]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ReactorStatus
 *
 * @property {ReactorFeatureStatus} [advancedIdentityProviders]
 * @property {ReactorFeatureStatus} [advancedLambdas]
 * @property {ReactorFeatureStatus} [advancedMultiFactorAuthentication]
 * @property {ReactorFeatureStatus} [advancedOAuthScopes]
 * @property {ReactorFeatureStatus} [advancedOAuthScopesCustomScopes]
 * @property {ReactorFeatureStatus} [advancedOAuthScopesThirdPartyApplications]
 * @property {ReactorFeatureStatus} [advancedRegistration]
 * @property {ReactorFeatureStatus} [applicationMultiFactorAuthentication]
 * @property {ReactorFeatureStatus} [applicationThemes]
 * @property {ReactorFeatureStatus} [breachedPasswordDetection]
 * @property {ReactorFeatureStatus} [connectors]
 * @property {ReactorFeatureStatus} [entityManagement]
 * @property {string} [expiration]
 * @property {Object<string, string>} [licenseAttributes]
 * @property {boolean} [licensed]
 * @property {ReactorFeatureStatus} [scimServer]
 * @property {ReactorFeatureStatus} [threatDetection]
 * @property {ReactorFeatureStatus} [webAuthn]
 * @property {ReactorFeatureStatus} [webAuthnPlatformAuthenticators]
 * @property {ReactorFeatureStatus} [webAuthnRoamingAuthenticators]
 */


/**
 * Search request for entity types.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityTypeSearchRequest
 *
 * @property {EntityTypeSearchCriteria} [search]
 */


/**
 * @typedef {Object} MultiFactorSMSMethod
 * @extends Enableable
 *
 * @property {UUIDString} [messengerId]
 * @property {UUIDString} [templateId]
 */


/**
 * Login Ping API request object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginPingRequest
 * @extends BaseLoginRequest
 *
 * @property {UUIDString} [userId]
 */


/**
 * @readonly
 * @enum
 */
var RegistrationType = {
  basic: 'basic',
  advanced: 'advanced'
};

/**
 * @readonly
 * @enum
 */
var EmailSecurityType = {
  NONE: 'NONE',
  SSL: 'SSL',
  TLS: 'TLS'
};

/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var LambdaEngineType = {
  GraalJS: 'GraalJS',
  Nashorn: 'Nashorn'
};

/**
 * @author Michael Sleevi
 *
 * @typedef {Object} SMSMessageTemplate
 * @extends MessageTemplate
 *
 * @property {string} [defaultTemplate]
 * @property {LocalizedStrings} [localizedTemplates]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var FormControl = {
  checkbox: 'checkbox',
  number: 'number',
  password: 'password',
  radio: 'radio',
  select: 'select',
  textarea: 'textarea',
  text: 'text'
};

/**
 * @author Trevor Smith
 *
 * @typedef {Object} Theme
 *
 * @property {Object<string, Object>} [data]
 * @property {string} [defaultMessages]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {LocalizedStrings} [localizedMessages]
 * @property {string} [name]
 * @property {string} [stylesheet]
 * @property {Templates} [templates]
 */


/**
 * Models the JWT public key Refresh Token Revoke Event. This event might be for a single
 * token, a user or an entire application.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} JWTPublicKeyUpdateEvent
 * @extends BaseEvent
 *
 * @property {Object<UUIDString>} [applicationIds]
 */


/**
 * Models the User Password Reset Send Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserPasswordResetSendEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * Models the Group Member Remove Complete Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberRemoveCompleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Array<GroupMember>} [members]
 */


/**
 * Search request for Tenants
 *
 * @author Mark Manes
 *
 * @typedef {Object} TenantSearchRequest
 *
 * @property {TenantSearchCriteria} [search]
 */


/**
 * The Application Scope API response.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ApplicationOAuthScopeResponse
 *
 * @property {ApplicationOAuthScope} [scope]
 */


/**
 * @typedef {Object} MultiFactorSMSTemplate
 *
 * @property {UUIDString} [templateId]
 */


/**
 * User API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [currentPassword]
 * @property {boolean} [disableDomainBlock]
 * @property {boolean} [sendSetPasswordEmail]
 * @property {boolean} [skipVerification]
 * @property {User} [user]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} PendingResponse
 *
 * @property {Array<User>} [users]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorStartResponse
 *
 * @property {string} [code]
 * @property {Array<TwoFactorMethod>} [methods]
 * @property {string} [twoFactorId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} VerifyEmailResponse
 *
 * @property {string} [oneTimeCode]
 * @property {string} [verificationId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} OpenIdConnectApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonImageURL]
 * @property {string} [buttonText]
 * @property {IdentityProviderOauth2Configuration} [oauth2]
 */


/**
 * Defines valid credential types. This is an extension point in the WebAuthn spec. The only defined value at this time is "public-key"
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var PublicKeyCredentialType = {
  publicKey: 'public-key'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordlessStartRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [loginId]
 * @property {Object<string, Object>} [state]
 */


/**
 * Response for the registration report.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} RegistrationReportResponse
 *
 * @property {Array<Count>} [hourlyCounts]
 * @property {number} [total]
 */


/**
 * Authentication key request object.
 *
 * @author Sanjay
 *
 * @typedef {Object} APIKeyRequest
 *
 * @property {APIKey} [apiKey]
 * @property {UUIDString} [sourceKeyId]
 */


/**
 * User Action Reason API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionReasonRequest
 *
 * @property {UserActionReason} [userActionReason]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} OAuthError
 *
 * @property {string} [change_password_id]
 * @property {OAuthErrorType} [error]
 * @property {string} [error_description]
 * @property {OAuthErrorReason} [error_reason]
 * @property {string} [error_uri]
 * @property {string} [two_factor_id]
 * @property {Array<TwoFactorMethod>} [two_factor_methods]
 */


/**
 * @readonly
 * @enum
 */
var OAuthErrorReason = {
  auth_code_not_found: 'auth_code_not_found',
  access_token_malformed: 'access_token_malformed',
  access_token_expired: 'access_token_expired',
  access_token_unavailable_for_processing: 'access_token_unavailable_for_processing',
  access_token_failed_processing: 'access_token_failed_processing',
  access_token_invalid: 'access_token_invalid',
  access_token_required: 'access_token_required',
  refresh_token_not_found: 'refresh_token_not_found',
  refresh_token_type_not_supported: 'refresh_token_type_not_supported',
  invalid_client_id: 'invalid_client_id',
  invalid_user_credentials: 'invalid_user_credentials',
  invalid_grant_type: 'invalid_grant_type',
  invalid_origin: 'invalid_origin',
  invalid_origin_opaque: 'invalid_origin_opaque',
  invalid_pkce_code_verifier: 'invalid_pkce_code_verifier',
  invalid_pkce_code_challenge: 'invalid_pkce_code_challenge',
  invalid_pkce_code_challenge_method: 'invalid_pkce_code_challenge_method',
  invalid_redirect_uri: 'invalid_redirect_uri',
  invalid_response_mode: 'invalid_response_mode',
  invalid_response_type: 'invalid_response_type',
  invalid_id_token_hint: 'invalid_id_token_hint',
  invalid_post_logout_redirect_uri: 'invalid_post_logout_redirect_uri',
  invalid_device_code: 'invalid_device_code',
  invalid_user_code: 'invalid_user_code',
  invalid_additional_client_id: 'invalid_additional_client_id',
  invalid_target_entity_scope: 'invalid_target_entity_scope',
  invalid_entity_permission_scope: 'invalid_entity_permission_scope',
  invalid_user_id: 'invalid_user_id',
  grant_type_disabled: 'grant_type_disabled',
  missing_client_id: 'missing_client_id',
  missing_client_secret: 'missing_client_secret',
  missing_code: 'missing_code',
  missing_code_challenge: 'missing_code_challenge',
  missing_code_verifier: 'missing_code_verifier',
  missing_device_code: 'missing_device_code',
  missing_grant_type: 'missing_grant_type',
  missing_redirect_uri: 'missing_redirect_uri',
  missing_refresh_token: 'missing_refresh_token',
  missing_response_type: 'missing_response_type',
  missing_token: 'missing_token',
  missing_user_code: 'missing_user_code',
  missing_user_id: 'missing_user_id',
  missing_verification_uri: 'missing_verification_uri',
  login_prevented: 'login_prevented',
  not_licensed: 'not_licensed',
  user_code_expired: 'user_code_expired',
  user_expired: 'user_expired',
  user_locked: 'user_locked',
  user_not_found: 'user_not_found',
  client_authentication_missing: 'client_authentication_missing',
  invalid_client_authentication_scheme: 'invalid_client_authentication_scheme',
  invalid_client_authentication: 'invalid_client_authentication',
  client_id_mismatch: 'client_id_mismatch',
  change_password_administrative: 'change_password_administrative',
  change_password_breached: 'change_password_breached',
  change_password_expired: 'change_password_expired',
  change_password_validation: 'change_password_validation',
  unknown: 'unknown',
  missing_required_scope: 'missing_required_scope',
  unknown_scope: 'unknown_scope',
  consent_canceled: 'consent_canceled'
};

/**
 * An Event "event" to indicate an event log was created.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} EventLogCreateEvent
 * @extends BaseEvent
 *
 * @property {EventLog} [eventLog]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var RefreshTokenExpirationPolicy = {
  Fixed: 'Fixed',
  SlidingWindow: 'SlidingWindow',
  SlidingWindowWithMaximumLifetime: 'SlidingWindowWithMaximumLifetime'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantLoginConfiguration
 *
 * @property {boolean} [requireAuthentication]
 */


/**
 * Models the User Login Failed Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserLoginFailedEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [authenticationType]
 * @property {string} [ipAddress]
 * @property {User} [user]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} AppleIdentityProvider
 * @extends BaseIdentityProvider<AppleApplicationConfiguration>
 *
 * @property {string} [bundleId]
 * @property {string} [buttonText]
 * @property {UUIDString} [keyId]
 * @property {string} [scope]
 * @property {string} [servicesId]
 * @property {string} [teamId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SendResponse
 *
 * @property {Object<string, EmailTemplateErrors>} [anonymousResults]
 * @property {Object<UUIDString, EmailTemplateErrors>} [results]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var FormType = {
  registration: 'registration',
  adminRegistration: 'adminRegistration',
  adminUser: 'adminUser',
  selfServiceUser: 'selfServiceUser'
};

/**
 * @author Brett Guy
 *
 * @typedef {Object} MessengerResponse
 *
 * @property {BaseMessengerConfiguration} [messenger]
 * @property {Array<BaseMessengerConfiguration>} [messengers]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var RateLimitedRequestType = {
  FailedLogin: 'FailedLogin',
  ForgotPassword: 'ForgotPassword',
  SendEmailVerification: 'SendEmailVerification',
  SendPasswordless: 'SendPasswordless',
  SendRegistrationVerification: 'SendRegistrationVerification',
  SendTwoFactor: 'SendTwoFactor'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ReactorMetrics
 *
 * @property {Object<UUIDString, BreachedPasswordTenantMetric>} [breachedPasswordMetrics]
 */


/**
 * Identifies the WebAuthn workflow. This will affect the parameters used for credential creation
 * and request based on the Tenant configuration.
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var WebAuthnWorkflow = {
  bootstrap: 'bootstrap',
  general: 'general',
  reauthentication: 'reauthentication'
};

/**
 * The types of lambdas that indicate how they are invoked by FusionAuth.
 *
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var LambdaType = {
  JWTPopulate: 'JWTPopulate',
  OpenIDReconcile: 'OpenIDReconcile',
  SAMLv2Reconcile: 'SAMLv2Reconcile',
  SAMLv2Populate: 'SAMLv2Populate',
  AppleReconcile: 'AppleReconcile',
  ExternalJWTReconcile: 'ExternalJWTReconcile',
  FacebookReconcile: 'FacebookReconcile',
  GoogleReconcile: 'GoogleReconcile',
  HYPRReconcile: 'HYPRReconcile',
  TwitterReconcile: 'TwitterReconcile',
  LDAPConnectorReconcile: 'LDAPConnectorReconcile',
  LinkedInReconcile: 'LinkedInReconcile',
  EpicGamesReconcile: 'EpicGamesReconcile',
  NintendoReconcile: 'NintendoReconcile',
  SonyPSNReconcile: 'SonyPSNReconcile',
  SteamReconcile: 'SteamReconcile',
  TwitchReconcile: 'TwitchReconcile',
  XboxReconcile: 'XboxReconcile',
  ClientCredentialsJWTPopulate: 'ClientCredentialsJWTPopulate',
  SCIMServerGroupRequestConverter: 'SCIMServerGroupRequestConverter',
  SCIMServerGroupResponseConverter: 'SCIMServerGroupResponseConverter',
  SCIMServerUserRequestConverter: 'SCIMServerUserRequestConverter',
  SCIMServerUserResponseConverter: 'SCIMServerUserResponseConverter',
  SelfServiceRegistrationValidation: 'SelfServiceRegistrationValidation',
  UserInfoPopulate: 'UserInfoPopulate'
};

/**
 * CleanSpeak configuration at the system and application level.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} CleanSpeakConfiguration
 * @extends Enableable
 *
 * @property {string} [apiKey]
 * @property {Array<UUIDString>} [applicationIds]
 * @property {string} [url]
 * @property {UsernameModeration} [usernameModeration]
 */


/**
 * @readonly
 * @enum
 */
var LDAPSecurityMethod = {
  None: 'None',
  LDAPS: 'LDAPS',
  StartTLS: 'StartTLS'
};

/**
 * Entity API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityRequest
 *
 * @property {Entity} [entity]
 */


/**
 * Something that can be enabled and thus also disabled.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} Enableable
 *
 * @property {boolean} [enabled]
 */


/**
 * @typedef {Object} EmailTemplateErrors
 *
 * @property {Object<string, string>} [parseErrors]
 * @property {Object<string, string>} [renderErrors]
 */


/**
 * Base-class for all FusionAuth events.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} BaseEvent
 *
 * @property {number} [createInstant]
 * @property {UUIDString} [id]
 * @property {EventInfo} [info]
 * @property {UUIDString} [tenantId]
 * @property {EventType} [type]
 */


/**
 * Controls the policy for requesting user permission to grant access to requested scopes during an OAuth workflow
 * for a third-party application.
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var OAuthScopeConsentMode = {
  AlwaysPrompt: 'AlwaysPrompt',
  RememberDecision: 'RememberDecision',
  NeverPrompt: 'NeverPrompt'
};

/**
 * Models the User Identity Provider Link Event.
 *
 * @author Rob Davis
 *
 * @typedef {Object} UserIdentityProviderLinkEvent
 * @extends BaseEvent
 *
 * @property {IdentityProviderLink} [identityProviderLink]
 * @property {User} [user]
 */


/**
 * Location information. Useful for IP addresses and other displayable data objects.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Location
 *
 * @property {string} [city]
 * @property {string} [country]
 * @property {string} [displayString]
 * @property {number} [latitude]
 * @property {number} [longitude]
 * @property {string} [region]
 * @property {string} [zipcode]
 */


/**
 * A grant for an entity to a user or another entity.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityGrant
 *
 * @property {Object<string, Object>} [data]
 * @property {Entity} [entity]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {Object<string>} [permissions]
 * @property {UUIDString} [recipientEntityId]
 * @property {UUIDString} [userId]
 */


/**
 * @typedef {Object} TenantOAuth2Configuration
 *
 * @property {UUIDString} [clientCredentialsAccessTokenPopulateLambdaId]
 */


/**
 * Request for managing FusionAuth Reactor and licenses.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ReactorRequest
 *
 * @property {string} [license]
 * @property {string} [licenseId]
 */


/**
 * Models the User Password Reset Success Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserPasswordResetSuccessEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * @typedef {Object} AuthenticationTokenConfiguration
 * @extends Enableable
 *
 */


/**
 * Controls the policy for whether OAuth workflows will more strictly adhere to the OAuth and OIDC specification
 * or run in backwards compatibility mode.
 *
 * @author David Charles
 *
 * @readonly
 * @enum
 */
var OAuthScopeHandlingPolicy = {
  Compatibility: 'Compatibility',
  Strict: 'Strict'
};

/**
 * Models the User Created Registration Event.
 * <p>
 * This is different than the user.registration.create event in that it will be sent after the user has been created. This event cannot be made
 * transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserRegistrationCreateCompleteEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * The response from the total report. This report stores the total numbers for each application.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} TotalsReportResponse
 *
 * @property {Object<UUIDString, Totals>} [applicationTotals]
 * @property {number} [globalRegistrations]
 * @property {number} [totalGlobalRegistrations]
 */


/**
 * A JavaScript lambda function that is executed during certain events inside FusionAuth.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Lambda
 *
 * @property {string} [body]
 * @property {boolean} [debug]
 * @property {LambdaEngineType} [engineType]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {LambdaType} [type]
 */


/**
 * @author Lyle Schemmerling
 *
 * @typedef {Object} SAMLv2DestinationAssertionConfiguration
 *
 * @property {Array<string>} [alternates]
 * @property {SAMLv2DestinationAssertionPolicy} [policy]
 */


/**
 * A policy to configure if and when the user-action is canceled prior to the expiration of the action.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} FailedAuthenticationActionCancelPolicy
 *
 * @property {boolean} [onPasswordReset]
 */


/**
 * Steam gaming login provider.
 *
 * @author Brett Pontarelli
 *
 * @typedef {Object} SteamIdentityProvider
 * @extends BaseIdentityProvider<SteamApplicationConfiguration>
 *
 * @property {SteamAPIMode} [apiMode]
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [scope]
 * @property {string} [webAPIKey]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} BreachedPasswordTenantMetric
 *
 * @property {number} [actionRequired]
 * @property {number} [matchedCommonPasswordCount]
 * @property {number} [matchedExactCount]
 * @property {number} [matchedPasswordCount]
 * @property {number} [matchedSubAddressCount]
 * @property {number} [passwordsCheckedCount]
 */


/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} DailyActiveUserReportResponse
 *
 * @property {Array<Count>} [dailyActiveUsers]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwitterApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [consumerKey]
 * @property {string} [consumerSecret]
 */


/**
 * @author Trevor Smith
 *
 * @typedef {Object} ConnectorPolicy
 *
 * @property {UUIDString} [connectorId]
 * @property {Object<string, Object>} [data]
 * @property {Object<string>} [domains]
 * @property {boolean} [migrate]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var HTTPMethod = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  DELETE: 'DELETE',
  HEAD: 'HEAD',
  OPTIONS: 'OPTIONS',
  PATCH: 'PATCH'
};

/**
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlListRequest
 *
 * @property {IPAccessControlList} [ipAccessControlList]
 */


/**
 * Search request for entities
 *
 * @author Brett Guy
 *
 * @typedef {Object} EntitySearchResponse
 *
 * @property {Array<Entity>} [entities]
 * @property {string} [nextResults]
 * @property {number} [total]
 */


/**
 * Search API request.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SearchRequest
 * @extends ExpandableRequest
 *
 * @property {UserSearchCriteria} [search]
 */


/**
 * Response for the user login report.
 *
 * @author Seth Musselman
 *
 * @typedef {Object} RecentLoginResponse
 *
 * @property {Array<DisplayableRawLogin>} [logins]
 */


/**
 * Supply information on credential type and algorithm to the <i>authenticator</i>.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} PublicKeyCredentialParameters
 *
 * @property {CoseAlgorithmIdentifier} [alg]
 * @property {PublicKeyCredentialType} [type]
 */


/**
 * Search criteria for Consents
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ConsentSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 */


/**
 * Password Encryption Scheme Configuration
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordEncryptionConfiguration
 *
 * @property {string} [encryptionScheme]
 * @property {number} [encryptionSchemeFactor]
 * @property {boolean} [modifyEncryptionSchemeOnLogin]
 */


/**
 * @typedef {Object} SAMLv2Logout
 *
 * @property {SAMLLogoutBehavior} [behavior]
 * @property {UUIDString} [defaultVerificationKeyId]
 * @property {UUIDString} [keyId]
 * @property {boolean} [requireSignedRequests]
 * @property {SAMLv2SingleLogout} [singleLogout]
 * @property {CanonicalizationMethod} [xmlSignatureC14nMethod]
 */


/**
 * Response for the login report.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} LoginReportResponse
 *
 * @property {Array<Count>} [hourlyCounts]
 * @property {number} [total]
 */


/**
 * A User's WebAuthnCredential. Contains all data required to complete WebAuthn authentication ceremonies.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnCredential
 *
 * @property {CoseAlgorithmIdentifier} [algorithm]
 * @property {AttestationType} [attestationType]
 * @property {boolean} [authenticatorSupportsUserVerification]
 * @property {string} [credentialId]
 * @property {Object<string, Object>} [data]
 * @property {boolean} [discoverable]
 * @property {string} [displayName]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUseInstant]
 * @property {string} [name]
 * @property {string} [publicKey]
 * @property {string} [relyingPartyId]
 * @property {number} [signCount]
 * @property {UUIDString} [tenantId]
 * @property {Array<string>} [transports]
 * @property {string} [userAgent]
 * @property {UUIDString} [userId]
 */


/**
 * Search criteria for Identity Providers.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} IdentityProviderSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [name]
 * @property {IdentityProviderType} [type]
 */


/**
 * Models the JWT Refresh Event. This event will be fired when a JWT is "refreshed" (generated) using a Refresh Token.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWTRefreshEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [original]
 * @property {string} [refreshToken]
 * @property {string} [token]
 * @property {UUIDString} [userId]
 */


/**
 * @typedef {Object} UsernameModeration
 * @extends Enableable
 *
 * @property {UUIDString} [applicationId]
 */


/**
 * @readonly
 * @enum
 */
var OAuthErrorType = {
  invalid_request: 'invalid_request',
  invalid_client: 'invalid_client',
  invalid_grant: 'invalid_grant',
  invalid_token: 'invalid_token',
  unauthorized_client: 'unauthorized_client',
  invalid_scope: 'invalid_scope',
  server_error: 'server_error',
  unsupported_grant_type: 'unsupported_grant_type',
  unsupported_response_type: 'unsupported_response_type',
  access_denied: 'access_denied',
  change_password_required: 'change_password_required',
  not_licensed: 'not_licensed',
  two_factor_required: 'two_factor_required',
  authorization_pending: 'authorization_pending',
  expired_token: 'expired_token',
  unsupported_token_type: 'unsupported_token_type'
};

/**
 * Models the Group Member Remove Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberRemoveEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Array<GroupMember>} [members]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} TwoFactorRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [authenticatorId]
 * @property {string} [code]
 * @property {string} [email]
 * @property {string} [method]
 * @property {string} [mobilePhone]
 * @property {string} [secret]
 * @property {string} [secretBase32Encoded]
 * @property {string} [twoFactorId]
 */


/**
 * Policy for handling unknown OAuth scopes in the request
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var UnknownScopePolicy = {
  Allow: 'Allow',
  Remove: 'Remove',
  Reject: 'Reject'
};

/**
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlListSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 */


/**
 * User Action API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionResponse
 *
 * @property {UserAction} [userAction]
 * @property {Array<UserAction>} [userActions]
 */


/**
 * Models the Group Created Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupCreateCompleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 */


/**
 * Authorization Grant types as defined by the <a href="https://tools.ietf.org/html/rfc6749">The OAuth 2.0 Authorization
 * Framework - RFC 6749</a>.
 * <p>
 * Specific names as defined by <a href="https://tools.ietf.org/html/rfc7591#section-4.1">
 * OAuth 2.0 Dynamic Client Registration Protocol - RFC 7591 Section 4.1</a>
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var GrantType = {
  authorization_code: 'authorization_code',
  implicit: 'implicit',
  password: 'password',
  client_credentials: 'client_credentials',
  refresh_token: 'refresh_token',
  unknown: 'unknown',
  device_code: 'urn:ietf:params:oauth:grant-type:device_code'
};

/**
 * User API bulk response object.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} UserDeleteResponse
 *
 * @property {boolean} [dryRun]
 * @property {boolean} [hardDelete]
 * @property {number} [total]
 * @property {Array<UUIDString>} [userIds]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlList
 *
 * @property {Object<string, Object>} [data]
 * @property {Array<IPAccessControlEntry>} [entries]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 */


/**
 * @typedef {Object} MultiFactorEmailMethod
 * @extends Enableable
 *
 * @property {UUIDString} [templateId]
 */


/**
 * A historical state of a user log event. Since events can be modified, this stores the historical state.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} LogHistory
 *
 * @property {Array<HistoryItem>} [historyItems]
 */


/**
 * Container for the event information. This is the JSON that is sent from FusionAuth to webhooks.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventRequest
 *
 * @property {BaseEvent} [event]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderLimitUserLinkingPolicy
 * @extends Enableable
 *
 * @property {number} [maximumLinks]
 */


/**
 * @author Brett Pontarelli
 *
 * @readonly
 * @enum
 */
var CaptchaMethod = {
  GoogleRecaptchaV2: 'GoogleRecaptchaV2',
  GoogleRecaptchaV3: 'GoogleRecaptchaV3',
  HCaptcha: 'HCaptcha',
  HCaptchaEnterprise: 'HCaptchaEnterprise'
};

/**
 * @author Lyle Schemmerling
 *
 * @readonly
 * @enum
 */
var SAMLv2DestinationAssertionPolicy = {
  Enabled: 'Enabled',
  Disabled: 'Disabled',
  AllowAlternates: 'AllowAlternates'
};

/**
 * Search request for IP ACLs .
 *
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlListSearchRequest
 *
 * @property {IPAccessControlListSearchCriteria} [search]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var ObjectState = {
  Active: 'Active',
  Inactive: 'Inactive',
  PendingDelete: 'PendingDelete'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SystemLogsExportRequest
 * @extends BaseExportRequest
 *
 * @property {boolean} [includeArchived]
 * @property {number} [lastNBytes]
 */


/**
 * Request for the Logout API that can be used as an alternative to URL parameters.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} LogoutRequest
 * @extends BaseEventRequest
 *
 * @property {boolean} [global]
 * @property {string} [refreshToken]
 */


/**
 * Event log response.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventLogSearchResponse
 *
 * @property {Array<EventLog>} [eventLogs]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} EmailHeader
 *
 * @property {string} [name]
 * @property {string} [value]
 */


/**
 * Helper interface that indicates an identity provider can be federated to using the HTTP POST method.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SupportsPostBindings
 *
 */


/**
 * An expandable API response.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ExpandableResponse
 *
 * @property {Array<string>} [expandable]
 */


/**
 * @typedef {Object} EventLogConfiguration
 *
 * @property {number} [numberToRetain]
 */


/**
 * Type for webhook headers.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} HTTPHeaders
 * @extends Object<string, string>
 *
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} Form
 *
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {Array<FormStep>} [steps]
 * @property {FormType} [type]
 */


/**
 * Search response for Groups
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupSearchResponse
 *
 * @property {Array<Group>} [groups]
 * @property {number} [total]
 */


/**
 * API request for User consent types.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ConsentRequest
 *
 * @property {Consent} [consent]
 */


/**
 * Application search response
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ApplicationSearchResponse
 * @extends ExpandableResponse
 *
 * @property {Array<Application>} [applications]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordlessStartResponse
 *
 * @property {string} [code]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IssueResponse
 *
 * @property {string} [refreshToken]
 * @property {string} [token]
 */


/**
 * @typedef {Object} MultiFactorAuthenticatorMethod
 * @extends Enableable
 *
 * @property {TOTPAlgorithm} [algorithm]
 * @property {number} [codeLength]
 * @property {number} [timeStep]
 */


/**
 * Request for the Tenant API to delete a tenant rather than using the URL parameters.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} TenantDeleteRequest
 * @extends BaseEventRequest
 *
 * @property {boolean} [async]
 */


/**
 * @author Brett Pontarelli
 *
 * @readonly
 * @enum
 */
var AuthenticationThreats = {
  ImpossibleTravel: 'ImpossibleTravel'
};

/**
 * A marker interface indicating this event cannot be made transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} NonTransactionalEvent
 *
 */


/**
 * @author Michael Sleevi
 *
 * @typedef {Object} PreviewMessageTemplateResponse
 *
 * @property {Errors} [errors]
 * @property {SMSMessage} [message]
 */


/**
 * Theme API response object.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} ThemeResponse
 *
 * @property {Theme} [theme]
 * @property {Array<Theme>} [themes]
 */


/**
 * Interface for all identity providers that are passwordless and do not accept a password.
 *
 * @typedef {Object} PasswordlessIdentityProvider
 *
 */


/**
 * This class is an abstraction of a simple email message.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Email
 *
 * @property {Array<Attachment>} [attachments]
 * @property {Array<EmailAddress>} [bcc]
 * @property {Array<EmailAddress>} [cc]
 * @property {EmailAddress} [from]
 * @property {string} [html]
 * @property {EmailAddress} [replyTo]
 * @property {string} [subject]
 * @property {string} [text]
 * @property {Array<EmailAddress>} [to]
 */


/**
 * The global view of a User. This object contains all global information about the user including birthdate, registration information
 * preferred languages, global attributes, etc.
 *
 * @author Seth Musselman
 *
 * @typedef {Object} User
 * @extends SecureIdentity
 *
 * @property {boolean} [active]
 * @property {string} [birthDate]
 * @property {UUIDString} [cleanSpeakId]
 * @property {Object<string, Object>} [data]
 * @property {string} [email]
 * @property {number} [expiry]
 * @property {string} [firstName]
 * @property {string} [fullName]
 * @property {string} [imageUrl]
 * @property {number} [insertInstant]
 * @property {string} [lastName]
 * @property {number} [lastUpdateInstant]
 * @property {Array<GroupMember>} [memberships]
 * @property {string} [middleName]
 * @property {string} [mobilePhone]
 * @property {string} [parentEmail]
 * @property {Array<string>} [preferredLanguages]
 * @property {Array<UserRegistration>} [registrations]
 * @property {UUIDString} [tenantId]
 * @property {string} [timezone]
 * @property {UserTwoFactorConfiguration} [twoFactor]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} OAuthConfigurationResponse
 *
 * @property {number} [httpSessionMaxInactiveInterval]
 * @property {string} [logoutURL]
 * @property {OAuth2Configuration} [oauthConfiguration]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LinkedInIdentityProvider
 * @extends BaseIdentityProvider<LinkedInApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * JWT Configuration. A JWT Configuration for an Application may not be active if it is using the global configuration, the configuration
 * may be <code>enabled = false</code>.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWTConfiguration
 * @extends Enableable
 *
 * @property {UUIDString} [accessTokenKeyId]
 * @property {UUIDString} [idTokenKeyId]
 * @property {RefreshTokenExpirationPolicy} [refreshTokenExpirationPolicy]
 * @property {RefreshTokenRevocationPolicy} [refreshTokenRevocationPolicy]
 * @property {RefreshTokenSlidingWindowConfiguration} [refreshTokenSlidingWindowConfiguration]
 * @property {number} [refreshTokenTimeToLiveInMinutes]
 * @property {RefreshTokenUsagePolicy} [refreshTokenUsagePolicy]
 * @property {number} [timeToLiveInSeconds]
 */


/**
 * Models the Group Member Update Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberUpdateEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Array<GroupMember>} [members]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} BaseExportRequest
 *
 * @property {string} [dateTimeSecondsFormat]
 * @property {string} [zoneId]
 */


/**
 * Models the Group Delete Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupDeleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 */


/**

 *
 * @typedef {Object} BaseMessengerConfiguration
 *
 * @property {Object<string, Object>} [data]
 * @property {boolean} [debug]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {string} [transport]
 * @property {MessengerType} [type]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RateLimitedRequestConfiguration
 * @extends Enableable
 *
 * @property {number} [limit]
 * @property {number} [timePeriodInSeconds]
 */


/**
 * User comment search response
 *
 * @author Spencer Witt
 *
 * @typedef {Object} UserCommentSearchResponse
 *
 * @property {number} [total]
 * @property {Array<UserComment>} [userComments]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var MultiFactorLoginPolicy = {
  Disabled: 'Disabled',
  Enabled: 'Enabled',
  Required: 'Required'
};

/**
 * @readonly
 * @enum
 */
var SAMLLogoutBehavior = {
  AllParticipants: 'AllParticipants',
  OnlyOriginator: 'OnlyOriginator'
};

/**
 * Models the User Password Breach Event.
 *
 * @author Matthew Altman
 *
 * @typedef {Object} UserPasswordBreachEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * The types of connectors. This enum is stored as an ordinal on the <code>identities</code> table, order must be maintained.
 *
 * @author Trevor Smith
 *
 * @readonly
 * @enum
 */
var ConnectorType = {
  FusionAuth: 'FusionAuth',
  Generic: 'Generic',
  LDAP: 'LDAP'
};

/**
 * @typedef {Object} MetaData
 *
 * @property {Object<string, Object>} [data]
 * @property {DeviceInfo} [device]
 * @property {Object<string>} [scopes]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} VerifyRegistrationRequest
 * @extends BaseEventRequest
 *
 * @property {string} [oneTimeCode]
 * @property {string} [verificationId]
 */


/**
 * Search request for Themes.
 *
 * @author Mark Manes
 *
 * @typedef {Object} ThemeSearchRequest
 *
 * @property {ThemeSearchCriteria} [search]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} EmailConfiguration
 *
 * @property {Array<EmailHeader>} [additionalHeaders]
 * @property {boolean} [debug]
 * @property {string} [defaultFromEmail]
 * @property {string} [defaultFromName]
 * @property {UUIDString} [emailUpdateEmailTemplateId]
 * @property {UUIDString} [emailVerifiedEmailTemplateId]
 * @property {UUIDString} [forgotPasswordEmailTemplateId]
 * @property {string} [host]
 * @property {boolean} [implicitEmailVerificationAllowed]
 * @property {UUIDString} [loginIdInUseOnCreateEmailTemplateId]
 * @property {UUIDString} [loginIdInUseOnUpdateEmailTemplateId]
 * @property {UUIDString} [loginNewDeviceEmailTemplateId]
 * @property {UUIDString} [loginSuspiciousEmailTemplateId]
 * @property {string} [password]
 * @property {UUIDString} [passwordlessEmailTemplateId]
 * @property {UUIDString} [passwordResetSuccessEmailTemplateId]
 * @property {UUIDString} [passwordUpdateEmailTemplateId]
 * @property {number} [port]
 * @property {string} [properties]
 * @property {EmailSecurityType} [security]
 * @property {UUIDString} [setPasswordEmailTemplateId]
 * @property {UUIDString} [twoFactorMethodAddEmailTemplateId]
 * @property {UUIDString} [twoFactorMethodRemoveEmailTemplateId]
 * @property {EmailUnverifiedOptions} [unverified]
 * @property {string} [username]
 * @property {UUIDString} [verificationEmailTemplateId]
 * @property {VerificationStrategy} [verificationStrategy]
 * @property {boolean} [verifyEmail]
 * @property {boolean} [verifyEmailWhenChanged]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ReloadRequest
 *
 * @property {Array<string>} [names]
 */


/**
 * @author Trevor Smith
 *
 * @typedef {Object} CORSConfiguration
 * @extends Enableable
 *
 * @property {boolean} [allowCredentials]
 * @property {Array<string>} [allowedHeaders]
 * @property {Array<HTTPMethod>} [allowedMethods]
 * @property {Array<string>} [allowedOrigins]
 * @property {boolean} [debug]
 * @property {Array<string>} [exposedHeaders]
 * @property {number} [preflightMaxAgeInSeconds]
 */


/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} AuditLogResponse
 *
 * @property {AuditLog} [auditLog]
 */


/**
 * Models a generic connector.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} GenericConnectorConfiguration
 * @extends BaseConnectorConfiguration
 *
 * @property {string} [authenticationURL]
 * @property {number} [connectTimeout]
 * @property {HTTPHeaders} [headers]
 * @property {string} [httpAuthenticationPassword]
 * @property {string} [httpAuthenticationUsername]
 * @property {number} [readTimeout]
 * @property {UUIDString} [sslCertificateKeyId]
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} TwitchApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * Webhook search response
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebhookSearchResponse
 *
 * @property {number} [total]
 * @property {Array<Webhook>} [webhooks]
 */


/**
 * Model a user event when a two-factor method has been removed.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserTwoFactorMethodAddEvent
 * @extends BaseEvent
 *
 * @property {TwoFactorMethod} [method]
 * @property {User} [user]
 */


/**
 * Stores an email template used to send emails to users.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EmailTemplate
 *
 * @property {string} [defaultFromName]
 * @property {string} [defaultHtmlTemplate]
 * @property {string} [defaultSubject]
 * @property {string} [defaultTextTemplate]
 * @property {string} [fromEmail]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {LocalizedStrings} [localizedFromNames]
 * @property {LocalizedStrings} [localizedHtmlTemplates]
 * @property {LocalizedStrings} [localizedSubjects]
 * @property {LocalizedStrings} [localizedTextTemplates]
 * @property {string} [name]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserTwoFactorConfiguration
 *
 * @property {Array<TwoFactorMethod>} [methods]
 * @property {Array<string>} [recoveryCodes]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ExternalJWTApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 */


/**
 * JWT Configuration for entities.
 *
 * @typedef {Object} EntityJWTConfiguration
 * @extends Enableable
 *
 * @property {UUIDString} [accessTokenKeyId]
 * @property {number} [timeToLiveInSeconds]
 */


/**
 * @author Mikey Sleevi
 *
 * @typedef {Object} Message
 *
 */


/**
 * @author Mikey Sleevi
 *
 * @typedef {Object} TenantMultiFactorConfiguration
 *
 * @property {MultiFactorAuthenticatorMethod} [authenticator]
 * @property {MultiFactorEmailMethod} [email]
 * @property {MultiFactorLoginPolicy} [loginPolicy]
 * @property {MultiFactorSMSMethod} [sms]
 */


/**
 * Describes the authenticator attachment modality preference for a WebAuthn workflow. See {@link AuthenticatorAttachment}
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var AuthenticatorAttachmentPreference = {
  any: 'any',
  platform: 'platform',
  crossPlatform: 'crossPlatform'
};

/**
 * @author Brett Guy
 *
 * @readonly
 * @enum
 */
var ProofKeyForCodeExchangePolicy = {
  Required: 'Required',
  NotRequired: 'NotRequired',
  NotRequiredWhenUsingClientAuthentication: 'NotRequiredWhenUsingClientAuthentication'
};

/**
 * Request for the Refresh Token API to revoke a refresh token rather than using the URL parameters.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} RefreshTokenRevokeRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [token]
 * @property {UUIDString} [userId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorStatusResponse
 *
 * @property {Array<TwoFactorTrust>} [trusts]
 * @property {string} [twoFactorTrustId]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var Sort = {
  asc: 'asc',
  desc: 'desc'
};

/**
 * @readonly
 * @enum
 */
var LoginIdType = {
  email: 'email',
  username: 'username'
};

/**
 * The Application Scope API request object.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ApplicationOAuthScopeRequest
 *
 * @property {ApplicationOAuthScope} [scope]
 */


/**
 * Refresh Token Import request.
 *
 * @author Brett Guy
 *
 * @typedef {Object} RefreshTokenImportRequest
 *
 * @property {Array<RefreshToken>} [refreshTokens]
 * @property {boolean} [validateDbConstraints]
 */


/**
 * @author Brett Guy
 *
 * @readonly
 * @enum
 */
var IPAccessControlEntryAction = {
  Allow: 'Allow',
  Block: 'Block'
};

/**
 * API response for managing families and members.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} FamilyResponse
 *
 * @property {Array<Family>} [families]
 * @property {Family} [family]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderStartLoginRequest
 * @extends BaseLoginRequest
 *
 * @property {Object<string, string>} [data]
 * @property {UUIDString} [identityProviderId]
 * @property {string} [loginId]
 * @property {Object<string, Object>} [state]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var ApplicationMultiFactorTrustPolicy = {
  Any: 'Any',
  This: 'This',
  None: 'None'
};

/**
 * Identity Provider response.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} IdentityProviderSearchResponse
 *
 * @property {Array<BaseIdentityProvider<Object>>} [identityProviders]
 * @property {number} [total]
 */


/**
 * @typedef {Object} SAMLv2Configuration
 * @extends Enableable
 *
 * @property {SAMLv2AssertionEncryptionConfiguration} [assertionEncryptionConfiguration]
 * @property {string} [audience]
 * @property {Array<string>} [authorizedRedirectURLs]
 * @property {string} [callbackURL]
 * @property {boolean} [debug]
 * @property {UUIDString} [defaultVerificationKeyId]
 * @property {SAMLv2IdPInitiatedLoginConfiguration} [initiatedLogin]
 * @property {string} [issuer]
 * @property {UUIDString} [keyId]
 * @property {LoginHintConfiguration} [loginHintConfiguration]
 * @property {SAMLv2Logout} [logout]
 * @property {string} [logoutURL]
 * @property {boolean} [requireSignedRequests]
 * @property {CanonicalizationMethod} [xmlSignatureC14nMethod]
 * @property {XMLSignatureLocation} [xmlSignatureLocation]
 */


/**
 * Describes the <a href="https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality">authenticator attachment modality</a>.
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var AuthenticatorAttachment = {
  platform: 'platform',
  crossPlatform: 'crossPlatform'
};

/**
 * The <i>authenticator's</i> response for the authentication ceremony in its encoded format
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnAuthenticatorAuthenticationResponse
 *
 * @property {string} [authenticatorData]
 * @property {string} [clientDataJSON]
 * @property {string} [signature]
 * @property {string} [userHandle]
 */


/**
 * Search request for Consents
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ConsentSearchRequest
 *
 * @property {ConsentSearchCriteria} [search]
 */


/**
 * XML canonicalization method enumeration. This is used for the IdP and SP side of FusionAuth SAML.
 *
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var CanonicalizationMethod = {
  exclusive: 'exclusive',
  exclusive_with_comments: 'exclusive_with_comments',
  inclusive: 'inclusive',
  inclusive_with_comments: 'inclusive_with_comments'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} DeviceInfo
 *
 * @property {string} [description]
 * @property {string} [lastAccessedAddress]
 * @property {number} [lastAccessedInstant]
 * @property {string} [name]
 * @property {string} [type]
 */


/**
 * Search request for Lambdas
 *
 * @author Mark Manes
 *
 * @typedef {Object} LambdaSearchRequest
 *
 * @property {LambdaSearchCriteria} [search]
 */


/**
 * OpenID Connect Configuration as described by the <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
 * Provider Metadata</a>.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} OpenIdConfiguration
 *
 * @property {string} [authorization_endpoint]
 * @property {boolean} [backchannel_logout_supported]
 * @property {Array<string>} [claims_supported]
 * @property {string} [device_authorization_endpoint]
 * @property {string} [end_session_endpoint]
 * @property {boolean} [frontchannel_logout_supported]
 * @property {Array<string>} [grant_types_supported]
 * @property {Array<string>} [id_token_signing_alg_values_supported]
 * @property {string} [issuer]
 * @property {string} [jwks_uri]
 * @property {Array<string>} [response_modes_supported]
 * @property {Array<string>} [response_types_supported]
 * @property {Array<string>} [scopes_supported]
 * @property {Array<string>} [subject_types_supported]
 * @property {string} [token_endpoint]
 * @property {Array<string>} [token_endpoint_auth_methods_supported]
 * @property {string} [userinfo_endpoint]
 * @property {Array<string>} [userinfo_signing_alg_values_supported]
 */


/**
 * @typedef {Object} APIKeyMetaData
 *
 * @property {Object<string, string>} [attributes]
 */


/**
 * The FormField API request object.
 *
 * @author Brett Guy
 *
 * @typedef {Object} FormFieldRequest
 *
 * @property {FormField} [field]
 * @property {Array<FormField>} [fields]
 */


/**
 * Models the User Created Event.
 * <p>
 * This is different than the user.create event in that it will be sent after the user has been created. This event cannot be made transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserCreateCompleteEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * @typedef {Object} EventConfigurationData
 * @extends Enableable
 *
 * @property {TransactionType} [transactionType]
 */


/**
 * This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserSearchCriteria
 * @extends BaseElasticSearchCriteria
 *
 */


/**
 * @typedef {Object} MultiFactorEmailTemplate
 *
 * @property {UUIDString} [templateId]
 */


/**
 * Models the User Delete Registration Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserRegistrationDeleteEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * Webhook API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} WebhookResponse
 *
 * @property {Webhook} [webhook]
 * @property {Array<Webhook>} [webhooks]
 */


/**
 * A raw login record response
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginRecordSearchResponse
 *
 * @property {Array<DisplayableRawLogin>} [logins]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} VerifyRegistrationResponse
 *
 * @property {string} [oneTimeCode]
 * @property {string} [verificationId]
 */


/**
 * API request for managing families and members.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} FamilyRequest
 *
 * @property {FamilyMember} [familyMember]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RememberPreviousPasswords
 * @extends Enableable
 *
 * @property {number} [count]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} MinimumPasswordAge
 * @extends Enableable
 *
 * @property {number} [seconds]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} EmailUnverifiedOptions
 *
 * @property {boolean} [allowEmailChangeWhenGated]
 * @property {UnverifiedBehavior} [behavior]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorEnableDisableSendRequest
 *
 * @property {string} [email]
 * @property {string} [method]
 * @property {string} [methodId]
 * @property {string} [mobilePhone]
 */


/**
 * @typedef {Object} IdentityProviderDetails
 *
 * @property {Array<UUIDString>} [applicationIds]
 * @property {UUIDString} [id]
 * @property {string} [idpEndpoint]
 * @property {string} [name]
 * @property {IdentityProviderOauth2Configuration} [oauth2]
 * @property {IdentityProviderType} [type]
 */


/**
 * @typedef {Object} Totals
 *
 * @property {number} [logins]
 * @property {number} [registrations]
 * @property {number} [totalRegistrations]
 */


/**
 * @readonly
 * @enum
 */
var BreachMatchMode = {
  Low: 'Low',
  Medium: 'Medium',
  High: 'High'
};

/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var BreachedPasswordStatus = {
  None: 'None',
  ExactMatch: 'ExactMatch',
  SubAddressMatch: 'SubAddressMatch',
  PasswordOnly: 'PasswordOnly',
  CommonPassword: 'CommonPassword'
};

/**
 * A server where events are sent. This includes user action events and any other events sent by FusionAuth.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Webhook
 *
 * @property {number} [connectTimeout]
 * @property {Object<string, Object>} [data]
 * @property {string} [description]
 * @property {Object<EventType, boolean>} [eventsEnabled]
 * @property {boolean} [global]
 * @property {HTTPHeaders} [headers]
 * @property {string} [httpAuthenticationPassword]
 * @property {string} [httpAuthenticationUsername]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {number} [readTimeout]
 * @property {WebhookSignatureConfiguration} [signatureConfiguration]
 * @property {string} [sslCertificate]
 * @property {UUIDString} [sslCertificateKeyId]
 * @property {Array<UUIDString>} [tenantIds]
 * @property {string} [url]
 */


/**
 * Email template request.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EmailTemplateRequest
 *
 * @property {EmailTemplate} [emailTemplate]
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} XboxApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LookupResponse
 *
 * @property {IdentityProviderDetails} [identityProvider]
 */


/**
 * Event Log Type
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var EventLogType = {
  Information: 'Information',
  Debug: 'Debug',
  Error: 'Error'
};

/**
 * Tenant search response
 *
 * @author Mark Manes
 *
 * @typedef {Object} TenantSearchResponse
 *
 * @property {Array<Tenant>} [tenants]
 * @property {number} [total]
 */


/**
 * <ul>
 * <li>Bearer Token type as defined by <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>.</li>
 * <li>MAC Token type as referenced by <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a> and
 * <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05">
 * Draft RFC on OAuth 2.0 Message Authentication Code (MAC) Tokens</a>
 * </li>
 * </ul>
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var TokenType = {
  Bearer: 'Bearer',
  MAC: 'MAC'
};

/**
 * Search criteria for entity grants.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityGrantSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {UUIDString} [entityId]
 * @property {string} [name]
 * @property {UUIDString} [userId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PendingIdPLink
 *
 * @property {string} [displayName]
 * @property {string} [email]
 * @property {UUIDString} [identityProviderId]
 * @property {Array<IdentityProviderLink>} [identityProviderLinks]
 * @property {string} [identityProviderName]
 * @property {IdentityProviderTenantConfiguration} [identityProviderTenantConfiguration]
 * @property {IdentityProviderType} [identityProviderType]
 * @property {string} [identityProviderUserId]
 * @property {User} [user]
 * @property {string} [username]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} PreviewRequest
 *
 * @property {EmailTemplate} [emailTemplate]
 * @property {string} [locale]
 */


/**
 * Search results.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SearchResults
 * @template {T}
 *
 * @property {string} [nextResults]
 * @property {Array<T>} [results]
 * @property {number} [total]
 * @property {boolean} [totalEqualToActual]
 */


/**
 * @typedef {Object} APIKeyPermissions
 *
 * @property {Object<string, Object<string>>} [endpoints]
 */


/**
 * Lambda search response
 *
 * @author Mark Manes
 *
 * @typedef {Object} LambdaSearchResponse
 *
 * @property {Array<Lambda>} [lambdas]
 * @property {number} [total]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} Count
 *
 * @property {number} [count]
 * @property {number} [interval]
 */


/**
 * User Action Reason API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionReasonResponse
 *
 * @property {UserActionReason} [userActionReason]
 * @property {Array<UserActionReason>} [userActionReasons]
 */


/**
 * @typedef {Object} PasswordlessConfiguration
 * @extends Enableable
 *
 */


/**
 * SAML v2 identity provider configuration.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SAMLv2IdentityProvider
 * @extends BaseSAMLv2IdentityProvider<SAMLv2ApplicationConfiguration>
 *
 * @property {SAMLv2AssertionConfiguration} [assertionConfiguration]
 * @property {string} [buttonImageURL]
 * @property {string} [buttonText]
 * @property {Object<string>} [domains]
 * @property {string} [idpEndpoint]
 * @property {SAMLv2IdpInitiatedConfiguration} [idpInitiatedConfiguration]
 * @property {string} [issuer]
 * @property {LoginHintConfiguration} [loginHintConfiguration]
 * @property {string} [nameIdFormat]
 * @property {boolean} [postRequest]
 * @property {UUIDString} [requestSigningKeyId]
 * @property {boolean} [signRequest]
 * @property {CanonicalizationMethod} [xmlSignatureC14nMethod]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordValidationRulesResponse
 *
 * @property {PasswordValidationRules} [passwordValidationRules]
 */


/**
 * @readonly
 * @enum
 */
var ClientAuthenticationMethod = {
  none: 'none',
  client_secret_basic: 'client_secret_basic',
  client_secret_post: 'client_secret_post'
};

/**
 * Search criteria for entity types.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityTypeSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 */


/**
 * Contains extension output for requested extensions during a WebAuthn ceremony
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnExtensionsClientOutputs
 *
 * @property {CredentialPropertiesOutput} [credProps]
 */


/**
 * User Action API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionRequest
 *
 * @property {UserAction} [userAction]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} AppleApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [bundleId]
 * @property {string} [buttonText]
 * @property {UUIDString} [keyId]
 * @property {string} [scope]
 * @property {string} [servicesId]
 * @property {string} [teamId]
 */


/**
 * Group API request object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupRequest
 *
 * @property {Group} [group]
 * @property {Array<UUIDString>} [roleIds]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ValidateResponse
 *
 * @property {JWT | object} [jwt]
 */


/**
 * @author Seth Musselman
 *
 * @typedef {Object} UserCommentRequest
 *
 * @property {UserComment} [userComment]
 */


/**
 * API request to start a WebAuthn registration ceremony
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnRegisterStartRequest
 *
 * @property {string} [displayName]
 * @property {string} [name]
 * @property {string} [userAgent]
 * @property {UUIDString} [userId]
 * @property {WebAuthnWorkflow} [workflow]
 */


/**
 * Models the Group Member Add Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberAddEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Array<GroupMember>} [members]
 */


/**
 * Search request for entities
 *
 * @author Brett Guy
 *
 * @typedef {Object} EntitySearchRequest
 *
 * @property {EntitySearchCriteria} [search]
 */


/**
 * Models the User Update Event.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserUpdateEvent
 * @extends BaseEvent
 *
 * @property {User} [original]
 * @property {User} [user]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var IdentityProviderType = {
  Apple: 'Apple',
  EpicGames: 'EpicGames',
  ExternalJWT: 'ExternalJWT',
  Facebook: 'Facebook',
  Google: 'Google',
  HYPR: 'HYPR',
  LinkedIn: 'LinkedIn',
  Nintendo: 'Nintendo',
  OpenIDConnect: 'OpenIDConnect',
  SAMLv2: 'SAMLv2',
  SAMLv2IdPInitiated: 'SAMLv2IdPInitiated',
  SonyPSN: 'SonyPSN',
  Steam: 'Steam',
  Twitch: 'Twitch',
  Twitter: 'Twitter',
  Xbox: 'Xbox'
};

/**
 * Entity Type API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityTypeRequest
 *
 * @property {EntityType} [entityType]
 * @property {EntityTypePermission} [permission]
 */


/**
 * @author Trevor Smith
 *
 * @typedef {Object} ConnectorResponse
 *
 * @property {BaseConnectorConfiguration} [connector]
 * @property {Array<BaseConnectorConfiguration>} [connectors]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderLinkResponse
 *
 * @property {IdentityProviderLink} [identityProviderLink]
 * @property {Array<IdentityProviderLink>} [identityProviderLinks]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ApplicationExternalIdentifierConfiguration
 *
 * @property {number} [twoFactorTrustIdTimeToLiveInSeconds]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantFormConfiguration
 *
 * @property {UUIDString} [adminUserFormId]
 */


/**
 * Search criteria for Lambdas
 *
 * @author Mark Manes
 *
 * @typedef {Object} LambdaSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [body]
 * @property {string} [name]
 * @property {LambdaType} [type]
 */


/**
 * Search criteria for Tenants
 *
 * @author Mark Manes
 *
 * @typedef {Object} TenantSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 */


/**
 * Tenant-level configuration for WebAuthn
 *
 * @author Spencer Witt
 *
 * @typedef {Object} TenantWebAuthnConfiguration
 * @extends Enableable
 *
 * @property {TenantWebAuthnWorkflowConfiguration} [bootstrapWorkflow]
 * @property {boolean} [debug]
 * @property {TenantWebAuthnWorkflowConfiguration} [reauthenticationWorkflow]
 * @property {string} [relyingPartyId]
 * @property {string} [relyingPartyName]
 */


/**
 * Defines an error.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Error
 *
 * @property {string} [code]
 * @property {Object<string, Object>} [data]
 * @property {string} [message]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SendRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {Array<string>} [bccAddresses]
 * @property {Array<string>} [ccAddresses]
 * @property {Array<string>} [preferredLanguages]
 * @property {Object<string, Object>} [requestData]
 * @property {Array<EmailAddress>} [toAddresses]
 * @property {Array<UUIDString>} [userIds]
 */


/**
 * Interface for all identity providers that can be domain based.
 *
 * @typedef {Object} DomainBasedIdentityProvider
 *
 */


/**
 * @typedef {Object} EmailPlus
 * @extends Enableable
 *
 * @property {UUIDString} [emailTemplateId]
 * @property {number} [maximumTimeToSendEmailInHours]
 * @property {number} [minimumTimeToSendEmailInHours]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var SystemTrustedProxyConfigurationPolicy = {
  All: 'All',
  OnlyConfigured: 'OnlyConfigured'
};

/**
 * Used to communicate whether and how authenticator attestation should be delivered to the Relying Party
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var AttestationConveyancePreference = {
  none: 'none',
  indirect: 'indirect',
  direct: 'direct',
  enterprise: 'enterprise'
};

/**
 * @typedef {Object} CertificateInformation
 *
 * @property {string} [issuer]
 * @property {string} [md5Fingerprint]
 * @property {string} [serialNumber]
 * @property {string} [sha1Fingerprint]
 * @property {string} [sha1Thumbprint]
 * @property {string} [sha256Fingerprint]
 * @property {string} [sha256Thumbprint]
 * @property {string} [subject]
 * @property {number} [validFrom]
 * @property {number} [validTo]
 */


/**
 * JWT Public Key Response Object
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} PublicKeyResponse
 *
 * @property {string} [publicKey]
 * @property {Object<string, string>} [publicKeys]
 */


/**
 * @author Mikey Sleevi
 *
 * @readonly
 * @enum
 */
var MessageType = {
  SMS: 'SMS'
};

/**
 * Event log used internally by FusionAuth to help developers debug hooks, Webhooks, email templates, etc.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventLog
 *
 * @property {number} [id]
 * @property {number} [insertInstant]
 * @property {string} [message]
 * @property {EventLogType} [type]
 */


/**
 * Config for regular SAML IDP configurations that support IdP initiated requests
 *
 * @author Lyle Schemmerling
 *
 * @typedef {Object} SAMLv2IdpInitiatedConfiguration
 * @extends Enableable
 *
 * @property {string} [issuer]
 */


/**
 * API response for refreshing a JWT with a Refresh Token.
 * <p>
 * Using a different response object from RefreshTokenResponse because the retrieve response will return an object for refreshToken, and this is a
 * string.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWTRefreshResponse
 *
 * @property {string} [refreshToken]
 * @property {UUIDString} [refreshTokenId]
 * @property {string} [token]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginHintConfiguration
 * @extends Enableable
 *
 * @property {string} [parameterName]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} FacebookApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [appId]
 * @property {string} [buttonText]
 * @property {string} [client_secret]
 * @property {string} [fields]
 * @property {IdentityProviderLoginMethod} [loginMethod]
 * @property {string} [permissions]
 */


/**
 * User Comment Response
 *
 * @author Seth Musselman
 *
 * @typedef {Object} UserCommentResponse
 *
 * @property {UserComment} [userComment]
 * @property {Array<UserComment>} [userComments]
 */


/**
 * Models the event types that FusionAuth produces.
 *
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var EventType = {
  JWTPublicKeyUpdate: 'jwt.public-key.update',
  JWTRefreshTokenRevoke: 'jwt.refresh-token.revoke',
  JWTRefresh: 'jwt.refresh',
  AuditLogCreate: 'audit-log.create',
  EventLogCreate: 'event-log.create',
  KickstartSuccess: 'kickstart.success',
  GroupCreate: 'group.create',
  GroupCreateComplete: 'group.create.complete',
  GroupDelete: 'group.delete',
  GroupDeleteComplete: 'group.delete.complete',
  GroupMemberAdd: 'group.member.add',
  GroupMemberAddComplete: 'group.member.add.complete',
  GroupMemberRemove: 'group.member.remove',
  GroupMemberRemoveComplete: 'group.member.remove.complete',
  GroupMemberUpdate: 'group.member.update',
  GroupMemberUpdateComplete: 'group.member.update.complete',
  GroupUpdate: 'group.update',
  GroupUpdateComplete: 'group.update.complete',
  UserAction: 'user.action',
  UserBulkCreate: 'user.bulk.create',
  UserCreate: 'user.create',
  UserCreateComplete: 'user.create.complete',
  UserDeactivate: 'user.deactivate',
  UserDelete: 'user.delete',
  UserDeleteComplete: 'user.delete.complete',
  UserEmailUpdate: 'user.email.update',
  UserEmailVerified: 'user.email.verified',
  UserIdentityProviderLink: 'user.identity-provider.link',
  UserIdentityProviderUnlink: 'user.identity-provider.unlink',
  UserLoginIdDuplicateOnCreate: 'user.loginId.duplicate.create',
  UserLoginIdDuplicateOnUpdate: 'user.loginId.duplicate.update',
  UserLoginFailed: 'user.login.failed',
  UserLoginNewDevice: 'user.login.new-device',
  UserLoginSuccess: 'user.login.success',
  UserLoginSuspicious: 'user.login.suspicious',
  UserPasswordBreach: 'user.password.breach',
  UserPasswordResetSend: 'user.password.reset.send',
  UserPasswordResetStart: 'user.password.reset.start',
  UserPasswordResetSuccess: 'user.password.reset.success',
  UserPasswordUpdate: 'user.password.update',
  UserReactivate: 'user.reactivate',
  UserRegistrationCreate: 'user.registration.create',
  UserRegistrationCreateComplete: 'user.registration.create.complete',
  UserRegistrationDelete: 'user.registration.delete',
  UserRegistrationDeleteComplete: 'user.registration.delete.complete',
  UserRegistrationUpdate: 'user.registration.update',
  UserRegistrationUpdateComplete: 'user.registration.update.complete',
  UserRegistrationVerified: 'user.registration.verified',
  UserTwoFactorMethodAdd: 'user.two-factor.method.add',
  UserTwoFactorMethodRemove: 'user.two-factor.method.remove',
  UserUpdate: 'user.update',
  UserUpdateComplete: 'user.update.complete',
  Test: 'test'
};

/**
 * Used to express whether the Relying Party requires <a href="https://www.w3.org/TR/webauthn-2/#user-verification">user verification</a> for the
 * current operation.
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var UserVerificationRequirement = {
  required: 'required',
  preferred: 'preferred',
  discouraged: 'discouraged'
};

/**
 * Models the User Password Update Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserPasswordUpdateEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * Request to authenticate with WebAuthn
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnPublicKeyAuthenticationRequest
 *
 * @property {WebAuthnExtensionsClientOutputs} [clientExtensionResults]
 * @property {string} [id]
 * @property {WebAuthnAuthenticatorAuthenticationResponse} [response]
 * @property {string} [rpId]
 * @property {string} [type]
 */


/**
 * Standard error domain object that can also be used as the response from an API call.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Errors
 *
 * @property {Object<string, Array<Error>>} [fieldErrors]
 * @property {Array<Error>} [generalErrors]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginRecordExportRequest
 * @extends BaseExportRequest
 *
 * @property {LoginRecordSearchCriteria} [criteria]
 */


/**
 * IdP Initiated login configuration
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} SAMLv2IdPInitiatedLoginConfiguration
 * @extends Enableable
 *
 * @property {string} [nameIdFormat]
 */


/**
 * A marker interface indicating this event is not scoped to a tenant and will be sent to all webhooks.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} InstanceEvent
 * @extends NonTransactionalEvent
 *
 */


/**
 * The IdP behavior when no user link has been made yet.
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var IdentityProviderLinkingStrategy = {
  CreatePendingLink: 'CreatePendingLink',
  Disabled: 'Disabled',
  LinkAnonymously: 'LinkAnonymously',
  LinkByEmail: 'LinkByEmail',
  LinkByEmailForExistingUser: 'LinkByEmailForExistingUser',
  LinkByUsername: 'LinkByUsername',
  LinkByUsernameForExistingUser: 'LinkByUsernameForExistingUser',
  Unsupported: 'Unsupported'
};

/**
 * Event to indicate kickstart has been successfully completed.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} KickstartSuccessEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [instanceId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWKSResponse
 *
 * @property {Array<JSONWebKey>} [keys]
 */


/**
 * @readonly
 * @enum
 */
var KeyType = {
  EC: 'EC',
  RSA: 'RSA',
  HMAC: 'HMAC'
};

/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var RefreshTokenUsagePolicy = {
  Reusable: 'Reusable',
  OneTimeUse: 'OneTimeUse'
};

/**
 * User API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserResponse
 *
 * @property {string} [emailVerificationId]
 * @property {string} [emailVerificationOneTimeCode]
 * @property {Object<UUIDString, string>} [registrationVerificationIds]
 * @property {Object<UUIDString, string>} [registrationVerificationOneTimeCodes]
 * @property {string} [token]
 * @property {number} [tokenExpirationInstant]
 * @property {User} [user]
 */


/**
 * A User's membership into a Group
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMember
 *
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [groupId]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {User} [user]
 * @property {UUIDString} [userId]
 */


/**
 * User registration information for a single application.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserRegistration
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [authenticationToken]
 * @property {UUIDString} [cleanSpeakId]
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastLoginInstant]
 * @property {number} [lastUpdateInstant]
 * @property {Array<string>} [preferredLanguages]
 * @property {Array<string>} [roles]
 * @property {string} [timezone]
 * @property {Object<string, string>} [tokens]
 * @property {string} [username]
 * @property {ContentStatus} [usernameStatus]
 * @property {boolean} [verified]
 * @property {number} [verifiedInstant]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} TenantAccessControlConfiguration
 *
 * @property {UUIDString} [uiIPAccessControlListId]
 */


/**
 * Webhook API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} WebhookRequest
 *
 * @property {Webhook} [webhook]
 */


/**
 * Models the user action Event.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionEvent
 * @extends BaseEvent
 *
 * @property {string} [action]
 * @property {UUIDString} [actioneeUserId]
 * @property {UUIDString} [actionerUserId]
 * @property {UUIDString} [actionId]
 * @property {Array<UUIDString>} [applicationIds]
 * @property {string} [comment]
 * @property {Email} [email]
 * @property {boolean} [emailedUser]
 * @property {number} [expiry]
 * @property {string} [localizedAction]
 * @property {string} [localizedDuration]
 * @property {string} [localizedOption]
 * @property {string} [localizedReason]
 * @property {boolean} [notifyUser]
 * @property {string} [option]
 * @property {UserActionPhase} [phase]
 * @property {string} [reason]
 * @property {string} [reasonCode]
 */


/**
 * Models the Group Member Add Complete Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberAddCompleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Array<GroupMember>} [members]
 */


/**
 * Search API response.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SearchResponse
 * @extends ExpandableResponse
 *
 * @property {string} [nextResults]
 * @property {number} [total]
 * @property {Array<User>} [users]
 */


/**
 * The handling policy for scopes provided by FusionAuth
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ProvidedScopePolicy
 *
 * @property {Requirable} [address]
 * @property {Requirable} [email]
 * @property {Requirable} [phone]
 * @property {Requirable} [profile]
 */


/**
 * Search criteria for themes
 *
 * @author Mark Manes
 *
 * @typedef {Object} ThemeSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [name]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} OAuth2Configuration
 *
 * @property {Array<string>} [authorizedOriginURLs]
 * @property {Array<string>} [authorizedRedirectURLs]
 * @property {Oauth2AuthorizedURLValidationPolicy} [authorizedURLValidationPolicy]
 * @property {ClientAuthenticationPolicy} [clientAuthenticationPolicy]
 * @property {string} [clientId]
 * @property {string} [clientSecret]
 * @property {OAuthScopeConsentMode} [consentMode]
 * @property {boolean} [debug]
 * @property {string} [deviceVerificationURL]
 * @property {Object<GrantType>} [enabledGrants]
 * @property {boolean} [generateRefreshTokens]
 * @property {LogoutBehavior} [logoutBehavior]
 * @property {string} [logoutURL]
 * @property {ProofKeyForCodeExchangePolicy} [proofKeyForCodeExchangePolicy]
 * @property {ProvidedScopePolicy} [providedScopePolicy]
 * @property {OAuthApplicationRelationship} [relationship]
 * @property {boolean} [requireClientAuthentication]
 * @property {boolean} [requireRegistration]
 * @property {OAuthScopeHandlingPolicy} [scopeHandlingPolicy]
 * @property {UnknownScopePolicy} [unknownScopePolicy]
 */


/**
 * Search criteria for Group Members
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {UUIDString} [groupId]
 * @property {UUIDString} [tenantId]
 * @property {UUIDString} [userId]
 */


/**
 * Models the User Create Registration Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserRegistrationCreateEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * @author Rob Davis
 *
 * @typedef {Object} TenantSCIMServerConfiguration
 * @extends Enableable
 *
 * @property {UUIDString} [clientEntityTypeId]
 * @property {Object<string, Object>} [schemas]
 * @property {UUIDString} [serverEntityTypeId]
 */


/**
 * @typedef {Object} UIConfiguration
 *
 * @property {string} [headerColor]
 * @property {string} [logoURL]
 * @property {string} [menuFontColor]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventConfiguration
 *
 * @property {Object<EventType, EventConfigurationData>} [events]
 */


/**
 * A log for an action that was taken on a User.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionLog
 *
 * @property {UUIDString} [actioneeUserId]
 * @property {UUIDString} [actionerUserId]
 * @property {Array<UUIDString>} [applicationIds]
 * @property {string} [comment]
 * @property {boolean} [emailUserOnEnd]
 * @property {boolean} [endEventSent]
 * @property {number} [expiry]
 * @property {LogHistory} [history]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {string} [localizedName]
 * @property {string} [localizedOption]
 * @property {string} [localizedReason]
 * @property {string} [name]
 * @property {boolean} [notifyUserOnEnd]
 * @property {string} [option]
 * @property {string} [reason]
 * @property {string} [reasonCode]
 * @property {UUIDString} [userActionId]
 */


/**
 * Email template search response
 *
 * @author Mark Manes
 *
 * @typedef {Object} EmailTemplateSearchResponse
 *
 * @property {Array<EmailTemplate>} [emailTemplates]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ExternalIdentifierConfiguration
 *
 * @property {number} [authorizationGrantIdTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [changePasswordIdGenerator]
 * @property {number} [changePasswordIdTimeToLiveInSeconds]
 * @property {number} [deviceCodeTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [deviceUserCodeIdGenerator]
 * @property {SecureGeneratorConfiguration} [emailVerificationIdGenerator]
 * @property {number} [emailVerificationIdTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [emailVerificationOneTimeCodeGenerator]
 * @property {number} [externalAuthenticationIdTimeToLiveInSeconds]
 * @property {number} [oneTimePasswordTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [passwordlessLoginGenerator]
 * @property {number} [passwordlessLoginTimeToLiveInSeconds]
 * @property {number} [pendingAccountLinkTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [registrationVerificationIdGenerator]
 * @property {number} [registrationVerificationIdTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [registrationVerificationOneTimeCodeGenerator]
 * @property {number} [rememberOAuthScopeConsentChoiceTimeToLiveInSeconds]
 * @property {number} [samlv2AuthNRequestIdTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [setupPasswordIdGenerator]
 * @property {number} [setupPasswordIdTimeToLiveInSeconds]
 * @property {number} [trustTokenTimeToLiveInSeconds]
 * @property {number} [twoFactorIdTimeToLiveInSeconds]
 * @property {SecureGeneratorConfiguration} [twoFactorOneTimeCodeIdGenerator]
 * @property {number} [twoFactorOneTimeCodeIdTimeToLiveInSeconds]
 * @property {number} [twoFactorTrustIdTimeToLiveInSeconds]
 * @property {number} [webAuthnAuthenticationChallengeTimeToLiveInSeconds]
 * @property {number} [webAuthnRegistrationChallengeTimeToLiveInSeconds]
 */


/**
 * @readonly
 * @enum
 */
var DeviceType = {
  BROWSER: 'BROWSER',
  DESKTOP: 'DESKTOP',
  LAPTOP: 'LAPTOP',
  MOBILE: 'MOBILE',
  OTHER: 'OTHER',
  SERVER: 'SERVER',
  TABLET: 'TABLET',
  TV: 'TV',
  UNKNOWN: 'UNKNOWN'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantRateLimitConfiguration
 *
 * @property {RateLimitedRequestConfiguration} [failedLogin]
 * @property {RateLimitedRequestConfiguration} [forgotPassword]
 * @property {RateLimitedRequestConfiguration} [sendEmailVerification]
 * @property {RateLimitedRequestConfiguration} [sendPasswordless]
 * @property {RateLimitedRequestConfiguration} [sendRegistrationVerification]
 * @property {RateLimitedRequestConfiguration} [sendTwoFactor]
 */


/**
 * Search request for entity grants.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityGrantSearchRequest
 *
 * @property {EntityGrantSearchCriteria} [search]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} Tenant
 *
 * @property {TenantAccessControlConfiguration} [accessControlConfiguration]
 * @property {TenantCaptchaConfiguration} [captchaConfiguration]
 * @property {boolean} [configured]
 * @property {Array<ConnectorPolicy>} [connectorPolicies]
 * @property {Object<string, Object>} [data]
 * @property {EmailConfiguration} [emailConfiguration]
 * @property {EventConfiguration} [eventConfiguration]
 * @property {ExternalIdentifierConfiguration} [externalIdentifierConfiguration]
 * @property {FailedAuthenticationConfiguration} [failedAuthenticationConfiguration]
 * @property {FamilyConfiguration} [familyConfiguration]
 * @property {TenantFormConfiguration} [formConfiguration]
 * @property {number} [httpSessionMaxInactiveInterval]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {string} [issuer]
 * @property {JWTConfiguration} [jwtConfiguration]
 * @property {TenantLambdaConfiguration} [lambdaConfiguration]
 * @property {number} [lastUpdateInstant]
 * @property {TenantLoginConfiguration} [loginConfiguration]
 * @property {string} [logoutURL]
 * @property {MaximumPasswordAge} [maximumPasswordAge]
 * @property {MinimumPasswordAge} [minimumPasswordAge]
 * @property {TenantMultiFactorConfiguration} [multiFactorConfiguration]
 * @property {string} [name]
 * @property {TenantOAuth2Configuration} [oauthConfiguration]
 * @property {PasswordEncryptionConfiguration} [passwordEncryptionConfiguration]
 * @property {PasswordValidationRules} [passwordValidationRules]
 * @property {TenantRateLimitConfiguration} [rateLimitConfiguration]
 * @property {TenantRegistrationConfiguration} [registrationConfiguration]
 * @property {TenantSCIMServerConfiguration} [scimServerConfiguration]
 * @property {TenantSSOConfiguration} [ssoConfiguration]
 * @property {ObjectState} [state]
 * @property {UUIDString} [themeId]
 * @property {TenantUserDeletePolicy} [userDeletePolicy]
 * @property {TenantUsernameConfiguration} [usernameConfiguration]
 * @property {TenantWebAuthnConfiguration} [webAuthnConfiguration]
 */


/**
 * @author Lyle Schemmerling
 *
 * @typedef {Object} BaseSAMLv2IdentityProvider
 * @template {D}
 * @extends BaseIdentityProvider<D>
 *
 * @property {string} [emailClaim]
 * @property {UUIDString} [keyId]
 * @property {string} [uniqueIdClaim]
 * @property {boolean} [useNameIdForEmail]
 * @property {string} [usernameClaim]
 */


/**
 * Models the User Password Reset Start Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserPasswordResetStartEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * @typedef {Object} LoginConfiguration
 *
 * @property {boolean} [allowTokenRefresh]
 * @property {boolean} [generateRefreshTokens]
 * @property {boolean} [requireAuthentication]
 */


/**
 * Change password request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ChangePasswordRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [changePasswordId]
 * @property {string} [currentPassword]
 * @property {string} [loginId]
 * @property {string} [password]
 * @property {string} [refreshToken]
 * @property {string} [trustChallenge]
 * @property {string} [trustToken]
 */


/**
 * Contains attributes for the Relying Party to refer to an existing public key credential as an input parameter.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} PublicKeyCredentialDescriptor
 *
 * @property {string} [id]
 * @property {Array<string>} [transports]
 * @property {PublicKeyCredentialType} [type]
 */


/**
 * Models a single family member.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} FamilyMember
 *
 * @property {Object<string, Object>} [data]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {boolean} [owner]
 * @property {FamilyRole} [role]
 * @property {UUIDString} [userId]
 */


/**
 * @typedef {Object} RegistrationConfiguration
 * @extends Enableable
 *
 * @property {Requirable} [birthDate]
 * @property {boolean} [confirmPassword]
 * @property {Requirable} [firstName]
 * @property {UUIDString} [formId]
 * @property {Requirable} [fullName]
 * @property {Requirable} [lastName]
 * @property {LoginIdType} [loginIdType]
 * @property {Requirable} [middleName]
 * @property {Requirable} [mobilePhone]
 * @property {Requirable} [preferredLanguages]
 * @property {RegistrationType} [type]
 */


/**
 * @readonly
 * @enum
 */
var BreachAction = {
  Off: 'Off',
  RecordOnly: 'RecordOnly',
  NotifyUser: 'NotifyUser',
  RequireChange: 'RequireChange'
};

/**
 * Search request for Keys
 *
 * @author Spencer Witt
 *
 * @typedef {Object} KeySearchRequest
 *
 * @property {KeySearchCriteria} [search]
 */


/**
 * The application's relationship to the authorization server. First-party applications will be granted implicit permission for requested scopes.
 * Third-party applications will use the {@link OAuthScopeConsentMode} policy.
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var OAuthApplicationRelationship = {
  FirstParty: 'FirstParty',
  ThirdParty: 'ThirdParty'
};

/**
 * Group Member Response
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} MemberResponse
 *
 * @property {Object<UUIDString, Array<GroupMember>>} [members]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SystemTrustedProxyConfiguration
 *
 * @property {Array<string>} [trusted]
 * @property {SystemTrustedProxyConfigurationPolicy} [trustPolicy]
 */


/**
 * Key search response
 *
 * @author Spencer Witt
 *
 * @typedef {Object} KeySearchResponse
 *
 * @property {Array<Key>} [keys]
 * @property {number} [total]
 */


/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserConsentRequest
 *
 * @property {UserConsent} [userConsent]
 */


/**
 * Describes the Relying Party's requirements for <a href="https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential">client-side
 * discoverable credentials</a> (formerly known as "resident keys")
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var ResidentKeyRequirement = {
  discouraged: 'discouraged',
  preferred: 'preferred',
  required: 'required'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RefreshRequest
 * @extends BaseEventRequest
 *
 * @property {string} [refreshToken]
 * @property {string} [token]
 */


/**
 * Form field response.
 *
 * @author Brett Guy
 *
 * @typedef {Object} FormFieldResponse
 *
 * @property {FormField} [field]
 * @property {Array<FormField>} [fields]
 */


/**
 * API response for completing WebAuthn credential registration or assertion
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnRegisterCompleteResponse
 *
 * @property {WebAuthnCredential} [credential]
 */


/**
 * Change password response object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ChangePasswordResponse
 *
 * @property {string} [oneTimePassword]
 * @property {Object<string, Object>} [state]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantResponse
 *
 * @property {Tenant} [tenant]
 * @property {Array<Tenant>} [tenants]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ApplicationFormConfiguration
 *
 * @property {UUIDString} [adminRegistrationFormId]
 * @property {SelfServiceFormConfiguration} [selfServiceFormConfiguration]
 * @property {UUIDString} [selfServiceFormId]
 */


/**
 * Raw login information for each time a user logs into an application.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} RawLogin
 *
 * @property {UUIDString} [applicationId]
 * @property {number} [instant]
 * @property {string} [ipAddress]
 * @property {UUIDString} [userId]
 */


/**
 * Models an event where a user is being updated and tries to use an "in-use" login Id (email or username).
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserLoginIdDuplicateOnUpdateEvent
 * @extends UserLoginIdDuplicateOnCreateEvent
 *
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} TenantSSOConfiguration
 *
 * @property {number} [deviceTrustTimeToLiveInSeconds]
 */


/**
 * API response for starting a WebAuthn registration ceremony
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnRegisterStartResponse
 *
 * @property {PublicKeyCredentialCreationOptions} [options]
 */


/**
 * SonyPSN gaming login provider.
 *
 * @author Brett Pontarelli
 *
 * @typedef {Object} SonyPSNIdentityProvider
 * @extends BaseIdentityProvider<SonyPSNApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SAMLv2IdPInitiatedApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} VerifyEmailRequest
 * @extends BaseEventRequest
 *
 * @property {string} [oneTimeCode]
 * @property {UUIDString} [userId]
 * @property {string} [verificationId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} AuditLogExportRequest
 * @extends BaseExportRequest
 *
 * @property {AuditLogSearchCriteria} [criteria]
 */


/**
 * @author Michael Sleevi
 *
 * @typedef {Object} SMSMessage
 *
 * @property {string} [phoneNumber]
 * @property {string} [textMessage]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var VerificationStrategy = {
  ClickableLink: 'ClickableLink',
  FormField: 'FormField'
};

/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} SAMLv2ApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonImageURL]
 * @property {string} [buttonText]
 */


/**
 * @author Matthew Altman
 *
 * @readonly
 * @enum
 */
var LogoutBehavior = {
  RedirectOnly: 'RedirectOnly',
  AllApplications: 'AllApplications'
};

/**
 * This class is a simple attachment with a byte array, name and MIME type.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Attachment
 *
 * @property {Array<number>} [attachment]
 * @property {string} [mime]
 * @property {string} [name]
 */


/**
 * User API delete request object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserDeleteRequest
 * @extends BaseEventRequest
 *
 * @property {boolean} [dryRun]
 * @property {boolean} [hardDelete]
 * @property {number} [limit]
 * @property {string} [query]
 * @property {string} [queryString]
 * @property {Array<UUIDString>} [userIds]
 */


/**
 * SAML v2 IdP Initiated identity provider configuration.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} SAMLv2IdPInitiatedIdentityProvider
 * @extends BaseSAMLv2IdentityProvider<SAMLv2IdPInitiatedApplicationConfiguration>
 *
 * @property {string} [issuer]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} LoginResponse
 *
 * @property {Array<LoginPreventedResponse>} [actions]
 * @property {string} [changePasswordId]
 * @property {ChangePasswordReason} [changePasswordReason]
 * @property {Array<string>} [configurableMethods]
 * @property {string} [emailVerificationId]
 * @property {Array<TwoFactorMethod>} [methods]
 * @property {string} [pendingIdPLinkId]
 * @property {string} [refreshToken]
 * @property {UUIDString} [refreshTokenId]
 * @property {string} [registrationVerificationId]
 * @property {Object<string, Object>} [state]
 * @property {Object<AuthenticationThreats>} [threatsDetected]
 * @property {string} [token]
 * @property {number} [tokenExpirationInstant]
 * @property {string} [trustToken]
 * @property {string} [twoFactorId]
 * @property {string} [twoFactorTrustId]
 * @property {User} [user]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ReactorResponse
 *
 * @property {ReactorStatus} [status]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} BaseElasticSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {boolean} [accurateTotal]
 * @property {Array<UUIDString>} [ids]
 * @property {string} [nextResults]
 * @property {string} [query]
 * @property {string} [queryString]
 * @property {Array<SortField>} [sortFields]
 */


/**
 * The user action response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ActionResponse
 *
 * @property {UserActionLog} [action]
 * @property {Array<UserActionLog>} [actions]
 */


/**
 * Models the Group Create Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupCreateEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 */


/**
 * Models an entity that a user can be granted permissions to. Or an entity that can be granted permissions to another entity.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} Entity
 *
 * @property {string} [clientId]
 * @property {string} [clientSecret]
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {UUIDString} [parentId]
 * @property {UUIDString} [tenantId]
 * @property {EntityType} [type]
 */


/**
 * @readonly
 * @enum
 */
var FamilyRole = {
  Child: 'Child',
  Teen: 'Teen',
  Adult: 'Adult'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SortField
 *
 * @property {string} [missing]
 * @property {string} [name]
 * @property {Sort} [order]
 */


/**
 * Entity Type API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityTypeResponse
 *
 * @property {EntityType} [entityType]
 * @property {Array<EntityType>} [entityTypes]
 * @property {EntityTypePermission} [permission]
 */


/**
 * @typedef {Object} LambdaConfiguration
 *
 * @property {UUIDString} [reconcileId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ReactorMetricsResponse
 *
 * @property {ReactorMetrics} [metrics]
 */


/**
 * Steam API modes.
 *
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var SteamAPIMode = {
  Public: 'Public',
  Partner: 'Partner'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderRequest
 *
 * @property {BaseIdentityProvider<Object>} [identityProvider]
 */


/**
 * Search criteria for the event log.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EventLogSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {number} [end]
 * @property {string} [message]
 * @property {number} [start]
 * @property {EventLogType} [type]
 */


/**
 * Search request for email templates
 *
 * @author Mark Manes
 *
 * @typedef {Object} EmailTemplateSearchRequest
 *
 * @property {EmailTemplateSearchCriteria} [search]
 */


/**
 * Models the User Registration Verified Event.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} UserRegistrationVerifiedEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * The Integration Request
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} IntegrationRequest
 *
 * @property {Integrations} [integrations]
 */


/**
 * @typedef {Object} AuditLogConfiguration
 *
 * @property {DeleteConfiguration} [delete]
 */


/**
 * @author Lyle Schemmerling
 *
 * @typedef {Object} SAMLv2AssertionConfiguration
 *
 * @property {SAMLv2DestinationAssertionConfiguration} [destination]
 */


/**
 * Google social login provider parameters.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GoogleIdentityProviderProperties
 *
 * @property {string} [api]
 * @property {string} [button]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ApplicationAccessControlConfiguration
 *
 * @property {UUIDString} [uiIPAccessControlListId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TestEvent
 * @extends BaseEvent
 *
 * @property {string} [message]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} Tenantable
 *
 */


/**
 * This class is the entity query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntitySearchCriteria
 * @extends BaseElasticSearchCriteria
 *
 */


/**
 * Event log response.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} EventLogResponse
 *
 * @property {EventLog} [eventLog]
 */


/**
 * Search criteria for Keys
 *
 * @author Spencer Witt
 *
 * @typedef {Object} KeySearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {KeyAlgorithm} [algorithm]
 * @property {string} [name]
 * @property {KeyType} [type]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RefreshTokenSlidingWindowConfiguration
 *
 * @property {number} [maximumTimeToLiveInMinutes]
 */


/**
 * Events that are bound to applications.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ApplicationEvent
 *
 */


/**
 * Forgot password response object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ForgotPasswordResponse
 *
 * @property {string} [changePasswordId]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} LoginRecordSearchRequest
 *
 * @property {boolean} [retrieveTotal]
 * @property {LoginRecordSearchCriteria} [search]
 */


/**
 * API response for retrieving Refresh Tokens
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} RefreshTokenResponse
 *
 * @property {RefreshToken} [refreshToken]
 * @property {Array<RefreshToken>} [refreshTokens]
 */


/**
 * Models the Group Update Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupUpdateEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Group} [original]
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} NintendoApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [emailClaim]
 * @property {string} [scope]
 * @property {string} [uniqueIdClaim]
 * @property {string} [usernameClaim]
 */


/**
 * Models an LDAP connector.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} LDAPConnectorConfiguration
 * @extends BaseConnectorConfiguration
 *
 * @property {string} [authenticationURL]
 * @property {string} [baseStructure]
 * @property {number} [connectTimeout]
 * @property {string} [identifyingAttribute]
 * @property {LambdaConfiguration} [lambdaConfiguration]
 * @property {string} [loginIdAttribute]
 * @property {number} [readTimeout]
 * @property {Array<string>} [requestedAttributes]
 * @property {LDAPSecurityMethod} [securityMethod]
 * @property {string} [systemAccountDN]
 * @property {string} [systemAccountPassword]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} DeviceUserCodeResponse
 *
 * @property {string} [client_id]
 * @property {DeviceInfo} [deviceInfo]
 * @property {number} [expires_in]
 * @property {PendingIdPLink} [pendingIdPLink]
 * @property {string} [scope]
 * @property {UUIDString} [tenantId]
 * @property {string} [user_code]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} OpenIdConnectIdentityProvider
 * @extends BaseIdentityProvider<OpenIdConnectApplicationConfiguration>
 *
 * @property {string} [buttonImageURL]
 * @property {string} [buttonText]
 * @property {Object<string>} [domains]
 * @property {IdentityProviderOauth2Configuration} [oauth2]
 * @property {boolean} [postRequest]
 */


/**
 * @typedef {Object} LambdaConfiguration
 *
 * @property {UUIDString} [reconcileId]
 */


/**
 * Models the User Bulk Create Event.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserBulkCreateEvent
 * @extends BaseEvent
 *
 * @property {Array<User>} [users]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWTVendRequest
 *
 * @property {Object<string, Object>} [claims]
 * @property {UUIDString} [keyId]
 * @property {number} [timeToLiveInSeconds]
 */


/**
 * Models a User consent.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserConsent
 *
 * @property {Consent} [consent]
 * @property {UUIDString} [consentId]
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [giverUserId]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {ConsentStatus} [status]
 * @property {UUIDString} [userId]
 * @property {Array<string>} [values]
 */


/**
 * A displayable raw login that includes application name and user loginId.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} DisplayableRawLogin
 * @extends RawLogin
 *
 * @property {string} [applicationName]
 * @property {Location} [location]
 * @property {string} [loginId]
 */


/**
 * Search response for Themes
 *
 * @author Mark Manes
 *
 * @typedef {Object} ThemeSearchResponse
 *
 * @property {Array<Theme>} [themes]
 * @property {number} [total]
 */


/**
 * @typedef {Object} TwoFactorTrust
 *
 * @property {UUIDString} [applicationId]
 * @property {number} [expiration]
 * @property {number} [startInstant]
 */


/**
 * Models the User Identity Provider Unlink Event.
 *
 * @author Rob Davis
 *
 * @typedef {Object} UserIdentityProviderUnlinkEvent
 * @extends BaseEvent
 *
 * @property {IdentityProviderLink} [identityProviderLink]
 * @property {User} [user]
 */


/**
 * @author Derek Klatt
 *
 * @typedef {Object} PasswordValidationRules
 *
 * @property {PasswordBreachDetection} [breachDetection]
 * @property {number} [maxLength]
 * @property {number} [minLength]
 * @property {RememberPreviousPasswords} [rememberPreviousPasswords]
 * @property {boolean} [requireMixedCase]
 * @property {boolean} [requireNonAlpha]
 * @property {boolean} [requireNumber]
 * @property {boolean} [validateOnLogin]
 */


/**
 * Models the Group Update Complete Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupUpdateCompleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 * @property {Group} [original]
 */


/**
 * Models a specific entity type permission. This permission can be granted to users or other entities.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityTypePermission
 *
 * @property {Object<string, Object>} [data]
 * @property {string} [description]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {boolean} [isDefault]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 */


/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} MonthlyActiveUserReportResponse
 *
 * @property {Array<Count>} [monthlyActiveUsers]
 * @property {number} [total]
 */


/**
 * @author Brett Guy
 *
 * @readonly
 * @enum
 */
var ClientAuthenticationPolicy = {
  Required: 'Required',
  NotRequired: 'NotRequired',
  NotRequiredWhenUsingPKCE: 'NotRequiredWhenUsingPKCE'
};

/**
 * Event event to an audit log was created.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} AuditLogCreateEvent
 * @extends BaseEvent
 *
 * @property {AuditLog} [auditLog]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantUsernameConfiguration
 *
 * @property {UniqueUsernameConfiguration} [unique]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorMethod
 *
 * @property {AuthenticatorConfiguration} [authenticator]
 * @property {string} [email]
 * @property {string} [id]
 * @property {boolean} [lastUsed]
 * @property {string} [method]
 * @property {string} [mobilePhone]
 * @property {string} [secret]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantUnverifiedConfiguration
 *
 * @property {UnverifiedBehavior} [email]
 * @property {RegistrationUnverifiedOptions} [whenGated]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorSendRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [email]
 * @property {string} [method]
 * @property {string} [methodId]
 * @property {string} [mobilePhone]
 * @property {UUIDString} [userId]
 */


/**
 * Models content user action options.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserActionOption
 *
 * @property {LocalizedStrings} [localizedNames]
 * @property {string} [name]
 */


/**
 * The transaction types for Webhooks and other event systems within FusionAuth.
 *
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var TransactionType = {
  None: 'None',
  Any: 'Any',
  SimpleMajority: 'SimpleMajority',
  SuperMajority: 'SuperMajority',
  AbsoluteMajority: 'AbsoluteMajority'
};

/**
 * The Application API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ApplicationRequest
 * @extends BaseEventRequest
 *
 * @property {Application} [application]
 * @property {ApplicationRole} [role]
 * @property {UUIDString} [sourceApplicationId]
 */


/**

 *
 * @typedef {Object} BaseIdentityProvider
 * @template {D}
 * @extends Enableable
 *
 * @property {Object<UUIDString, D>} [applicationConfiguration]
 * @property {Object<string, Object>} [data]
 * @property {boolean} [debug]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {LambdaConfiguration} [lambdaConfiguration]
 * @property {number} [lastUpdateInstant]
 * @property {IdentityProviderLinkingStrategy} [linkingStrategy]
 * @property {string} [name]
 * @property {Object<UUIDString, IdentityProviderTenantConfiguration>} [tenantConfiguration]
 * @property {IdentityProviderType} [type]
 */


/**
 * Describes a user account or WebAuthn Relying Party associated with a public key credential
 *
 * @typedef {Object} PublicKeyCredentialEntity
 *
 * @property {string} [name]
 */


/**
 * Models the User Update Registration Event.
 * <p>
 * This is different than user.registration.update in that it is sent after this event completes, this cannot be transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserRegistrationUpdateCompleteEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [original]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} AuditLogSearchResponse
 *
 * @property {Array<AuditLog>} [auditLogs]
 * @property {number} [total]
 */


/**
 * COSE key type
 *
 * @author Spencer Witt
 *
 * @readonly
 * @enum
 */
var CoseKeyType = {
  Reserved: '0',
  OKP: '1',
  EC2: '2',
  RSA: '3',
  Symmetric: '4'
};

/**
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var ExpiryUnit = {
  MINUTES: 'MINUTES',
  HOURS: 'HOURS',
  DAYS: 'DAYS',
  WEEKS: 'WEEKS',
  MONTHS: 'MONTHS',
  YEARS: 'YEARS'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} KafkaConfiguration
 * @extends Enableable
 *
 * @property {string} [defaultTopic]
 * @property {Object<string, string>} [producer]
 */


/**
 * Contains the output for the {@code credProps} extension
 *
 * @author Spencer Witt
 *
 * @typedef {Object} CredentialPropertiesOutput
 *
 * @property {boolean} [rk]
 */


/**
 * An action that can be executed on a user (discipline or reward potentially).
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserAction
 *
 * @property {boolean} [active]
 * @property {UUIDString} [cancelEmailTemplateId]
 * @property {UUIDString} [endEmailTemplateId]
 * @property {UUIDString} [id]
 * @property {boolean} [includeEmailInEventJSON]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {LocalizedStrings} [localizedNames]
 * @property {UUIDString} [modifyEmailTemplateId]
 * @property {string} [name]
 * @property {Array<UserActionOption>} [options]
 * @property {boolean} [preventLogin]
 * @property {boolean} [sendEndEvent]
 * @property {UUIDString} [startEmailTemplateId]
 * @property {boolean} [temporal]
 * @property {TransactionType} [transactionType]
 * @property {boolean} [userEmailingEnabled]
 * @property {boolean} [userNotificationsEnabled]
 */


/**
 * An audit log.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} AuditLog
 *
 * @property {Object<string, Object>} [data]
 * @property {number} [id]
 * @property {number} [insertInstant]
 * @property {string} [insertUser]
 * @property {string} [message]
 * @property {Object} [newValue]
 * @property {Object} [oldValue]
 * @property {string} [reason]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderTenantConfiguration
 *
 * @property {Object<string, Object>} [data]
 * @property {IdentityProviderLimitUserLinkingPolicy} [limitUserLinkCount]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} AuthenticatorConfiguration
 *
 * @property {TOTPAlgorithm} [algorithm]
 * @property {number} [codeLength]
 * @property {number} [timeStep]
 */


/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} RegistrationRequest
 * @extends BaseEventRequest
 *
 * @property {boolean} [disableDomainBlock]
 * @property {boolean} [generateAuthenticationToken]
 * @property {UserRegistration} [registration]
 * @property {boolean} [sendSetPasswordEmail]
 * @property {boolean} [skipRegistrationVerification]
 * @property {boolean} [skipVerification]
 * @property {User} [user]
 */


/**
 * JSON Web Token (JWT) as defined by RFC 7519.
 * <pre>
 * From RFC 7519 Section 1. Introduction:
 *    The suggested pronunciation of JWT is the same as the English word "jot".
 * </pre>
 * The JWT is not Thread-Safe and should not be re-used.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} JWT | object
 *
 * @property {Object} [aud]
 * @property {number} [exp]
 * @property {number} [iat]
 * @property {string} [iss]
 * @property {string} [jti]
 * @property {number} [nbf]
 * @property {string} [sub]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} IPAccessControlListSearchResponse
 *
 * @property {Array<IPAccessControlList>} [ipAccessControlLists]
 * @property {number} [total]
 */


/**
 * Login API request object used for login to third-party systems (i.e. Login with Facebook).
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} IdentityProviderLoginRequest
 * @extends BaseLoginRequest
 *
 * @property {Object<string, string>} [data]
 * @property {string} [encodedJWT]
 * @property {UUIDString} [identityProviderId]
 * @property {boolean} [noLink]
 */


/**
 * A Application-level policy for deleting Users.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} ApplicationRegistrationDeletePolicy
 *
 * @property {TimeBasedDeletePolicy} [unverified]
 */


/**
 * Models an entity type that has a specific set of permissions. These are global objects and can be used across tenants.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityType
 *
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {EntityJWTConfiguration} [jwtConfiguration]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {Array<EntityTypePermission>} [permissions]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} FormStep
 *
 * @property {Array<UUIDString>} [fields]
 */


/**
 * Lambda API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} LambdaRequest
 *
 * @property {Lambda} [lambda]
 */


/**
 * API response for consent.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ConsentResponse
 *
 * @property {Consent} [consent]
 * @property {Array<Consent>} [consents]
 */


/**
 * Xbox gaming login provider.
 *
 * @author Brett Pontarelli
 *
 * @typedef {Object} XboxIdentityProvider
 * @extends BaseIdentityProvider<XboxApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} ApplicationMultiFactorConfiguration
 *
 * @property {MultiFactorEmailTemplate} [email]
 * @property {MultiFactorLoginPolicy} [loginPolicy]
 * @property {MultiFactorSMSTemplate} [sms]
 * @property {ApplicationMultiFactorTrustPolicy} [trustPolicy]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} SystemConfiguration
 *
 * @property {AuditLogConfiguration} [auditLogConfiguration]
 * @property {CORSConfiguration} [corsConfiguration]
 * @property {Object<string, Object>} [data]
 * @property {EventLogConfiguration} [eventLogConfiguration]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {LoginRecordConfiguration} [loginRecordConfiguration]
 * @property {string} [reportTimezone]
 * @property {SystemTrustedProxyConfiguration} [trustedProxyConfiguration]
 * @property {UIConfiguration} [uiConfiguration]
 */


/**
 * Interface describing the need for CORS configuration.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} RequiresCORSConfiguration
 *
 */


/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 * <p>
 * This is different than user.delete because it is sent after the tx is committed, this cannot be transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserDeleteCompleteEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorLoginRequest
 * @extends BaseLoginRequest
 *
 * @property {string} [code]
 * @property {boolean} [trustComputer]
 * @property {string} [twoFactorId]
 * @property {UUIDString} [userId]
 */


/**
 * A custom OAuth scope for a specific application.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ApplicationOAuthScope
 *
 * @property {UUIDString} [applicationId]
 * @property {Object<string, Object>} [data]
 * @property {string} [defaultConsentDetail]
 * @property {string} [defaultConsentMessage]
 * @property {string} [description]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {boolean} [required]
 */


/**
 * @typedef {Object} ActionData
 *
 * @property {UUIDString} [actioneeUserId]
 * @property {UUIDString} [actionerUserId]
 * @property {Array<UUIDString>} [applicationIds]
 * @property {string} [comment]
 * @property {boolean} [emailUser]
 * @property {number} [expiry]
 * @property {boolean} [notifyUser]
 * @property {string} [option]
 * @property {UUIDString} [reasonId]
 * @property {UUIDString} [userActionId]
 */


/**
 * Search request for user comments
 *
 * @author Spencer Witt
 *
 * @typedef {Object} UserCommentSearchRequest
 *
 * @property {UserCommentSearchCriteria} [search]
 */


/**
 * Models the FusionAuth connector.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} FusionAuthConnectorConfiguration
 * @extends BaseConnectorConfiguration
 *
 */


/**
 * @author Brett Pontarelli
 *
 * @readonly
 * @enum
 */
var IdentityProviderLoginMethod = {
  UsePopup: 'UsePopup',
  UseRedirect: 'UseRedirect',
  UseVendorJavaScript: 'UseVendorJavaScript'
};

/**
 * The <i>authenticator's</i> response for the registration ceremony in its encoded format
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnAuthenticatorRegistrationResponse
 *
 * @property {string} [attestationObject]
 * @property {string} [clientDataJSON]
 */


/**
 * @readonly
 * @enum
 */
var TOTPAlgorithm = {
  HmacSHA1: 'HmacSHA1',
  HmacSHA256: 'HmacSHA256',
  HmacSHA512: 'HmacSHA512'
};

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserConsentResponse
 *
 * @property {UserConsent} [userConsent]
 * @property {Array<UserConsent>} [userConsents]
 */


/**
 * Models an event where a user is being created with an "in-use" login Id (email or username).
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserLoginIdDuplicateOnCreateEvent
 * @extends BaseEvent
 *
 * @property {string} [duplicateEmail]
 * @property {string} [duplicateUsername]
 * @property {User} [existing]
 * @property {User} [user]
 */


/**
 * Consent search response
 *
 * @author Spencer Witt
 *
 * @typedef {Object} ConsentSearchResponse
 *
 * @property {Array<Consent>} [consents]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TwoFactorRecoveryCodeResponse
 *
 * @property {Array<string>} [recoveryCodes]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantRequest
 * @extends BaseEventRequest
 *
 * @property {UUIDString} [sourceTenantId]
 * @property {Tenant} [tenant]
 * @property {Array<UUIDString>} [webhookIds]
 */


/**
 * API request to start a WebAuthn authentication ceremony
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnStartRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {UUIDString} [credentialId]
 * @property {string} [loginId]
 * @property {Object<string, Object>} [state]
 * @property {UUIDString} [userId]
 * @property {WebAuthnWorkflow} [workflow]
 */


/**
 * Google social login provider.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GoogleIdentityProvider
 * @extends BaseIdentityProvider<GoogleApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {IdentityProviderLoginMethod} [loginMethod]
 * @property {GoogleIdentityProviderProperties} [properties]
 * @property {string} [scope]
 */


/**
 * API response for completing WebAuthn assertion
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnAssertResponse
 *
 * @property {WebAuthnCredential} [credential]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RefreshTokenRevocationPolicy
 *
 * @property {boolean} [onLoginPrevented]
 * @property {boolean} [onMultiFactorEnable]
 * @property {boolean} [onPasswordChanged]
 */


/**
 * Entity API response object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityResponse
 *
 * @property {Entity} [entity]
 */


/**
 * @author andrewpai
 *
 * @typedef {Object} SelfServiceFormConfiguration
 *
 * @property {boolean} [requireCurrentPasswordOnPasswordChange]
 */


/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} Consent
 *
 * @property {UUIDString} [consentEmailTemplateId]
 * @property {LocalizedIntegers} [countryMinimumAgeForSelfConsent]
 * @property {Object<string, Object>} [data]
 * @property {number} [defaultMinimumAgeForSelfConsent]
 * @property {EmailPlus} [emailPlus]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {boolean} [multipleValuesAllowed]
 * @property {string} [name]
 * @property {Array<string>} [values]
 */


/**
 * @author Tyler Scott
 *
 * @typedef {Object} Group
 *
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {Object<UUIDString, Array<ApplicationRole>>} [roles]
 * @property {UUIDString} [tenantId]
 */


/**
 * @author Trevor Smith
 *
 * @typedef {Object} ConnectorRequest
 *
 * @property {BaseConnectorConfiguration} [connector]
 */


/**
 * Response for the system configuration API.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SystemConfigurationResponse
 *
 * @property {SystemConfiguration} [systemConfiguration]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} GoogleApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {IdentityProviderLoginMethod} [loginMethod]
 * @property {GoogleIdentityProviderProperties} [properties]
 * @property {string} [scope]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} BaseSearchCriteria
 *
 * @property {number} [numberOfResults]
 * @property {string} [orderBy]
 * @property {number} [startRow]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var FormFieldAdminPolicy = {
  Edit: 'Edit',
  View: 'View'
};

/**
 * @readonly
 * @enum
 */
var UniqueUsernameStrategy = {
  Always: 'Always',
  OnCollision: 'OnCollision'
};

/**
 * Models the User Deleted Registration Event.
 * <p>
 * This is different than user.registration.delete in that it is sent after the TX has been committed. This event cannot be transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserRegistrationDeleteCompleteEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * The Integration Response
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} IntegrationResponse
 *
 * @property {Integrations} [integrations]
 */


/**
 * The Application API response.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ApplicationResponse
 *
 * @property {Application} [application]
 * @property {Array<Application>} [applications]
 * @property {ApplicationRole} [role]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} FamilyConfiguration
 * @extends Enableable
 *
 * @property {boolean} [allowChildRegistrations]
 * @property {UUIDString} [confirmChildEmailTemplateId]
 * @property {boolean} [deleteOrphanedAccounts]
 * @property {number} [deleteOrphanedAccountsDays]
 * @property {UUIDString} [familyRequestEmailTemplateId]
 * @property {number} [maximumChildAge]
 * @property {number} [minimumOwnerAge]
 * @property {boolean} [parentEmailRequired]
 * @property {UUIDString} [parentRegistrationEmailTemplateId]
 */


/**
 * @author Brian Pontarelli
 *
 * @typedef {Object} AuditLogSearchRequest
 *
 * @property {AuditLogSearchCriteria} [search]
 */


/**
 * Provides the <i>authenticator</i> with the data it needs to generate an assertion.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} PublicKeyCredentialRequestOptions
 *
 * @property {Array<PublicKeyCredentialDescriptor>} [allowCredentials]
 * @property {string} [challenge]
 * @property {string} [rpId]
 * @property {number} [timeout]
 * @property {UserVerificationRequirement} [userVerification]
 */


/**
 * @typedef {Object} DeleteConfiguration
 * @extends Enableable
 *
 * @property {number} [numberOfDaysToRetain]
 */


/**
 * Request to complete the WebAuthn registration ceremony
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnLoginRequest
 * @extends BaseLoginRequest
 *
 * @property {WebAuthnPublicKeyAuthenticationRequest} [credential]
 * @property {string} [origin]
 * @property {string} [rpId]
 * @property {string} [twoFactorTrustId]
 */


/**
 * Request for the system configuration API.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} SystemConfigurationRequest
 *
 * @property {SystemConfiguration} [systemConfiguration]
 */


/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var UserState = {
  Authenticated: 'Authenticated',
  AuthenticatedNotRegistered: 'AuthenticatedNotRegistered',
  AuthenticatedNotVerified: 'AuthenticatedNotVerified',
  AuthenticatedRegistrationNotVerified: 'AuthenticatedRegistrationNotVerified'
};

/**
 * @author Daniel DeGroff
 *
 * @readonly
 * @enum
 */
var SecureGeneratorType = {
  randomDigits: 'randomDigits',
  randomBytes: 'randomBytes',
  randomAlpha: 'randomAlpha',
  randomAlphaNumeric: 'randomAlphaNumeric'
};

/**
 * A Tenant-level policy for deleting Users.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} TenantUserDeletePolicy
 *
 * @property {TimeBasedDeletePolicy} [unverified]
 */


/**
 * domain POJO to represent AuthenticationKey
 *
 * @author sanjay
 *
 * @typedef {Object} APIKey
 *
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {UUIDString} [ipAccessControlListId]
 * @property {string} [key]
 * @property {boolean} [keyManager]
 * @property {number} [lastUpdateInstant]
 * @property {APIKeyMetaData} [metaData]
 * @property {APIKeyPermissions} [permissions]
 * @property {UUIDString} [tenantId]
 */


/**
 * @author Brian Pontarelli
 *
 * @readonly
 * @enum
 */
var ReactorFeatureStatus = {
  ACTIVE: 'ACTIVE',
  DISCONNECTED: 'DISCONNECTED',
  PENDING: 'PENDING',
  DISABLED: 'DISABLED',
  UNKNOWN: 'UNKNOWN'
};

/**
 * Reindex API request
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ReindexRequest
 *
 * @property {string} [index]
 */


/**
 * Search response for entity types.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} EntityTypeSearchResponse
 *
 * @property {Array<EntityType>} [entityTypes]
 * @property {number} [total]
 */


/**
 * A role given to a user for a specific application.
 *
 * @author Seth Musselman
 *
 * @typedef {Object} ApplicationRole
 *
 * @property {string} [description]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {boolean} [isDefault]
 * @property {boolean} [isSuperRole]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} TenantRegistrationConfiguration
 *
 * @property {Object<string>} [blockedDomains]
 */


/**
 * Key API response object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} KeyResponse
 *
 * @property {Key} [key]
 * @property {Array<Key>} [keys]
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} SteamApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {SteamAPIMode} [apiMode]
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [scope]
 * @property {string} [webAPIKey]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} TwoFactorStartRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [code]
 * @property {string} [loginId]
 * @property {Object<string, Object>} [state]
 * @property {string} [trustChallenge]
 * @property {UUIDString} [userId]
 */


/**
 * Models the User Update Registration Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserRegistrationUpdateEvent
 * @extends BaseEvent
 *
 * @property {UUIDString} [applicationId]
 * @property {UserRegistration} [original]
 * @property {UserRegistration} [registration]
 * @property {User} [user]
 */


/**
 * Search response for Group Members
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberSearchResponse
 *
 * @property {Array<GroupMember>} [members]
 * @property {number} [total]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderLinkRequest
 * @extends BaseEventRequest
 *
 * @property {IdentityProviderLink} [identityProviderLink]
 * @property {string} [pendingIdPLinkId]
 */


/**
 * Used by the Relying Party to specify their requirements for authenticator attributes. Fields use the deprecated "resident key" terminology to refer
 * to client-side discoverable credentials to maintain backwards compatibility with WebAuthn Level 1.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} AuthenticatorSelectionCriteria
 *
 * @property {AuthenticatorAttachment} [authenticatorAttachment]
 * @property {boolean} [requireResidentKey]
 * @property {ResidentKeyRequirement} [residentKey]
 * @property {UserVerificationRequirement} [userVerification]
 */


/**
 * Form response.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} FormResponse
 *
 * @property {Form} [form]
 * @property {Array<Form>} [forms]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} HYPRIdentityProvider
 * @extends BaseIdentityProvider<HYPRApplicationConfiguration>
 *
 * @property {string} [relyingPartyApplicationId]
 * @property {string} [relyingPartyURL]
 */


/**
 * Group API response object.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupResponse
 *
 * @property {Group} [group]
 * @property {Array<Group>} [groups]
 */


/**
 * Request to register a new public key with WebAuthn
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnPublicKeyRegistrationRequest
 *
 * @property {WebAuthnExtensionsClientOutputs} [clientExtensionResults]
 * @property {string} [id]
 * @property {WebAuthnAuthenticatorRegistrationResponse} [response]
 * @property {string} [rpId]
 * @property {Array<string>} [transports]
 * @property {string} [type]
 */


/**
 * Models the Group Create Complete Event.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupDeleteCompleteEvent
 * @extends BaseEvent
 *
 * @property {Group} [group]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RegistrationUnverifiedOptions
 *
 * @property {UnverifiedBehavior} [behavior]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderPendingLinkResponse
 *
 * @property {IdentityProviderTenantConfiguration} [identityProviderTenantConfiguration]
 * @property {number} [linkCount]
 * @property {PendingIdPLink} [pendingIdPLink]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} PasswordlessSendRequest
 *
 * @property {UUIDString} [applicationId]
 * @property {string} [code]
 * @property {string} [loginId]
 * @property {Object<string, Object>} [state]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} GenericMessengerConfiguration
 * @extends BaseMessengerConfiguration
 *
 * @property {number} [connectTimeout]
 * @property {HTTPHeaders} [headers]
 * @property {string} [httpAuthenticationPassword]
 * @property {string} [httpAuthenticationUsername]
 * @property {number} [readTimeout]
 * @property {string} [sslCertificate]
 * @property {string} [url]
 */


/**
 * API request to import an existing WebAuthn credential(s)
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnCredentialImportRequest
 *
 * @property {Array<WebAuthnCredential>} [credentials]
 * @property {boolean} [validateDbConstraints]
 */


/**
 * @typedef {Object} Templates
 *
 * @property {string} [accountEdit]
 * @property {string} [accountIndex]
 * @property {string} [accountTwoFactorDisable]
 * @property {string} [accountTwoFactorEnable]
 * @property {string} [accountTwoFactorIndex]
 * @property {string} [accountWebAuthnAdd]
 * @property {string} [accountWebAuthnDelete]
 * @property {string} [accountWebAuthnIndex]
 * @property {string} [confirmationRequired]
 * @property {string} [emailComplete]
 * @property {string} [emailSend]
 * @property {string} [emailSent]
 * @property {string} [emailVerificationRequired]
 * @property {string} [emailVerify]
 * @property {string} [helpers]
 * @property {string} [index]
 * @property {string} [oauth2Authorize]
 * @property {string} [oauth2AuthorizedNotRegistered]
 * @property {string} [oauth2ChildRegistrationNotAllowed]
 * @property {string} [oauth2ChildRegistrationNotAllowedComplete]
 * @property {string} [oauth2CompleteRegistration]
 * @property {string} [oauth2Consent]
 * @property {string} [oauth2Device]
 * @property {string} [oauth2DeviceComplete]
 * @property {string} [oauth2Error]
 * @property {string} [oauth2Logout]
 * @property {string} [oauth2Passwordless]
 * @property {string} [oauth2Register]
 * @property {string} [oauth2StartIdPLink]
 * @property {string} [oauth2TwoFactor]
 * @property {string} [oauth2TwoFactorEnable]
 * @property {string} [oauth2TwoFactorEnableComplete]
 * @property {string} [oauth2TwoFactorMethods]
 * @property {string} [oauth2Wait]
 * @property {string} [oauth2WebAuthn]
 * @property {string} [oauth2WebAuthnReauth]
 * @property {string} [oauth2WebAuthnReauthEnable]
 * @property {string} [passwordChange]
 * @property {string} [passwordComplete]
 * @property {string} [passwordForgot]
 * @property {string} [passwordSent]
 * @property {string} [registrationComplete]
 * @property {string} [registrationSend]
 * @property {string} [registrationSent]
 * @property {string} [registrationVerificationRequired]
 * @property {string} [registrationVerify]
 * @property {string} [samlv2Logout]
 * @property {string} [unauthorized]
 */


/**
 * Nintendo gaming login provider.
 *
 * @author Brett Pontarelli
 *
 * @typedef {Object} NintendoIdentityProvider
 * @extends BaseIdentityProvider<NintendoApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [emailClaim]
 * @property {string} [scope]
 * @property {string} [uniqueIdClaim]
 * @property {string} [usernameClaim]
 */


/**
 * @author Brett Guy
 *
 * @typedef {Object} TwilioMessengerConfiguration
 * @extends BaseMessengerConfiguration
 *
 * @property {string} [accountSID]
 * @property {string} [authToken]
 * @property {string} [fromPhoneNumber]
 * @property {string} [messagingServiceSid]
 * @property {string} [url]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} FormField
 *
 * @property {boolean} [confirm]
 * @property {UUIDString} [consentId]
 * @property {FormControl} [control]
 * @property {Object<string, Object>} [data]
 * @property {string} [description]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {string} [key]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {Array<string>} [options]
 * @property {boolean} [required]
 * @property {FormDataType} [type]
 * @property {FormFieldValidator} [validator]
 */


/**
 * Twitch gaming login provider.
 *
 * @author Brett Pontarelli
 *
 * @typedef {Object} TwitchIdentityProvider
 * @extends BaseIdentityProvider<TwitchApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * @author Michael Sleevi
 *
 * @typedef {Object} PreviewMessageTemplateRequest
 *
 * @property {string} [locale]
 * @property {MessageTemplate} [messageTemplate]
 */


/**
 * Stores an message template used to distribute messages;
 *
 * @author Michael Sleevi
 *
 * @typedef {Object} MessageTemplate
 *
 * @property {Object<string, Object>} [data]
 * @property {UUIDString} [id]
 * @property {number} [insertInstant]
 * @property {number} [lastUpdateInstant]
 * @property {string} [name]
 * @property {MessageType} [type]
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} TenantCaptchaConfiguration
 * @extends Enableable
 *
 * @property {CaptchaMethod} [captchaMethod]
 * @property {string} [secretKey]
 * @property {string} [siteKey]
 * @property {number} [threshold]
 */


/**
 * Models the User Reactivate Event.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserReactivateEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * Models the User Create Event.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserCreateEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * @typedef {Object} HistoryItem
 *
 * @property {UUIDString} [actionerUserId]
 * @property {string} [comment]
 * @property {number} [createInstant]
 * @property {number} [expiry]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderLink
 *
 * @property {Object<string, Object>} [data]
 * @property {string} [displayName]
 * @property {UUIDString} [identityProviderId]
 * @property {string} [identityProviderName]
 * @property {IdentityProviderType} [identityProviderType]
 * @property {string} [identityProviderUserId]
 * @property {number} [insertInstant]
 * @property {number} [lastLoginInstant]
 * @property {UUIDString} [tenantId]
 * @property {string} [token]
 * @property {UUIDString} [userId]
 */


/**
 * @author Seth Musselman
 *
 * @typedef {Object} PreviewResponse
 *
 * @property {Email} [email]
 * @property {Errors} [errors]
 */


/**
 * Supply additional information about the user account when creating a new credential
 *
 * @author Spencer Witt
 *
 * @typedef {Object} PublicKeyCredentialUserEntity
 * @extends PublicKeyCredentialEntity
 *
 * @property {string} [displayName]
 * @property {string} [id]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} RefreshResponse
 *
 */


/**
 * User API delete request object for a single user.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} UserDeleteSingleRequest
 * @extends BaseEventRequest
 *
 * @property {boolean} [hardDelete]
 */


/**
 * Application-level configuration for WebAuthn
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ApplicationWebAuthnConfiguration
 * @extends Enableable
 *
 * @property {ApplicationWebAuthnWorkflowConfiguration} [bootstrapWorkflow]
 * @property {ApplicationWebAuthnWorkflowConfiguration} [reauthenticationWorkflow]
 */


/**
 * A Message Template Request to the API
 *
 * @author Michael Sleevi
 *
 * @typedef {Object} MessageTemplateRequest
 *
 * @property {MessageTemplate} [messageTemplate]
 */


/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} RegistrationResponse
 *
 * @property {string} [refreshToken]
 * @property {UserRegistration} [registration]
 * @property {string} [registrationVerificationId]
 * @property {string} [registrationVerificationOneTimeCode]
 * @property {string} [token]
 * @property {number} [tokenExpirationInstant]
 * @property {User} [user]
 */


/**
 * @author Brett Guy
 *
 * @readonly
 * @enum
 */
var MessengerType = {
  Generic: 'Generic',
  Kafka: 'Kafka',
  Twilio: 'Twilio'
};

/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} SecretResponse
 *
 * @property {string} [secret]
 * @property {string} [secretBase32Encoded]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IntrospectResponse
 * @extends Object<string, Object>
 *
 */


/**
 * Search request for Group Members.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} GroupMemberSearchRequest
 *
 * @property {GroupMemberSearchCriteria} [search]
 */


/**
 * @author Rob Davis
 *
 * @typedef {Object} TenantLambdaConfiguration
 *
 * @property {UUIDString} [scimEnterpriseUserRequestConverterId]
 * @property {UUIDString} [scimEnterpriseUserResponseConverterId]
 * @property {UUIDString} [scimGroupRequestConverterId]
 * @property {UUIDString} [scimGroupResponseConverterId]
 * @property {UUIDString} [scimUserRequestConverterId]
 * @property {UUIDString} [scimUserResponseConverterId]
 */


/**
 * Search criteria for webhooks.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebhookSearchCriteria
 * @extends BaseSearchCriteria
 *
 * @property {string} [description]
 * @property {UUIDString} [tenantId]
 * @property {string} [url]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} BaseIdentityProviderApplicationConfiguration
 * @extends Enableable
 *
 * @property {boolean} [createRegistration]
 * @property {Object<string, Object>} [data]
 */


/**
 * Configuration for signing webhooks.
 *
 * @author Brent Halsey
 *
 * @typedef {Object} WebhookSignatureConfiguration
 * @extends Enableable
 *
 * @property {UUIDString} [signingKeyId]
 */


/**
 * Import request.
 *
 * @author Brian Pontarelli
 *
 * @typedef {Object} ImportRequest
 * @extends BaseEventRequest
 *
 * @property {string} [encryptionScheme]
 * @property {number} [factor]
 * @property {Array<User>} [users]
 * @property {boolean} [validateDbConstraints]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} MaximumPasswordAge
 * @extends Enableable
 *
 * @property {number} [days]
 */


/**
 * Epic gaming login provider.
 *
 * @author Brett Pontarelli
 *
 * @typedef {Object} EpicGamesIdentityProvider
 * @extends BaseIdentityProvider<EpicGamesApplicationConfiguration>
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * Models the User Email Verify Event.
 *
 * @author Trevor Smith
 *
 * @typedef {Object} UserEmailVerifiedEvent
 * @extends BaseEvent
 *
 * @property {User} [user]
 */


/**
 * An expandable API request.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} ExpandableRequest
 *
 * @property {Array<string>} [expand]
 */


/**
 * Authentication key response object.
 *
 * @author Sanjay
 *
 * @typedef {Object} APIKeyResponse
 *
 * @property {APIKey} [apiKey]
 */


/**
 * @author Daniel DeGroff
 *
 * @typedef {Object} IdentityProviderStartLoginResponse
 *
 * @property {string} [code]
 */


/**
 * Models the User Update Event once it is completed. This cannot be transactional.
 *
 * @author Daniel DeGroff
 *
 * @typedef {Object} UserUpdateCompleteEvent
 * @extends BaseEvent
 *
 * @property {User} [original]
 * @property {User} [user]
 */


/**
 * @author Trevor Smith
 *
 * @typedef {Object} DeviceResponse
 *
 * @property {string} [device_code]
 * @property {number} [expires_in]
 * @property {number} [interval]
 * @property {string} [user_code]
 * @property {string} [verification_uri]
 * @property {string} [verification_uri_complete]
 */


/**
 * @author Brett Pontarelli
 *
 * @typedef {Object} SonyPSNApplicationConfiguration
 * @extends BaseIdentityProviderApplicationConfiguration
 *
 * @property {string} [buttonText]
 * @property {string} [client_id]
 * @property {string} [client_secret]
 * @property {string} [scope]
 */


/**
 * Options to request extensions during credential registration
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnRegistrationExtensionOptions
 *
 * @property {boolean} [credProps]
 */


/**
 * Allows the Relying Party to specify desired attributes of a new credential.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} PublicKeyCredentialCreationOptions
 *
 * @property {AttestationConveyancePreference} [attestation]
 * @property {AuthenticatorSelectionCriteria} [authenticatorSelection]
 * @property {string} [challenge]
 * @property {Array<PublicKeyCredentialDescriptor>} [excludeCredentials]
 * @property {WebAuthnRegistrationExtensionOptions} [extensions]
 * @property {Array<PublicKeyCredentialParameters>} [pubKeyCredParams]
 * @property {PublicKeyCredentialRelyingPartyEntity} [rp]
 * @property {number} [timeout]
 * @property {PublicKeyCredentialUserEntity} [user]
 */


/**
 * Request to complete the WebAuthn registration ceremony for a new credential,.
 *
 * @author Spencer Witt
 *
 * @typedef {Object} WebAuthnRegisterCompleteRequest
 *
 * @property {WebAuthnPublicKeyRegistrationRequest} [credential]
 * @property {string} [origin]
 * @property {string} [rpId]
 * @property {UUIDString} [userId]
 */



module.exports = FusionAuthClient;
