/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.compliance.saml.plugin;

import com.jayway.restassured.response.Response;

/**
 * This interface provides a mechanism for implementers to handle a portion of the SAML IdP
 * interactions that are not constrained by the SAML specification (and are therefore
 * implementation-dependent).
 */
public interface IdpSSOResponder {

  /**
   * The tests will send an AuthnRequest to the IdP using Redirect binding. Then the tests will hand
   * the HTTP response to this method. Then this method is responsible for handling the
   * implementation-dependent interactions that need to occur before successfully authenticating a
   * user and getting the SAML response. Once the SAML response is received, this method should
   * return the RestAssured Response object that contains it.
   *
   * @param originalResponse - the original {@code RestAssured} response from the initial REDIRECT
   *     authn request
   * @return The {@code RestAssured} response containing the SAML response. </pre>
   */
  // TODO When DDF is fixed to return a POST SSO response, change the return type to
  // `IdpPostResponse`
  Response getResponseForRedirectRequest(Response originalResponse);

  /**
   * The tests will send an AuthnRequest to the IdP using POST binding. Then the tests will hand the
   * HTTP response to this method. Then this method is responsible for handling the
   * implementation-dependent interactions that need to occur before successfully authenticating a
   * user and getting the SAML response. Once the SAML response is received, this method should
   * return the RestAssured Response object that contains it.
   *
   * @param originalResponse - the original {@code RestAssured} response from the initial POST authn
   *     request
   * @return The {@code RestAssured} response containing the SAML response. </pre>
   */
  Response getResponseForPostRequest(Response originalResponse);
}
