/**
 * Copyright (c) Codice Foundation
 * <p>
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 * <p>
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.compliance.saml.plugin;

import com.jayway.restassured.response.Response;
import org.codice.compliance.Common;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE;

/**
 * This class is the return type for methods of the {@code IdpSSOResponder} interface for the POST
 * Binding. Once the user implemented portion finishes its interaction with the IdP under testing,
 * it should return an {@code IdpPostResponse}.
 * <p>
 * <p>An {@code IdpPostResponse} is created by passing in the resultant RestAssured {@code Response}
 * to its constructor.
 * <p>
 * <p>Example: {@code return IdpPostResponse(restAssuredResponse); }
 */
public class IdpPostResponse extends IdpResponse {

  public static final String NAME = "name";
  protected Response restAssuredResponse;

  public IdpPostResponse(Response response) {
    httpStatusCode = response.statusCode();

    responseForm = extractResponseForm(response.then().extract().asString());

    if (responseForm == null) {
      // Purely for debugging purposes
      this.restAssuredResponse = response;
    }
  }

  // Copy constructor
  protected IdpPostResponse(IdpPostResponse response) {
    super(response);
    this.restAssuredResponse = response.restAssuredResponse;
    responseForm = response.responseForm;
  }

  public Node responseForm;

  private Node extractResponseForm(String responseBody) {
    NodeList domChildren = Common.buildDom(responseBody).getChildNodes();

    for (int i = 0; i < domChildren.getLength(); i++) {
      Node node = domChildren.item(i);
      if (node.getLocalName().equals("form") && hasSamlResponseFormControl(node)) {
        return node;
      }
    }

    return null;
  }

  private boolean hasSamlResponseFormControl(Node node) {
    NamedNodeMap attributes = node.getAttributes();
    return attributes != null &&
            attributes.getNamedItem(NAME).getNodeValue().equalsIgnoreCase(SAML_RESPONSE);
  }
}
