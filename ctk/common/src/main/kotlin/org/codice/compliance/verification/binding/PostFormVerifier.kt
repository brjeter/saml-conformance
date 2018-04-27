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
package org.codice.compliance.verification.binding

import com.jayway.restassured.path.xml.element.Node
import com.jayway.restassured.response.Response
import de.jupf.staticlog.Log
import org.apache.commons.lang3.StringUtils.isNotEmpty
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLBindings_3_5_4_a
import org.codice.compliance.SAMLBindings_3_5_4_b
import org.codice.compliance.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLBindings_3_5_4_d
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.utils.SamlConfReqData
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.NAME
import org.codice.compliance.utils.TestCommon.Companion.VALUE
import org.codice.compliance.utils.extractSamlResponseForm
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST

class PostFormVerifier(val reqData: SamlConfReqData, val response: Response) {
    companion object {
        private const val HIDDEN = "hidden"
        private const val TYPE = "type"
        private const val ACTION = "action"
        private const val METHOD = "method"
        private const val POST = "POST"
    }

    /**
     * Verifies the form carrying the SAMLRequest was properly formatted according to the post
     * binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
    // TODO refactor this method and response objects so we can show values in the errors
    fun verifyAndParse(): String {
        val responseForm = response.extractSamlResponseForm()

        if (responseForm == null) {
            Log.debugWithSupplier {
                response.then().extract().body().asString().prettyPrintXml()
            }
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The form containing the SAMLResponse from control could not be" +
                            "found.")
        } else {
            verifyForm(responseForm)
            verifyRelayStateFormControl(responseForm)
            return verifyAndParseSamlResponse(responseForm)
        }
    }

    private fun verifyForm(responseForm: Node) {
        with(response) {
            if (!checkNodeAttribute(responseForm, ACTION,
                            checkNotNull(TestCommon.acsUrl[HTTP_POST]))) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_d,
                        message = """The form "action" is incorrect.""")
            }
            if (!checkNodeAttribute(responseForm, METHOD, POST)) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_d,
                        message = """The form "method" is incorrect.""")
            }
        }
    }

    private fun verifyAndParseSamlResponse(responseForm: Node): String {
        // Bindings 3.5.4 "If the message is a SAML response, then the form control MUST be named
        // SAMLResponse."
        val samlResponseFormControl =
                responseForm
                        .children()
                        .list()
                        .filter {
                            SSOConstants.SAML_RESPONSE.equals(it.attributes().get(
                                    TestCommon.NAME), ignoreCase = true)
                        }
                        .first()

        if (!checkNodeAttribute(samlResponseFormControl, NAME, SAML_RESPONSE)) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_b,
                    message = "The SAMLResponse form control was incorrectly named.")
        }
        if (!checkNodeAttributeIgnoreCase(samlResponseFormControl, TYPE, HIDDEN)) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    message = "The SAMLResponse form control was not hidden.")
        }

        val samlResponse =
                extractValue(samlResponseFormControl) ?: throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a,
                        SAMLBindings_3_5_4_b,
                        message = "The SAMLResponse within the SAMLResponse form control could " +
                                "not be found.")
        return samlResponse
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyRelayStateFormControl(responseForm: Node) {
        // Bindings 3.5.4 "If a “RelayState” value is to accompany the SAML protocol message, it
        // MUST be placed in an additional **hidden** form control named RelayState within the
        // same form with the SAML message"
        val relayStateFormControl =
                responseForm
                        .children()
                        .list()
                        .filter {
                            SSOConstants.RELAY_STATE.equals(it.attributes().get(TestCommon.NAME),
                                    ignoreCase = true)
                        }.firstOrNull()
        relayStateFormControl?.let {
            if (!checkNodeAttribute(relayStateFormControl, NAME, RELAY_STATE)) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control was incorrectly named.")
            }
            if (!checkNodeAttributeIgnoreCase(relayStateFormControl, TYPE, HIDDEN)) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control was not hidden.")
            }
            verifyRelayStateValue(extractValue(relayStateFormControl))
        } ?: if (reqData.wasRelayStateGiven) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState form control could not be found.")
        }
    }

    private fun verifyRelayStateValue(relayState: String?) {
        if (relayState == null && reqData.wasRelayStateGiven) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_3_b,
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState within the RelayState form control could not" +
                            "be found.")
        }
        if (relayState != null && relayState.toByteArray().size > TestCommon.MAX_RELAY_STATE_LEN)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_3_a,
                    property = RELAY_STATE,
                    actual = relayState)

        if (relayState != TestCommon.EXAMPLE_RELAY_STATE && reqData.wasRelayStateGiven) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_3_b,
                    property = RELAY_STATE,
                    actual = relayState,
                    expected = TestCommon.EXAMPLE_RELAY_STATE)
        }
    }

    private fun extractValue(node: Node?): String? {
        if (isNotEmpty(node?.value())) {
            return node?.value()
        }

        return if (isNotEmpty(node?.attributes()?.get(VALUE))) {
            node?.attributes()?.get(VALUE)
        } else null
    }

    private fun checkNodeAttribute(node: Node,
                                   attributeName: String,
                                   expectedValue: String): Boolean {
        return expectedValue == node.getAttribute(attributeName)
    }

    private fun checkNodeAttributeIgnoreCase(node: Node,
                                             attributeName: String,
                                             expectedValue: String): Boolean {
        return expectedValue.equals(node.getAttribute(attributeName), true)
    }
}
