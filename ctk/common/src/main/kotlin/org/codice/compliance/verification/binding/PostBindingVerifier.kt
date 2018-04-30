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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.Common
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLBindings_3_5_4_a
import org.codice.compliance.SAMLBindings_3_5_4_b
import org.codice.compliance.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLBindings_3_5_4_d
import org.codice.compliance.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_5_a
import org.codice.compliance.attributeNode
import org.codice.compliance.children
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.NAME
import org.codice.compliance.utils.TestCommon.Companion.VALUE
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.extractSamlResponseForm
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Decoder
import kotlin.test.assertNotNull

@Suppress("TooManyFunctions")
class PostBindingVerifier(override val response: Response) : BindingVerifier(response) {
    companion object {
        private const val HIDDEN = "hidden"
        private const val TYPE = "type"
        private const val ACTION = "action"
        private const val METHOD = "method"
        private const val POST = "POST"
    }

    private val responseForm: Node?
    private val samlResponseFormControl: Node?
    private val samlResponse: String?
    private val relayStateFormControl: Node?
    private val relayState: String?

    init {
        responseForm = response.extractSamlResponseForm()
        samlResponseFormControl =
                responseForm
                        ?.children()
                        ?.list()
                        ?.filter {
                            SAML_RESPONSE.equals(it.attributes().get(
                                    NAME), ignoreCase = true)
                        }?.firstOrNull()
        samlResponse = extractValue(samlResponseFormControl)
        relayStateFormControl =
                responseForm
                        ?.children()
                        ?.list()
                        ?.filter {
                            RELAY_STATE.equals(it.attributes().get(TestCommon.NAME),
                                    ignoreCase = true)
                        }?.firstOrNull()
        relayState = extractValue(relayStateFormControl)
    }

    /** Verify the response for a post binding */
    override fun decodeAndVerify(): org.w3c.dom.Node {
        verifyHttpStatusCode(response.statusCode)
        verifyNoNulls()
        verifyPostForm()
        if (isRelayStateGiven || relayState != null) {
            verifyPostRelayState()
        }
        val samlResponseDom = decode()
        verifyPostSSO(samlResponseDom)
        verifyPostDestination(samlResponseDom)
        return samlResponseDom
    }

    /** Verify an error response (Negative path) */
    override fun decodeAndVerifyError(): org.w3c.dom.Node {
        verifyHttpStatusCodeErrorResponse(response.statusCode)
        verifyNoNullsErrorResponse()
        return decodeError()
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNulls() {
        if (responseForm == null) {
            Log.debugWithSupplier {
                response.then().extract().body().asString().prettyPrintXml()
            }
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The form containing the SAMLResponse from control could not be" +
                            "found.")
        }
        if (isRelayStateGiven && relayStateFormControl == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState form control could not be found.")
        }
        if (samlResponse == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The SAMLResponse within the SAMLResponse form control could " +
                            "not be found.")
        }
        if (isRelayStateGiven && relayState == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_3_b,
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState within the RelayState form control could not" +
                            "be found.")
        }
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNullsErrorResponse() {
        if (responseForm == null) {
            Log.debugWithSupplier {
                response.then().extract().body().asString().prettyPrintXml()
            }
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The form containing the SAMLResponse from control could not be" +
                            "found." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
        if (isRelayStateGiven && relayStateFormControl == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState form control could not be found." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
        if (samlResponse == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The SAMLResponse within the SAMLResponse form control could" +
                            "not be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
        if (isRelayStateGiven && relayState == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_3_b,
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState within the RelayState form control could not " +
                            "be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec
     * 3.5.4 Message Encoding
     */
    private fun decode(): org.w3c.dom.Node {
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    message = "The SAML response could not be base64 decoded.",
                    cause = exception)
        }

        assertNotNull(decodedMessage)
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        return Common.buildDom(decodedMessage)
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun decodeError(): org.w3c.dom.Node {
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    message = "The SAML response could not be base64 decoded." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                    cause = exception)
        }

        assertNotNull(decodedMessage)
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        return Common.buildDom(decodedMessage)
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     */
    private fun verifyPostSSO(samlResponseDom: org.w3c.dom.Node) {
        if (samlResponseDom.children(SIGNATURE).isEmpty()
                || samlResponseDom.children(ASSERTION).any {
                    it.children(SIGNATURE).isEmpty()
                })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_5_a,
                    message = "No digital signature found on the Response or Assertions.",
                    node = samlResponseDom)
    }

    /**
     * Verifies the relay state according to the post binding rules in the binding spec
     * 3.5.3 RelayState
     */
    private fun verifyPostRelayState() {
        if (relayState != null && relayState.toByteArray().size > MAX_RELAY_STATE_LEN)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_3_a,
                    property = RELAY_STATE,
                    actual = relayState)

        if (isRelayStateGiven) {
            if (relayState != EXAMPLE_RELAY_STATE) {
                throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_3_b,
                        property = RELAY_STATE,
                        actual = relayState,
                        expected = EXAMPLE_RELAY_STATE)
            }
        }
    }

    /**
     * Verifies the destination is correct according to the post binding rules in the binding spec
     * 3.5.5.2 Security Considerations
     */
    private fun verifyPostDestination(samlResponseDom: org.w3c.dom.Node) {
        val destination = samlResponseDom.attributeNode(DESTINATION)?.nodeValue
        val signatures = samlResponseDom.recursiveChildren("Signature")

        if (signatures.isNotEmpty() && destination != acsUrl[HTTP_POST]) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = DESTINATION,
                    actual = destination,
                    expected = acsUrl[HTTP_POST],
                    node = samlResponseDom)
        }
    }

    /**
     * Verifies the form carrying the SAMLRequest was properly formatted according to the post
     * binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
// TODO refactor this method and response objects so we can show values in the errors
    private fun verifyPostForm() {
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
            if (isRelayStateGiven) {
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
            }
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

    private fun checkNodeAttribute(node: Node?,
                                   attributeName: String,
                                   expectedValue: String): Boolean {
        return expectedValue == node?.getAttribute(attributeName)
    }

    private fun checkNodeAttributeIgnoreCase(node: Node?,
                                             attributeName: String,
                                             expectedValue: String): Boolean {
        return expectedValue.equals(node?.getAttribute(attributeName), true)
    }
}
