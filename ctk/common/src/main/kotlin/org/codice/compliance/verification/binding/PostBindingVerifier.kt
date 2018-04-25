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

import io.kotlintest.matchers.shouldNotBe
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLBindings_3_5_4_a1
import org.codice.compliance.SAMLBindings_3_5_4_a2
import org.codice.compliance.SAMLBindings_3_5_4_b1
import org.codice.compliance.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLBindings_3_5_4_d1
import org.codice.compliance.SAMLBindings_3_5_4_d2
import org.codice.compliance.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_5
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.saml.plugin.IdpPostResponse.NAME
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.decorators.IdpPostResponseDecorator
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Decoder

class PostBindingVerifier(private val response: IdpPostResponseDecorator) : BindingVerifier() {
    companion object {
        private const val HIDDEN = "hidden"
        private const val TYPE = "type"
        private const val ACTION = "action"
        private const val METHOD = "method"
        private const val POST = "POST"
    }

    /**
     * Verify the response for a post binding
     */
    override fun verify() {
        verifyHttpStatusCode(response.httpStatusCode)
        verifyNoNulls()
        decodeAndVerify()
        verifyPostSSO()
        if (response.isRelayStateGiven || response.relayState != null) {
            verifyPostRelayState()
        }
        verifyPostDestination()
        verifyPostForm()
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNulls() {
        with(response) {
            if (responseForm == null || samlResponseFormControl == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The form containing the SAMLResponse from control could not be" +
                                "found.")

            if (isRelayStateGiven && relayStateFormControl == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control could not be found.")

            if (samlResponse == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The SAMLResponse within the SAMLResponse form control could " +
                                "not be found.")

            if (isRelayStateGiven && relayState == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_3_b,
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState within the RelayState form control could not" +
                                "be found.")
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec
     * 3.5.4 Message Encoding
     */
    private fun decodeAndVerify() {
        val samlResponse = response.samlResponse

        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a1,
                    message = "The SAML response could not be base64 decoded.",
                    cause = exception)
        }

        decodedMessage shouldNotBe null
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     */
    private fun verifyPostSSO() {
        if (response.responseDom.children(SIGNATURE).isEmpty()
                || response.responseDom.children("Assertion").any {
                    it.children(SIGNATURE).isEmpty()
                })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_5,
                    message = "No digital signature found on the Response or Assertions.",
                    node = response.responseDom)
    }

    /**
     * Verifies the relay state according to the post binding rules in the binding spec
     * 3.5.3 RelayState
     */
    private fun verifyPostRelayState() {
        val relayState = response.relayState
        val isRelayStateGiven = response.isRelayStateGiven

        if (relayState.toByteArray().size > MAX_RELAY_STATE_LEN)
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
    private fun verifyPostDestination() {
        val destination = response.responseDom.attributeNode("Destination")?.nodeValue
        val signatures = response.responseDom.recursiveChildren("Signature")

        if (signatures.isNotEmpty() && destination != acsUrl[HTTP_POST]) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = "Destination",
                    actual = destination,
                    expected = acsUrl[HTTP_POST],
                    node = response.responseDom)
        }
    }

    /**
     * Verifies the form carrying the SAMLRequest was properly formatted according to the post
     * binding rules in the binding spec
     * 3.5.4 Message Encoding
     *
     * Bindings 3.5.4 "The action attribute of the form MUST be the recipient's HTTP endpoint for
     * the protocol or profile using this binding to which the SAML message is to be delivered.
     * The method attribute MUST be "POST"."
     *
     * Bindings 3.5.4 "A SAML protocol message is form-encoded by... placing the result **in** a
     * **hidden** form control within a form as defined by [HTML401] Section 17"
     *
     * The two key words here are "in" and "hidden"
     *
     * Assuming "in" in the above quote means in either the value attribute or in the value
     * itself.
     *
     * And "hidden" means both the SAMLResponse and RelayState MUST be placed in "hidden" form
     * controls
     */
    private fun verifyPostForm() {
        with(response) {
            responseForm.attributeText(ACTION).let { action ->
                if (action == null || """^(http|https)://""".toRegex().matches(action))
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_d1,
                            message = """The form "action" [$action] is not a valid http url.""")
            }

            responseForm.attributeText(METHOD).let { method ->
                if (!POST.equals(method))
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_d2,
                            message = "The form's method attribute [$method] does not have the" +
                                    " expected value [$POST].")
            }
        }
        verifySamlResponseFormControl()
        if (response.isRelayStateGiven)
            verifyRelayStateFormControl()
    }

    private fun verifySamlResponseFormControl() {
        with(response) {
            samlResponseFormControl?.attributeText(NAME).let { name ->
                if (!SAML_RESPONSE.equals(name))
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_b1,
                            message = "The SAMLResponse form control's name [$name] does not have" +
                                    " the expected value [$SAML_RESPONSE].")
            }

            samlResponseFormControl?.attributeText(TYPE).let { type ->
                if (!HIDDEN.equals(type, ignoreCase = true))
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_a2,
                            message = "The SAMLResponse form control was not hidden.")
            }
        }
    }

    private fun verifyRelayStateFormControl() {
        with (response) {
            relayStateFormControl?.attributeText(NAME).let { name ->
                if (!RELAY_STATE.equals(name))
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_c,
                            message = "The RelayState form control's name [$name] does not" +
                                    " have the expected value [$RELAY_STATE].")
            }
            relayStateFormControl?.attributeText(TYPE).let { type ->
                if (!HIDDEN.equals(type, ignoreCase = true))
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_c,
                            message = "The RelayState form control's type [$type] does not" +
                                    " have the expected value [$HIDDEN].")
            }
        }
    }
}
