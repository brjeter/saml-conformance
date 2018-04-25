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
import org.codice.compliance.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLBindings_3_5_4_a1
import org.codice.compliance.SAMLBindings_3_5_4_a2
import org.codice.compliance.SAMLBindings_3_5_4_b1
import org.codice.compliance.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.decorators.IdpPostResponseDecorator
import org.codice.security.sign.Decoder

class PostBindingErrorVerifier(private val response: IdpPostResponseDecorator) : BindingVerifier() {
    /**
     * Verify an error response (Negative path)
     */
    override fun verify() {
        verifyHttpStatusCodeErrorResponse(response.httpStatusCode)
        verifyNoNullsErrorResponse()
        decodeAndVerifyErrorResponse()
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNullsErrorResponse() {
        with(response) {
            if (responseForm == null || samlResponseFormControl == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The form containing the SAMLResponse from control could not be" +
                                "found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")

            if (isRelayStateGiven && relayStateFormControl == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control could not be found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")

            if (samlResponse == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The SAMLResponse within the SAMLResponse form control could" +
                                "not be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")

            if (isRelayStateGiven && relayState == null)
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_3_b,
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState within the RelayState form control could not " +
                                "be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun decodeAndVerifyErrorResponse() {
        val samlResponse = response.samlResponse

        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a1,
                    message = "The SAML response could not be base64 decoded." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                    cause = exception)
        }

        decodedMessage shouldNotBe null
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }
}
