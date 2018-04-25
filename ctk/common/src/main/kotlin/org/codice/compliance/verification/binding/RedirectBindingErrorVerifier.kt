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

import com.google.api.client.http.HttpStatusCodes
import org.codice.compliance.SAMLBindings_3_4_3_b1
import org.codice.compliance.SAMLBindings_3_4_4_1
import org.codice.compliance.SAMLBindings_3_4_4_1_a
import org.codice.compliance.SAMLBindings_3_4_4_1_a1
import org.codice.compliance.SAMLBindings_3_4_4_1_a2
import org.codice.compliance.SAMLBindings_3_4_4_1_b1
import org.codice.compliance.SAMLBindings_3_4_4_a
import org.codice.compliance.SAMLBindings_3_4_6_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.decorators.IdpRedirectResponseDecorator
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_BASE64_DECODING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_INFLATING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_URL_DECODING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.LINEFEED_OR_WHITESPACE

@Suppress("TooManyFunctions" /* At least at present, there is no value in refactoring */)
class RedirectBindingErrorVerifier(private val response: IdpRedirectResponseDecorator)
    : BindingVerifier() {

    /**
     * Verify an error response (Negative path)
     */
    override fun verify() {
        verifyHttpRedirectStatusCodeErrorResponse()
        verifyNoNullsErrorResponse()
        decodeAndVerifyErrorResponse()
    }

    /**
     * Verifies the http status code of the response according to the redirect binding rules in the
     * binding spec (Negative path)
     * 3.4.6 Error Reporting
     */
    private fun verifyHttpRedirectStatusCodeErrorResponse() {
        // TODO remove the 200 check when we change HTTP status code to expect 302/303
        if (response.httpStatusCode != HttpStatusCodes.STATUS_CODE_OK
                && response.httpStatusCode != HttpStatusCodes.STATUS_CODE_FOUND
                && response.httpStatusCode != HttpStatusCodes.STATUS_CODE_SEE_OTHER) {
            throw SAMLComplianceException.createWithPropertyMessage(
                    SAMLBindings_3_4_6_a,
                    property = "HTTP Status Code",
                    actual = response.httpStatusCode.toString(),
                    expected = "${HttpStatusCodes.STATUS_CODE_FOUND} or " +
                            HttpStatusCodes.STATUS_CODE_SEE_OTHER +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE"
            )
        }
    }

    /**
     * Verifies the presence of redirect parameters according to the redirect binding rules in the
     * binding spec (Negative path)
     * 3.4.4 Message Encoding
     */
    private fun verifyNoNullsErrorResponse() {
        with(response) {
            if (isUrlNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Url not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isPathNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Path not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isParametersNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Parameters not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (samlResponse == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "SAMLResponse not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isRelayStateGiven && relayState == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_3_b1,
                        message = "RelayState not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the redirect binding
     * rules in the binding spec (Negative path)
     * 3.4.4.1 Deflate Encoding
     */
    @Suppress("ComplexMethod" /* Complexity due to nested `when` is acceptable */)
    private fun decodeAndVerifyErrorResponse() {
        val samlResponse = response.samlResponse
        val samlEncoding = response.samlEncoding
        val decodedMessage: String

        /**
         * A query string parameter named SAMLEncoding is reserved to identify the encoding
         * mechanism used. If this parameter is omitted, then the value is assumed to be
         * urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
         */
        decodedMessage = if (samlEncoding == null ||
                samlEncoding.equals("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE")) {
            try {
                Decoder.decodeAndInflateRedirectMessage(samlResponse)
            } catch (e: Decoder.DecoderException) {
                when (e.inflErrorCode) {
                    ERROR_URL_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not url decode the SAML response." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                                cause = e)
                    ERROR_BASE64_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not base64 decode the SAML response." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                                cause = e)
                    ERROR_INFLATING -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a1,
                            SAMLBindings_3_4_4_1,
                            message = "Could not inflate the SAML response." +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                            cause = e)
                    LINEFEED_OR_WHITESPACE ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a2,
                                message = "There were linefeeds or whitespace in the SAML " +
                                        "response." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                                cause = e)
                    else -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a,
                            SAMLBindings_3_4_4_1,
                            message = "Something went wrong with the SAML response." +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                            cause = e)
                }
            }
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE " +
                "encoding currently.")

        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }
}
