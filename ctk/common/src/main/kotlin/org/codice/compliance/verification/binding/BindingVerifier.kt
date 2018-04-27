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

import com.jayway.restassured.response.Response
import org.codice.compliance.SAMLBindings_3_4_6_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.utils.SamlConfReqData
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.determineBinding
import org.codice.security.saml.SamlProtocol

abstract class BindingVerifier(open val reqData: SamlConfReqData,
                               open val response: Response) {
    companion object {
        private const val HTTP_ERROR_THRESHOLD = 400

        /**
         * Verifies the http status code of the response is not an error status code
         * according to the binding spec
         * 3.4.6 & 3.5.6 Error Reporting
         */
        fun verifyHttpStatusCode(code: Int) {
            if (code >= HTTP_ERROR_THRESHOLD) {
                throw SAMLComplianceException.createWithPropertyMessage(
                        SAMLBindings_3_4_6_a,
                        property = "HTTP Status Code",
                        actual = code.toString(),
                        expected = "a non-error http status code; i.e. less than " +
                                HTTP_ERROR_THRESHOLD)
            }
        }

        /**
         * Verifies the http status code of the response is not an error status code
         * according to the binding spec (Negative path)
         * 3.4.6 & 3.5.6 Error Reporting
         */
        fun verifyHttpStatusCodeErrorResponse(code: Int) {
            if (code >= HTTP_ERROR_THRESHOLD) {
                throw SAMLComplianceException.createWithPropertyMessage(
                        SAMLBindings_3_4_6_a,
                        property = "HTTP Status Code",
                        actual = code.toString(),
                        expected = "a non-error http status code; i.e. less than " +
                                HTTP_ERROR_THRESHOLD +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
        }

        fun getBindingVerifier(reqData: SamlConfReqData, response: Response): BindingVerifier {
            return when (response.determineBinding()) {
                SamlProtocol.Binding.HTTP_REDIRECT -> RedirectBindingVerifier(reqData, response)
                SamlProtocol.Binding.HTTP_POST -> PostBindingVerifier(reqData, response)
                else -> throw UnsupportedOperationException("Binding is not currently supported.")
            }
        }
    }

    abstract fun decodeAndVerifyError(): org.w3c.dom.Node
    abstract fun decodeAndVerify(): org.w3c.dom.Node
}
