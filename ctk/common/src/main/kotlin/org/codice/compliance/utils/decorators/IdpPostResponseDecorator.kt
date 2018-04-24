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
package org.codice.compliance.utils.decorators

import de.jupf.staticlog.Log
import org.apache.commons.lang3.StringUtils.isNotEmpty
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.binding.PostBindingVerifier
import org.w3c.dom.Node

/**
 * This class can only be instantiated by using extension methods in IdpResponseDecorator.kt
 */
class IdpPostResponseDecorator
internal constructor(response: IdpPostResponse) : IdpPostResponse(response), IdpResponseDecorator {
    companion object {
        private const val VALUE = "value"
    }

    init {
        Log.debugWithSupplier {
            restAssuredResponse?.then()?.extract()?.body()?.asString()?.prettyPrintXml() ?: ""
        }
    }

    // Bindings 3.5.4 "If the message is a SAML response, then the form control MUST be named
    // SAMLResponse."
    val samlResponseFormControl: Node? = responseForm?.children("input")
            ?.firstOrNull({ SAML_RESPONSE.equals(it.attributeText(NAME), ignoreCase = true) })

    // Bindings 3.5.4 "If a “RelayState” value is to accompany the SAML protocol message, it MUST be
    // placed in an additional **hidden** form control named RelayState within the same form with
    // the SAML message"
    val relayStateFormControl: Node? = responseForm?.children("input")
            ?.firstOrNull({ RELAY_STATE.equals(it.attributeText(NAME), ignoreCase = true) })

    val samlResponseString: String? = extractValue(samlResponseFormControl)

    // Overridden by tests if relay state was provided in the SAML request.
    override var isRelayStateGiven: Boolean = false
    override lateinit var decodedSamlResponse: String

    override val responseDom: Node by lazy {
        checkNotNull(decodedSamlResponse)
        buildDom(decodedSamlResponse)
    }

    val relayStateString: String? = extractValue(relayStateFormControl)

    override fun bindingVerifier(): BindingVerifier {
        return PostBindingVerifier(this)
    }

    private fun extractValue(node: org.w3c.dom.Node?): String? {
        return node?.let {
            if (isNotEmpty(it.textContent))
                it.textContent
            else
                it.attributeText(VALUE)
        }
    }
}
