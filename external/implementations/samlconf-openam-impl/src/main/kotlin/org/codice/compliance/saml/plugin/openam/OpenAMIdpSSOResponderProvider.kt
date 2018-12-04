/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin.openam

import com.beust.klaxon.Klaxon
import io.restassured.RestAssured
import io.restassured.response.Response
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.kohsuke.MetaInfServices

@MetaInfServices
class OpenAMIdpSSOResponderProvider : IdpSSOResponder {
    override fun getResponseForPostRequest(originalResponse: Response): Response {
        //  return doStuff(originalResponse)
        return originalResponse
    }

    override fun getResponseForRedirectRequest(originalResponse: Response): Response {
        TODO("not implemented")
        //To change body of created functions use File | Settings | File Templates.
    }

    fun doStuff(response: Response?): Response? {

        val realm = "SamlCTK"
        val authURL = "/OpenAM-14.1.13/json/realms/root/realms/$realm/authenticate"
        //val url = response.getHeader("Location")

        val jsonString = RestAssured.given().`when`().post(authURL).jsonPath().prettyPrint()
        val authJson = Klaxon().parse<AuthJson>(jsonString)

        /*
            Post body
            callback_0={user}
            callback_1={password}
            body(callback_0=admin&callback_1=admin)
         */
        return response
    }
}
fun main(args: Array<String>) {
    OpenAMIdpSSOResponderProvider().doStuff(null)
}

data class AuthJson(
    val authId: String,
    val template: String,
    val header: String,
    val callbacks: List<CBNodes>
)

data class CBNodes(val type: String, val output: NodeData)

data class NodeData(val name: String, val value: String)
