# MUSTs or MUST NOTs That Are Not Currently Tested

### Core
| Section | Specification Snippet | Justification
| --- | --- | --- |
| 1.3.1 - String Values | Unless otherwise noted in this specification or particular profiles, all elements in SAML documents that have the XML Schema xs:string type, or a type derived from that, MUST be compared using an exact binary comparison. In particular, SAML implementations and deployments MUST NOT depend on case-insensitive string comparisons, normalization or trimming of whitespace, or conversion of locale-specific formats such as numbers of currency. | Impossible to directly verify
| 1.3.3 - Time Values | Implementations MUST NOT generate time instants that specify leap seconds. | Difficult to directly verify unless the IdP happens to return a response with a timestamp on the 60th second.
| 1.3.4 - ID and ID Reference Values | Any party that assigns an identifier MUST ensure that there is negligible probability that that party or any other party will accidentally assign the same identifier to a different data object. | Impossible to directly verify. Negligible probability is too subjective.
| 1.3.4 - ID and ID Reference Values | In the case that a random or pseudorandom technique is employed, the probability of two randomly chosen identifiers being identical MUST be less than or equal to 2-128. | Hard to test. Would need to know the possible set of characters they are using in to calculate the probability.
| 1.3.4 - ID and ID Reference Values | A pseudorandom generator MUST be seeded with unique material in order to ensure the desired uniqueness properties between different systems. | Impossible to directly verify
| 2.2.4 - Element <EncryptedID> | The encrypted content MUST contain an element that has a type of NameIDType or AssertionType, or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType. | It would take a lot of effort to verify the type of the decrypted element and provides little value. However, the extended element's SAML defined base values will be verified by the schema validator.
| 2.2.4 - Element <EncryptedID> | Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation. For more on such issues, see \[XMLEnc] Section 6.3. | This is implicitly verified by following XML Encryption rules when decrypting.
| 2.3.3 - Element <Assertion> | If such a signature is used, then the \<ds:Signature> element MUST be present. | Impossible to directly verify since it's impossible to know "If such a signature is used". However the \<ds:Signature> element is tested if provided.
| 2.3.4 - Element <EncryptedAssertion> | The encrypted content MUST contain an element that has a type of or derived from AssertionType. | It would take a lot of effort to verify the type of the decrypted element and provides little value. However, the extended element's SAML defined base values will be verified by the schema validator.
| 2.3.4 - Element <EncryptedAssertion> | Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation. For more on such issues, see \[XMLEnc] Section 6.3. | This is implicitly verified by following XML Encryption rules when decrypting.
| 2.5.1.6 - Element <ProxyRestriction> | A relying party acting as an asserting party MUST NOT issue an assertion that itself violates the restrictions specified in this condition on the basis of an assertion containing such a condition. | Difficult to test. Would need to intercept interactions between the proxying party and the asserting party.
| 2.5.1.6 - Element <ProxyRestriction> | A Count value of zero indicates that a relying party MUST NOT issue an assertion to another relying party on the basis of this assertion. | Difficult to test. Would need to intercept interactions between the proxying party and the asserting party.
| 2.5.1.6 - Element <ProxyRestriction> | If greater than zero, any assertions so issued MUST themselves contain a <ProxyRestriction> element with a Count value of at most one less than this value. | Difficult to test. Would need to intercept interactions between the proxying party and the asserting party.
| 2.7.3.1 - Element <Attribute> | This attribute's value MUST NOT be used as a basis for formally identifying SAML attributes. | Impossible to verify
| 2.7.3.1 - Element <Attribute> | Within an \<AttributeStatement>, if the SAML attribute exists but has no values, then the <AttributeValue> element MUST be omitted. | Impossible to know if the attribute has no value from a high-level perspective. Currently the CTK only tests to make sure there is a value within the AttributeValue element. For example: putting an attribute value of "empty" would be interpreted as a valid value by the CTK.
| 2.7.3.1 - Element <Attribute> | Any other uses of the element by profiles or other specifications MUST define the <Attribute> semantics of specifying or omitting elements. <AttributeValue> | Not verifying custom profiles or their specifications.
| 2.7.3.1.1 - Element <AttributeValue> | If a SAML attribute includes an empty value, such as the empty string, the corresponding <AttributeValue> element MUST be empty | Impossible to know if an Attribute had an empty string value from a high level perspective, i.e. "empty".
| 2.7.3.1.1 - Element <AttributeValue> | If a SAML attribute includes a "null" value, the corresponding <AttributeValue> element MUST be empty and MUST contain the reserved xsi:nil XML attribute with a value of "true" or "1". | Impossible to verify if an Attribute had a null value
| 2.7.3.2 - Element <EncryptedAttribute> | The encrypted content MUST contain an element that has a type of or derived from AttributeType. | It would take a lot of effort to verify the type of the decrypted element and provides little value. However, the extended element's SAML defined base values will be verified by the schema validator.
| 2.7.3.2 - Element <EncryptedAttribute> | Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation. For more on such issues, see \[XMLEnc] Section 6.3. | This is implicitly verified by following XML Encryption rules when decrypting.
| 2.7.4 - Element <AuthzDecisionStatement> | In order for the assertion to be interpreted correctly and securely, the SAML authority and SAML relying party MUST interpret each URI reference in a consistent manner. | Impossible to verify how the SAML authority interprets the URI it provided.
| 3.2.2 - Complex Type StatusResponseType | If such a signature is used, then the \<ds:Signature> element MUST be present. | Impossible to directly verify since it's impossible to know "If such a signature is used". However the \<ds:Signature> element is tested if provided.
| 3.3.4 - Processing Rules | If S2 includes one or more \<saml:SubjectConfirmation> elements, then S1 MUST include at least one \<SAML:SubjectConfirmation> element such that S1 can be confirmed in the manner described by at least one \<SAML:SubjectConfirmation> element in S2. | "Confirming" in \<SAML:SubjectConfirmation> is a very difficult task. For now only the \<SAML:SubjectConfirmation> Method attributes are compared, rather than actual confirmation.
| 3.4.1 - Element <AuthnRequest> | If \[ForceAuthn is\] "true", the identity provider MUST authenticate the presenter directly rather than rely on a previous security context. If a value is not provided, the default is "false". | Hard to test because how they use “previous security context” is implementation-specific. We could catch most cases by handling cookies and/or session variables, for example, but it wouldn’t cover all cases.
| 3.4.1 - Element <AuthnRequest> | If \[isPassive is\] "true", the identity provider and the user agent itself MUST NOT visibly take control of the user interface from the requester and interact with the presenter in a noticeable fashion. | Impossible to test because the tests cannot reliably tell if an HTML response is going to display anything in the browser. (for example, javascript could be embedded in the HTML that dynamically changes the HTML).
| 3.4.1 - Element <AuthnRequest> | If both ForceAuthn and IsPassive are "true", the identity provider MUST NOT freshly authenticate the presenter unless the constraints of IsPassive can be met. | Impossible to test. See IsPassive.
| 3.4.1 - Element <AuthnRequest> | AssertionConsumerServiceIndex usage | Can't be tested until a second binding (Artifact) is supported in the test kit, since we won't know if they're just relying on the default.
| 3.4.1 - Element <AuthnRequest> | The identity provider MUST have a trusted means to map the \[AssertionConsumerServiceIndex\] index value in the attribute to a location associated with the requester. \[SAMLMeta\] provides one possible mechanism. | Hard to test because we don’t know what method the IdP is going to use.
| 3.4.1 - Element <AuthnRequest> | \[AssertionConsumerServiceUrl\] Specifies by value the location to which the <Response> message MUST be returned to the requester.  | Can't be tested until a second binding (Artifact) is supported in the test kit, since we won't know if they're just relying on the default.
| 3.4.1 - Element <AuthnRequest> | The responder MUST ensure by some means that the value specified is in fact associated with the requester. \[SAMLMeta\] provides one possible mechanism; signing the enclosing <AuthnRequest> message is another. | Hard to test because we don’t know what method the IdP is going to use.
| 3.4.1 - Element <AuthnRequest> | The identity provider MUST have a trusted means to map the index value in the attribute to information associated with the requester. \[SAMLMeta\] provides one possible mechanism. | Hard to test because we don’t know what method the IdP is going to use.
| 3.4.1.4 - Processing Rules | In such a case, the identifier's physical content MAY be different, but it MUST refer to the same principal. | Figuring out if the identifiers refer to the same principal cannot be done without actually resolving the identifiers to a principal. For now all that is checked is identical identifier values.
| 4.1.2 - SAML Assertion Version | All assertions that share a major assertion version number MUST share the same general processing rules and semantics | Impossible to test
| 8.3.7 - Persistent Identifier | A given value, once associated with a principal, MUST NOT be assigned to a different principal at any time in the future. | Impossible to test
| 8.3.7 - Persistent Identifier | Persistent identifiers are intended as a privacy protection mechanism; as such they MUST NOT be shared in clear text with providers other than the providers that have established the shared identifier. | Impossible to test. Cannot make sure they do not send info to other entities.
| 8.3.7 - Persistent Identifier | Furthermore, \[persistent identifiers] MUST NOT appear in log files or similar locations without appropriate controls and protections. | Impossible to test. Cannot check their log files (unless provided).
| 8.3.7 - Persistent Identifier | Deployments without such requirements are free to use other kinds of identifiers in their SAML exchanges, but MUST NOT overload this format with persistent but non-opaque values | Extremely hard to test. Testing if a value is non-opaque, IOW you cannot derive anything about the user from the identifier alone, is hard.

### Profiles

| Section | Specification Snippet | Justification
| --- | --- | --- |
| 4.1.4.2 - <Response> Usage | If multiple assertions are included, then each assertion's <Subject> element MUST refer to the same principal. It is allowable for the content of the <Subject> elements to differ (e.g. using different <NameID> or alternative <SubjectConfirmation> elements). | Figuring out if the subjects all refer to the same principal cannot be done without actually resolving the subjects to a principal. However, <NameID> is being partially tested by comparing

### Bindings

| Section | Specification Snippet | Justification
| --- | --- | --- |
| 3.1.1 - Use of RelayState | If a SAML request message is accompanied by RelayState data, then the SAML responder MUST return its SAML protocol response using a binding that also supports a RelayState mechanism. | The CTK currently supports bindings that support a RelayState mechanism. Once additional bindings are supported, this should be revisited.
| 3.1.1 - Use of RelayState | Implementations MUST carefully sanitize the URL schemes they permit (for example, disallowing anything but "http" or "https") | Hard to test with little value. Most implementations only deal with http and https anyways. Would need to add a plugin point to attempt and hit every exposed endpoint on seemingly any protocol.
| 3.4.4 - Security Considerations | It is not a requirement that all possible SAML messages be encodable with a particular set of rules, but the rules MUST clearly indicate which messages or content can or cannot be so encoded. | Impossible to test. Cannot verify that the given encoding rules follow the stated guidelines.
| 3.4.4 - Message Encoding | A query string parameter named SAMLEncoding is reserved to identify the encoding mechanism used. If this parameter is omitted, then the value is assumed to be "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE". | Currently the CTK only supports DEFLATE encoding.
| 3.4.4.1 - DEFLATE ENCODING | The following signature algorithms (see \[XMLSig]) and their URI representations MUST be supported with this encoding mechanism: `DSAwithSHA1 – http://www.w3.org/2000/09/xmldsig#dsa-sha1`, `RSAwithSHA1 – http://www.w3.org/2000/09/xmldsig#rsa-sha1` | Impossible to test. Can't know if an encoding we might have never seen before can be signed with `DSAwithSHA1` or `RSAwithSHA1`.
| 3.5.5.2 - Security Considerations | The producer and consumer of "RelayState" information MUST take care not to associate sensitive state information with the "RelayState" value without taking additional precautions (such as based on the information in the SAML message). | Impossible to test. Cannot tell if something is "sensitive state information", and "additional precautions" is too ambiguous.