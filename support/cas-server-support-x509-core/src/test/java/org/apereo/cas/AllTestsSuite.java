package org.apereo.cas;

import org.apereo.cas.adaptors.x509.authentication.handler.support.CRLDistributionPointRevocationCheckerTests;
import org.apereo.cas.adaptors.x509.authentication.handler.support.ResourceCRLRevocationCheckerTests;
import org.apereo.cas.adaptors.x509.authentication.handler.support.ThresholdExpiredCRLRevocationPolicyTests;
import org.apereo.cas.adaptors.x509.authentication.handler.support.X509CredentialsAuthenticationHandlerTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509CertificateCredentialTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509CommonNameEDIPIPrincipalResolverTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509SerialNumberAndIssuerDNPrincipalResolverTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509SerialNumberPrincipalResolverTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509SubjectAlternativeNameRFC822EmailPrincipalResolverTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509SubjectAlternativeNameUPNPrincipalResolverTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509SubjectDNPrincipalResolverTests;
import org.apereo.cas.adaptors.x509.authentication.principal.X509SubjectPrincipalResolverTests;

import org.junit.platform.suite.api.SelectClasses;

/**
 * The {@link AllTestsSuite} is responsible for
 * running all cas test cases.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@SelectClasses({
    X509SerialNumberAndIssuerDNPrincipalResolverTests.class,
    X509SerialNumberPrincipalResolverTests.class,
    X509SubjectDNPrincipalResolverTests.class,
    X509CommonNameEDIPIPrincipalResolverTests.class,
    X509SubjectAlternativeNameRFC822EmailPrincipalResolverTests.class,
    X509SubjectAlternativeNameUPNPrincipalResolverTests.class,
    X509SubjectPrincipalResolverTests.class,
    ResourceCRLRevocationCheckerTests.class,
    X509CertificateCredentialTests.class,
    ThresholdExpiredCRLRevocationPolicyTests.class,
    X509CredentialsAuthenticationHandlerTests.class,
    CRLDistributionPointRevocationCheckerTests.class
})
public class AllTestsSuite {
}
