package org.apereo.cas.digest.web.flow;

import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.adaptive.AdaptiveAuthenticationPolicy;
import org.apereo.cas.digest.DigestCredential;
import org.apereo.cas.digest.DigestHashedCredentialRetriever;
import org.apereo.cas.digest.util.DigestAuthenticationUtils;
import org.apereo.cas.util.Pac4jUtils;
import org.apereo.cas.web.flow.actions.AbstractNonInteractiveCredentialsAction;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.http.credentials.extractor.DigestAuthExtractor;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletResponse;

/**
 * This is {@link DigestAuthenticationAction} that extracts digest authN credentials from the request.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@Slf4j
public class DigestAuthenticationAction extends AbstractNonInteractiveCredentialsAction {
    private final String nonce = DigestAuthenticationUtils.createNonce();
    private final DigestHashedCredentialRetriever credentialRetriever;
    private final String realm;
    private final String authenticationMethod;

    public DigestAuthenticationAction(final CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver,
                                      final CasWebflowEventResolver serviceTicketRequestWebflowEventResolver,
                                      final AdaptiveAuthenticationPolicy adaptiveAuthenticationPolicy,
                                      final String realm,
                                      final String authenticationMethod,
                                      final DigestHashedCredentialRetriever credentialRetriever) {
        super(initialAuthenticationAttemptWebflowEventResolver, serviceTicketRequestWebflowEventResolver, adaptiveAuthenticationPolicy);
        this.realm = realm;
        this.authenticationMethod = authenticationMethod;
        this.credentialRetriever = credentialRetriever;
    }

    @Override
    protected Credential constructCredentialsFromRequest(final RequestContext requestContext) {
        try {
            val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(requestContext);
            val response = WebUtils.getHttpServletResponseFromExternalWebflowContext(requestContext);

            val extractor = new DigestAuthExtractor();
            val webContext = Pac4jUtils.getPac4jJ2EContext(request, response, new J2ESessionStore());

            val credentials = extractor.extract(webContext);
            if (credentials == null) {
                response.addHeader(HttpConstants.AUTHENTICATE_HEADER,
                    DigestAuthenticationUtils.createAuthenticateHeader(this.realm, this.authenticationMethod, this.nonce));
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return null;
            }

            LOGGER.debug("Received digest authentication request from credentials [{}] ", credentials);
            val serverResponse = credentials.calculateServerDigest(true,
                this.credentialRetriever.findCredential(credentials.getUsername(), this.realm));

            val clientResponse = credentials.getToken();
            if (!serverResponse.equals(clientResponse)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return null;
            }

            return new DigestCredential(credentials.getUsername(), this.realm, credentials.getToken());

        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
