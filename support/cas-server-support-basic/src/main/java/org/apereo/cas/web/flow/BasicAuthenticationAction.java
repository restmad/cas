package org.apereo.cas.web.flow;

import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.adaptive.AdaptiveAuthenticationPolicy;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.util.Pac4jUtils;
import org.apereo.cas.web.flow.actions.AbstractNonInteractiveCredentialsAction;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.core.credentials.extractor.BasicAuthExtractor;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link BasicAuthenticationAction} that extracts basic authN credentials from the request.
 *
 * @author Misagh Moayyed
 * @since 4.2.0
 */
@Slf4j
public class BasicAuthenticationAction extends AbstractNonInteractiveCredentialsAction {

    public BasicAuthenticationAction(final CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver,
                                     final CasWebflowEventResolver serviceTicketRequestWebflowEventResolver,
                                     final AdaptiveAuthenticationPolicy adaptiveAuthenticationPolicy) {
        super(initialAuthenticationAttemptWebflowEventResolver, serviceTicketRequestWebflowEventResolver, adaptiveAuthenticationPolicy);
    }

    @Override
    protected Credential constructCredentialsFromRequest(final RequestContext requestContext) {
        try {
            val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(requestContext);
            val response = WebUtils.getHttpServletResponseFromExternalWebflowContext(requestContext);
            val extractor = new BasicAuthExtractor();
            val webContext = Pac4jUtils.getPac4jJ2EContext(request, response, new J2ESessionStore());
            val credentials = extractor.extract(webContext);
            if (credentials != null) {
                LOGGER.debug("Received basic authentication request from credentials [{}]", credentials);
                return new UsernamePasswordCredential(credentials.getUsername(), credentials.getPassword());
            }
        } catch (final Exception e) {
            LOGGER.warn(e.getMessage(), e);
        }
        return null;
    }
}
