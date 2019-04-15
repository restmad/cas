package org.apereo.cas.adaptors.duo.web.flow.action;

import org.apereo.cas.adaptors.duo.authn.DuoDirectCredential;
import org.apereo.cas.adaptors.duo.authn.DuoMultifactorAuthenticationProvider;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.support.WebUtils;

import lombok.val;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link DuoSecurityDirectAuthenticationAction}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
public class DuoSecurityDirectAuthenticationAction extends AbstractMultifactorAuthenticationAction<DuoMultifactorAuthenticationProvider> {

    @Override
    protected Event doExecute(final RequestContext requestContext) {
        val c = new DuoDirectCredential(WebUtils.getAuthentication(requestContext), provider.createUniqueId());
        WebUtils.putCredential(requestContext, c);
        return success();
    }
}
