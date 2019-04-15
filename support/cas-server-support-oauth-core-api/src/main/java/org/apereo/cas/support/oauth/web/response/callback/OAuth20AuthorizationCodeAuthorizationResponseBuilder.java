package org.apereo.cas.support.oauth.web.response.callback;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRequestDataHolder;
import org.apereo.cas.ticket.code.OAuthCode;
import org.apereo.cas.ticket.code.OAuthCodeFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.util.CommonHelper;
import org.springframework.web.servlet.ModelAndView;

import java.util.LinkedHashMap;

/**
 * This is {@link OAuth20AuthorizationCodeAuthorizationResponseBuilder}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Slf4j
@RequiredArgsConstructor
public class OAuth20AuthorizationCodeAuthorizationResponseBuilder implements OAuth20AuthorizationResponseBuilder {
    /**
     * The Ticket registry.
     */
    protected final TicketRegistry ticketRegistry;

    private final OAuthCodeFactory oAuthCodeFactory;

    private final ServicesManager servicesManager;

    @Override
    public ModelAndView build(final J2EContext context, final String clientId, final AccessTokenRequestDataHolder holder) {
        val authentication = holder.getAuthentication();
        val code = oAuthCodeFactory.create(holder.getService(), authentication,
            holder.getTicketGrantingTicket(), holder.getScopes(),
            holder.getCodeChallenge(), holder.getCodeChallengeMethod());
        LOGGER.debug("Generated OAuth code: [{}]", code);
        this.ticketRegistry.addTicket(code);

        return buildCallbackViewViaRedirectUri(context, clientId, authentication, code);
    }

    @Override
    public boolean supports(final J2EContext context) {
        val responseType = context.getRequestParameter(OAuth20Constants.RESPONSE_TYPE);
        return StringUtils.equalsIgnoreCase(responseType, OAuth20ResponseTypes.CODE.getType());
    }

    /**
     * Build callback view via redirect uri model and view.
     *
     * @param context        the context
     * @param clientId       the client id
     * @param authentication the authentication
     * @param code           the code
     * @return the model and view
     */
    protected ModelAndView buildCallbackViewViaRedirectUri(final J2EContext context, final String clientId,
                                                           final Authentication authentication, final OAuthCode code) {
        val attributes = authentication.getAttributes();
        val state = attributes.get(OAuth20Constants.STATE).get(0).toString();
        val nonce = attributes.get(OAuth20Constants.NONCE).get(0).toString();

        val redirectUri = context.getRequestParameter(OAuth20Constants.REDIRECT_URI);
        LOGGER.debug("Authorize request verification successful for client [{}] with redirect uri [{}]", clientId, redirectUri);

        var callbackUrl = redirectUri;
        callbackUrl = CommonHelper.addParameter(callbackUrl, OAuth20Constants.CODE, code.getId());
        if (StringUtils.isNotBlank(state)) {
            callbackUrl = CommonHelper.addParameter(callbackUrl, OAuth20Constants.STATE, state);
        }
        if (StringUtils.isNotBlank(nonce)) {
            callbackUrl = CommonHelper.addParameter(callbackUrl, OAuth20Constants.NONCE, nonce);
        }
        LOGGER.debug("Redirecting to URL [{}]", callbackUrl);
        val params = new LinkedHashMap<String, String>();
        params.put(OAuth20Constants.CODE, code.getId());
        params.put(OAuth20Constants.STATE, state);
        params.put(OAuth20Constants.NONCE, nonce);
        params.put(OAuth20Constants.CLIENT_ID, clientId);
        return buildResponseModelAndView(context, servicesManager, clientId, callbackUrl, params);
    }
}
