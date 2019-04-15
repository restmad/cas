package org.apereo.cas.support.oauth.web.endpoints;

import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRequestDataHolder;
import org.apereo.cas.util.Pac4jUtils;
import org.apereo.cas.web.support.CookieUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

/**
 * This controller is in charge of responding to the authorize call in OAuth v2 protocol.
 * This url is protected by a CAS authentication. It returns an OAuth code or directly an access token.
 *
 * @author Jerome Leleu
 * @since 3.5.0
 */
@Slf4j
public class OAuth20AuthorizeEndpointController extends BaseOAuth20Controller {
    public OAuth20AuthorizeEndpointController(final OAuth20ConfigurationContext oAuthConfigurationContext) {
        super(oAuthConfigurationContext);
    }

    private static boolean isRequestAuthenticated(final ProfileManager manager, final J2EContext context) {
        val opt = manager.get(true);
        return opt.isPresent();
    }

    /**
     * Handle request via GET.
     *
     * @param request  the request
     * @param response the response
     * @return the model and view
     * @throws Exception the exception
     */
    @GetMapping(path = OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.AUTHORIZE_URL)
    public ModelAndView handleRequest(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        val context = Pac4jUtils.getPac4jJ2EContext(request, response, new J2ESessionStore());
        val manager = Pac4jUtils.getPac4jProfileManager(request, response);

        if (!verifyAuthorizeRequest(context) || !isRequestAuthenticated(manager, context)) {
            LOGGER.error("Authorize request verification failed. Either the authorization request is missing required parameters, "
                + "or the request is not authenticated and contains no authenticated profile/principal.");
            return OAuth20Utils.produceUnauthorizedErrorView();
        }

        val clientId = context.getRequestParameter(OAuth20Constants.CLIENT_ID);
        val registeredService = getRegisteredServiceByClientId(clientId);
        try {
            RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(clientId, registeredService);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
            return OAuth20Utils.produceUnauthorizedErrorView();
        }

        val mv = getOAuthConfigurationContext().getConsentApprovalViewResolver().resolve(context, registeredService);
        if (!mv.isEmpty() && mv.hasView()) {
            return mv;
        }

        return redirectToCallbackRedirectUrl(manager, registeredService, context, clientId);
    }

    /**
     * Handle request post.
     *
     * @param request  the request
     * @param response the response
     * @return the model and view
     * @throws Exception the exception
     */
    @PostMapping(path = OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.AUTHORIZE_URL)
    public ModelAndView handleRequestPost(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        return handleRequest(request, response);
    }

    /**
     * Gets registered service by client id.
     *
     * @param clientId the client id
     * @return the registered service by client id
     */
    protected OAuthRegisteredService getRegisteredServiceByClientId(final String clientId) {
        return OAuth20Utils.getRegisteredOAuthServiceByClientId(getOAuthConfigurationContext().getServicesManager(), clientId);
    }

    /**
     * Redirect to callback redirect url model and view.
     *
     * @param manager           the manager
     * @param registeredService the registered service
     * @param context           the context
     * @param clientId          the client id
     * @return the model and view
     */
    protected ModelAndView redirectToCallbackRedirectUrl(final ProfileManager manager,
                                                         final OAuthRegisteredService registeredService,
                                                         final J2EContext context,
                                                         final String clientId) {
        val profile = (Optional<CommonProfile>) manager.get(true);
        if (profile == null || profile.isEmpty()) {
            LOGGER.error("Unexpected null profile from profile manager. Request is not fully authenticated.");
            return OAuth20Utils.produceUnauthorizedErrorView();
        }

        val service = getOAuthConfigurationContext().getAuthenticationBuilder().buildService(registeredService, context, false);
        LOGGER.debug("Created service [{}] based on registered service [{}]", service, registeredService);

        val authentication = getOAuthConfigurationContext().getAuthenticationBuilder().build(profile.get(), registeredService, context, service);
        LOGGER.debug("Created OAuth authentication [{}] for service [{}]", service, authentication);

        try {
            val audit = AuditableContext.builder()
                .service(service)
                .authentication(authentication)
                .registeredService(registeredService)
                .retrievePrincipalAttributesFromReleasePolicy(Boolean.TRUE)
                .build();
            val accessResult = getOAuthConfigurationContext().getRegisteredServiceAccessStrategyEnforcer().execute(audit);
            accessResult.throwExceptionIfNeeded();
        } catch (final UnauthorizedServiceException | PrincipalException e) {
            LOGGER.error(e.getMessage(), e);
            return OAuth20Utils.produceUnauthorizedErrorView();
        }

        val modelAndView = buildAuthorizationForRequest(registeredService, context, clientId, service, authentication);
        if (modelAndView != null && modelAndView.hasView()) {
            return modelAndView;
        }
        LOGGER.debug("No explicit view was defined as part of the authorization response");
        return null;
    }

    /**
     * Build callback url for request string.
     *
     * @param registeredService the registered service
     * @param context           the context
     * @param clientId          the client id
     * @param service           the service
     * @param authentication    the authentication
     * @return the string
     */
    protected ModelAndView buildAuthorizationForRequest(final OAuthRegisteredService registeredService,
                                                        final J2EContext context,
                                                        final String clientId, final Service service,
                                                        final Authentication authentication) {
        val builder = getOAuthConfigurationContext().getOauthAuthorizationResponseBuilders()
            .stream()
            .filter(b -> b.supports(context))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Could not build the callback url. Response type likely not supported"));

        val ticketGrantingTicket = CookieUtils.getTicketGrantingTicketFromRequest(
            getOAuthConfigurationContext().getTicketGrantingTicketCookieGenerator(),
            getOAuthConfigurationContext().getTicketRegistry(), context.getRequest());

        val grantType = StringUtils.defaultIfEmpty(context.getRequestParameter(OAuth20Constants.GRANT_TYPE),
            OAuth20GrantTypes.AUTHORIZATION_CODE.getType()).toUpperCase();
        val scopes = OAuth20Utils.parseRequestScopes(context);
        val codeChallenge = context.getRequestParameter(OAuth20Constants.CODE_CHALLENGE);
        val codeChallengeMethod = StringUtils.defaultIfEmpty(context.getRequestParameter(OAuth20Constants.CODE_CHALLENGE_METHOD),
            OAuth20GrantTypes.AUTHORIZATION_CODE.getType()).toUpperCase();
        val holder = AccessTokenRequestDataHolder.builder()
            .service(service)
            .authentication(authentication)
            .registeredService(registeredService)
            .ticketGrantingTicket(ticketGrantingTicket)
            .grantType(OAuth20GrantTypes.valueOf(grantType))
            .codeChallenge(codeChallenge)
            .codeChallengeMethod(codeChallengeMethod)
            .scopes(scopes)
            .build();

        LOGGER.debug("Building authorization response for grant type [{}] with scopes [{}] for client id [{}]",
            grantType, scopes, clientId);
        return builder.build(context, clientId, holder);
    }

    /**
     * Verify the authorize request.
     *
     * @param context the context
     * @return whether the authorize request is valid
     */
    private boolean verifyAuthorizeRequest(final J2EContext context) {
        val validator = getOAuthConfigurationContext().getOauthRequestValidators()
            .stream()
            .filter(b -> b.supports(context))
            .findFirst()
            .orElse(null);
        if (validator == null) {
            LOGGER.warn("Ignoring malformed request [{}] no OAuth20 validator could declare support for its syntax", context.getFullRequestURL());
            return false;
        }
        return validator.validate(context);
    }
}


