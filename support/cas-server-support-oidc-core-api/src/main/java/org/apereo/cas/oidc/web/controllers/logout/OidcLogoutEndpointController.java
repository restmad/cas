package org.apereo.cas.oidc.web.controllers.logout;

import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.BaseOAuth20Controller;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is {@link OidcLogoutEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
public class OidcLogoutEndpointController extends BaseOAuth20Controller {
    public OidcLogoutEndpointController(final OAuth20ConfigurationContext oAuthConfigurationContext) {
        super(oAuthConfigurationContext);
    }

    /**
     * Handle request.
     *
     * @param postLogoutRedirectUrl the post logout redirect url
     * @param state                 the state
     * @param idToken               the id token
     * @param request               the request
     * @param response              the response
     * @return the response entity
     */
    @GetMapping(value = '/' + OidcConstants.BASE_OIDC_URL + '/' + OidcConstants.LOGOUT_URL, produces = MediaType.APPLICATION_JSON_VALUE)
    @SneakyThrows
    public View handleRequestInternal(@RequestParam(value = "post_logout_redirect_uri", required = false) final String postLogoutRedirectUrl,
                                      @RequestParam(value = "state", required = false) final String state,
                                      @RequestParam(value = "id_token_hint", required = false) final String idToken,
                                      final HttpServletRequest request, final HttpServletResponse response) {

        if (StringUtils.isNotBlank(idToken)) {
            val claims = getOAuthConfigurationContext().getIdTokenSigningAndEncryptionService().validate(idToken);

            val clientId = claims.getStringClaimValue(OAuth20Constants.CLIENT_ID);

            val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(getOAuthConfigurationContext().getServicesManager(), clientId);
            val service = getOAuthConfigurationContext().getWebApplicationServiceServiceFactory().createService(clientId);

            val audit = AuditableContext.builder()
                .service(service)
                .registeredService(registeredService)
                .retrievePrincipalAttributesFromReleasePolicy(Boolean.FALSE)
                .build();
            val accessResult = getOAuthConfigurationContext().getRegisteredServiceAccessStrategyEnforcer().execute(audit);
            accessResult.throwExceptionIfNeeded();

            val urls = getOAuthConfigurationContext().getSingleLogoutServiceLogoutUrlBuilder().determineLogoutUrl(registeredService, service);
            if (StringUtils.isNotBlank(postLogoutRedirectUrl)) {
                val matchResult = urls.stream().anyMatch(url -> url.getUrl().equalsIgnoreCase(postLogoutRedirectUrl));
                if (matchResult) {
                    return getLogoutRedirectView(state, postLogoutRedirectUrl);
                }
            }

            if (urls.isEmpty()) {
                return getLogoutRedirectView(state, null);
            }
            return getLogoutRedirectView(state, urls.toArray()[0].toString());
        }

        return getLogoutRedirectView(state, null);
    }

    private View getLogoutRedirectView(final String state, final String redirectUrl) {
        val builder = UriComponentsBuilder.fromHttpUrl(getOAuthConfigurationContext().getCasProperties().getServer().getLogoutUrl());
        if (StringUtils.isNotBlank(redirectUrl)) {
            builder.queryParam(getOAuthConfigurationContext().getCasProperties().getLogout().getRedirectParameter(), redirectUrl);
        }
        if (StringUtils.isNotBlank(state)) {
            builder.queryParam(OAuth20Constants.STATE, redirectUrl);
        }
        val logoutUrl = builder.build().toUriString();
        return new RedirectView(logoutUrl);
    }
}
