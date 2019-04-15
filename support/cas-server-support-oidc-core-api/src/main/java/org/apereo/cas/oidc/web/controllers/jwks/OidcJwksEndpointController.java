package org.apereo.cas.oidc.web.controllers.jwks;

import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.support.oauth.web.endpoints.BaseOAuth20Controller;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.jooq.lambda.Unchecked;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;

/**
 * This is {@link OidcJwksEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@Slf4j
public class OidcJwksEndpointController extends BaseOAuth20Controller {
    private final Resource jwksFile;

    public OidcJwksEndpointController(final OAuth20ConfigurationContext oAuthConfigurationContext) {
        super(oAuthConfigurationContext);
        this.jwksFile = oAuthConfigurationContext.getCasProperties().getAuthn().getOidc().getJwksFile();
    }

    /**
     * Handle request for jwk set.
     *
     * @param request  the request
     * @param response the response
     * @param model    the model
     * @return the jwk set
     */
    @GetMapping(value = '/' + OidcConstants.BASE_OIDC_URL + '/' + OidcConstants.JWKS_URL, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleRequestInternal(final HttpServletRequest request,
                                                        final HttpServletResponse response,
                                                        final Model model) {
        try {
            val jsonJwks = IOUtils.toString(this.jwksFile.getInputStream(), StandardCharsets.UTF_8);
            val jsonWebKeySet = new JsonWebKeySet(jsonJwks);

            getOAuthConfigurationContext().getServicesManager().getAllServices()
                .stream()
                .filter(s -> s instanceof OidcRegisteredService && StringUtils.isNotBlank(((OidcRegisteredService) s).getJwks()))
                .forEach(
                    Unchecked.consumer(s -> {
                        val service = (OidcRegisteredService) s;
                        val resource = getOAuthConfigurationContext().getResourceLoader().getResource(service.getJwks());
                        val set = new JsonWebKeySet(IOUtils.toString(resource.getInputStream(), StandardCharsets.UTF_8));
                        set.getJsonWebKeys().forEach(jsonWebKeySet::addJsonWebKey);
                    }));
            val body = jsonWebKeySet.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            return new ResponseEntity<>(body, HttpStatus.OK);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
}
