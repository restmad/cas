package org.apereo.cas.support.claims;

import org.apereo.cas.ws.idp.WSFederationConstants;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.sts.claims.ClaimsParameters;

import java.util.ArrayList;
import java.util.List;

/**
 * This is {@link NonWSFederationClaimsClaimsHandler}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@Slf4j
public class NonWSFederationClaimsClaimsHandler extends WrappingSecurityTokenServiceClaimsHandler {
    public NonWSFederationClaimsClaimsHandler(final String handlerRealm, final String issuer) {
        super(handlerRealm, issuer);
    }

    @SneakyThrows
    @Override
    protected String createProcessedClaimType(final Claim requestClaim, final ClaimsParameters parameters) {
        val tokenType = parameters.getTokenRequirements().getTokenType();
        if (WSFederationConstants.WSS_SAML2_TOKEN_TYPE.equalsIgnoreCase(tokenType)) {
            return StringUtils.remove(requestClaim.getClaimType(), WSFederationConstants.HTTP_SCHEMAS_APEREO_CAS);
        }
        return requestClaim.getClaimType();
    }

    @Override
    public List<String> getSupportedClaimTypes() {
        return new NonWSFederationClaimsList();
    }

    private static class NonWSFederationClaimsList extends ArrayList<String> {
        @Override
        public boolean contains(final Object o) {
            return o.toString().startsWith(WSFederationConstants.HTTP_SCHEMAS_APEREO_CAS);
        }
    }
}
