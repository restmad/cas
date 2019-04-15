package org.apereo.cas.token;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.RegisteredServiceCipherExecutor;
import org.apereo.cas.services.ServicesManager;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.hjson.JsonValue;
import org.hjson.Stringify;

import java.io.Serializable;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * This is {@link JwtBuilder}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Slf4j
@RequiredArgsConstructor
@Getter
public class JwtBuilder {
    private final String casSeverPrefix;
    private final CipherExecutor<Serializable, String> defaultTokenCipherExecutor;
    private final ServicesManager servicesManager;
    private final RegisteredServiceCipherExecutor registeredServiceCipherExecutor;

    /**
     * Build JWT.
     *
     * @param payload the payload
     * @return the jwt
     */
    public String build(final JwtRequest payload) {
        val serviceAudience = payload.getServiceAudience();
        val claims = new JWTClaimsSet.Builder()
            .audience(serviceAudience)
            .issuer(casSeverPrefix)
            .jwtID(payload.getJwtId())
            .issueTime(payload.getIssueDate())
            .subject(payload.getSubject());

        payload.getAttributes().forEach(claims::claim);
        claims.expirationTime(payload.getValidUntilDate());

        val claimsSet = claims.build();
        val object = claimsSet.toJSONObject();

        val jwtJson = object.toJSONString();
        LOGGER.debug("Generated JWT [{}]", JsonValue.readJSON(jwtJson).toString(Stringify.FORMATTED));

        LOGGER.trace("Locating service [{}] in service registry", serviceAudience);
        val registeredService = this.servicesManager.findServiceBy(serviceAudience);
        RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(registeredService);

        LOGGER.trace("Locating service specific signing and encryption keys for [{}] in service registry", serviceAudience);
        if (registeredServiceCipherExecutor.supports(registeredService)) {
            LOGGER.trace("Encoding JWT based on keys provided by service [{}]", registeredService.getServiceId());
            return registeredServiceCipherExecutor.encode(jwtJson, Optional.of(registeredService));
        }

        if (defaultTokenCipherExecutor.isEnabled()) {
            LOGGER.trace("Encoding JWT based on default global keys for [{}]", serviceAudience);
            return defaultTokenCipherExecutor.encode(jwtJson);
        }
        val header = new PlainHeader.Builder()
            .type(JOSEObjectType.JWT)
            .build();
        val token = new PlainJWT(header, claimsSet).serialize();
        LOGGER.trace("Generating plain JWT as the ticket: [{}]", token);
        return token;
    }

    /**
     * The type Jwt request that allows the builder to create JWTs.
     */
    @Builder
    @Getter
    public static class JwtRequest {
        private final String jwtId;
        private final String serviceAudience;
        private final Date issueDate;
        private final String subject;
        private final Date validUntilDate;

        @Builder.Default
        private final Map<String, List<Object>> attributes = new LinkedHashMap<>();
    }
}
