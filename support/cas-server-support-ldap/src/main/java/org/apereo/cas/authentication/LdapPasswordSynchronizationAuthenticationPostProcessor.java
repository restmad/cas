package org.apereo.cas.authentication;

import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.configuration.model.support.ldap.AbstractLdapSearchProperties;
import org.apereo.cas.util.LdapUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.ldaptive.AttributeModification;
import org.ldaptive.AttributeModificationType;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.ModifyOperation;
import org.ldaptive.ModifyRequest;
import org.ldaptive.ResultCode;
import org.ldaptive.ad.UnicodePwdAttribute;

import java.util.Collections;

/**
 * This is {@link LdapPasswordSynchronizationAuthenticationPostProcessor}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Slf4j
public class LdapPasswordSynchronizationAuthenticationPostProcessor implements AuthenticationPostProcessor {
    private final ConnectionFactory searchFactory;
    private final AbstractLdapSearchProperties ldapProperties;

    public LdapPasswordSynchronizationAuthenticationPostProcessor(final AbstractLdapSearchProperties properties) {
        this.ldapProperties = properties;
        this.searchFactory = LdapUtils.newLdaptivePooledConnectionFactory(properties);
    }

    @Override
    public void process(final AuthenticationBuilder builder, final AuthenticationTransaction transaction) throws AuthenticationException {
        val primaryCredential = transaction.getPrimaryCredential();
        if (primaryCredential.isEmpty()) {
            LOGGER.warn("Current authentication transaction does not have a primary credential");
            return;
        }

        try {
            val credential = UsernamePasswordCredential.class.cast(primaryCredential.get());
            val filter = LdapUtils.newLdaptiveSearchFilter(ldapProperties.getSearchFilter(),
                LdapUtils.LDAP_SEARCH_FILTER_DEFAULT_PARAM_NAME, Collections.singletonList(credential.getUsername()));
            LOGGER.trace("Constructed LDAP filter [{}] to locate user and update password", filter);

            val response = LdapUtils.executeSearchOperation(searchFactory, ldapProperties.getBaseDn(), filter);
            LOGGER.debug("LDAP response is [{}]", response);

            if (LdapUtils.containsResultEntry(response)) {
                val searchResult = response.getResult();
                val dn = searchResult.getEntry().getDn();
                LOGGER.trace("Updating account password for [{}]", dn);

                try (val modifyConnection = LdapUtils.createConnection(searchFactory)) {
                    val operation = new ModifyOperation(modifyConnection);
                    val mod = new AttributeModification(AttributeModificationType.REPLACE, getLdapPasswordAttribute(credential));
                    val updateResponse = operation.execute(new ModifyRequest(dn, mod));
                    LOGGER.trace("Result code [{}], message: [{}]", searchResult, response.getMessage());
                    val result = updateResponse.getResultCode() == ResultCode.SUCCESS;
                    if (result) {
                        LOGGER.info("Updated the LDAP entry's password for [{}] and base DN [{}]", filter.format(), ldapProperties.getBaseDn());
                    } else {
                        LOGGER.warn("Could not update the LDAP entry's password for [{}] and base DN [{}]", filter.format(), ldapProperties.getBaseDn());
                    }
                }
            } else {
                LOGGER.error("Could not locate an LDAP entry for [{}] and base DN [{}]", filter.format(), ldapProperties.getBaseDn());
            }
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(final Credential credential) {
        return credential instanceof UsernamePasswordCredential;
    }

    /**
     * Gets ldap password attribute.
     *
     * @param credential the credential
     * @return the ldap password attribute
     */
    protected LdapAttribute getLdapPasswordAttribute(final UsernamePasswordCredential credential) {
        return new UnicodePwdAttribute(credential.getPassword());
    }
}
