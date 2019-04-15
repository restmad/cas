package org.apereo.cas.authentication.principal.resolvers;

import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.handler.PrincipalNameTransformer;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.util.CollectionUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.Synchronized;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.apereo.services.persondir.support.StubPersonAttributeDao;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Resolves principals by querying a data source using the Person Directory API.
 * The {@link Principal#getAttributes()} are populated by the results of the
 * query and the principal ID may optionally be set by proving an attribute whose first non-null value is used;
 * otherwise the credential ID is used for the principal ID.
 *
 * @author Marvin S. Addison
 * @since 4.0.0
 */
@Slf4j
@ToString
@RequiredArgsConstructor
@Getter
@Setter
public class PersonDirectoryPrincipalResolver implements PrincipalResolver {

    /**
     * Repository of principal attributes to be retrieved.
     */
    protected final IPersonAttributeDao attributeRepository;

    /**
     * Factory to create the principal type.
     **/
    protected final PrincipalFactory principalFactory;

    /**
     * return null if no attributes are found.
     */
    protected final boolean returnNullIfNoAttributes;

    /**
     * Transform principal name.
     */
    protected final PrincipalNameTransformer principalNameTransformer;

    /**
     * Optional principal attribute name.
     */
    protected final String principalAttributeNames;

    /**
     * Use the current principal id for extraction.
     */
    protected final boolean useCurrentPrincipalId;

    /**
     * Whether attributes should be fetched from attribute repositories.
     */
    protected final boolean resolveAttributes;

    /**
     * Active attribute repositories ids for this resolver
     * to use for attribute resolution.
     */
    protected final Set<String> activeAttributeRepositoryIdentifiers;

    public PersonDirectoryPrincipalResolver() {
        this(new StubPersonAttributeDao(new HashMap<>()), PrincipalFactoryUtils.newPrincipalFactory(), false,
            String::trim, null,
            false, true,
            CollectionUtils.wrapSet(IPersonAttributeDao.WILDCARD));
    }

    public PersonDirectoryPrincipalResolver(final IPersonAttributeDao attributeRepository, final String principalAttributeNames) {
        this(attributeRepository, PrincipalFactoryUtils.newPrincipalFactory(),
            false, formUserId -> formUserId, principalAttributeNames,
            false, true, CollectionUtils.wrapSet(IPersonAttributeDao.WILDCARD));
    }

    public PersonDirectoryPrincipalResolver(final IPersonAttributeDao attributeRepository) {
        this(attributeRepository, PrincipalFactoryUtils.newPrincipalFactory(),
            false, formUserId -> formUserId, null,
            false, true,
            CollectionUtils.wrapSet(IPersonAttributeDao.WILDCARD));
    }

    public PersonDirectoryPrincipalResolver(final boolean returnNullIfNoAttributes, final String principalAttributeNames) {
        this(new StubPersonAttributeDao(new HashMap<>()), PrincipalFactoryUtils.newPrincipalFactory(),
            returnNullIfNoAttributes, String::trim, principalAttributeNames,
            false, true,
            CollectionUtils.wrapSet(IPersonAttributeDao.WILDCARD));
    }

    public PersonDirectoryPrincipalResolver(final IPersonAttributeDao attributeRepository,
                                            final PrincipalFactory principalFactory,
                                            final boolean returnNullIfNoAttributes,
                                            final String principalAttributeNames,
                                            final boolean useCurrentPrincipalId) {
        this(attributeRepository, principalFactory, returnNullIfNoAttributes,
            formUserId -> formUserId, principalAttributeNames, useCurrentPrincipalId, true,
            CollectionUtils.wrapSet(IPersonAttributeDao.WILDCARD));
    }

    public PersonDirectoryPrincipalResolver(final IPersonAttributeDao attributeRepository,
                                            final PrincipalFactory principalFactory,
                                            final boolean returnNullIfNoAttributes,
                                            final String principalAttributeNames,
                                            final boolean useCurrentPrincipalId,
                                            final boolean resolveAttributes) {
        this(attributeRepository, principalFactory, returnNullIfNoAttributes,
            formUserId -> formUserId, principalAttributeNames,
            useCurrentPrincipalId, resolveAttributes,
            CollectionUtils.wrapSet(IPersonAttributeDao.WILDCARD));
    }

    public PersonDirectoryPrincipalResolver(final IPersonAttributeDao attributeRepository,
                                            final PrincipalFactory principalFactory,
                                            final boolean returnNullIfNoAttributes,
                                            final String principalAttributeNames,
                                            final boolean useCurrentPrincipalId,
                                            final boolean resolveAttributes,
                                            final Set<String> activeAttributeRepositoryIdentifiers) {
        this(attributeRepository, principalFactory, returnNullIfNoAttributes,
            formUserId -> formUserId, principalAttributeNames,
            useCurrentPrincipalId, resolveAttributes, activeAttributeRepositoryIdentifiers);
    }

    @Override
    public boolean supports(final Credential credential) {
        return credential != null && credential.getId() != null;
    }

    @Override
    public Principal resolve(final Credential credential, final Optional<Principal> currentPrincipal, final Optional<AuthenticationHandler> handler) {
        LOGGER.debug("Attempting to resolve a principal...");
        var principalId = extractPrincipalId(credential, currentPrincipal);
        if (StringUtils.isBlank(principalId)) {
            LOGGER.debug("Principal id [{}] could not be found", principalId);
            return null;
        }
        if (principalNameTransformer != null) {
            principalId = principalNameTransformer.transform(principalId);
        }
        if (StringUtils.isBlank(principalId)) {
            LOGGER.debug("Principal id [{}] could not be found", principalId);
            return null;
        }
        LOGGER.debug("Creating principal for [{}]", principalId);
        if (this.resolveAttributes) {
            val attributes = retrievePersonAttributes(principalId, credential);
            if (attributes == null || attributes.isEmpty()) {
                LOGGER.debug("Principal id [{}] did not specify any attributes", principalId);
                if (!this.returnNullIfNoAttributes) {
                    LOGGER.debug("Returning the principal with id [{}] without any attributes", principalId);
                    return this.principalFactory.createPrincipal(principalId);
                }
                LOGGER.debug("[{}] is configured to return null if no attributes are found for [{}]", this.getClass().getName(), principalId);
                return null;
            }
            LOGGER.debug("Retrieved [{}] attribute(s) from the repository", attributes.size());
            val pair = convertPersonAttributesToPrincipal(principalId, attributes);
            val principal = this.principalFactory.createPrincipal(pair.getKey(), pair.getValue());
            LOGGER.debug("Final resolved principal by [{}] is [{}]", getName(), principal);
            return principal;
        }
        val principal = this.principalFactory.createPrincipal(principalId);
        LOGGER.debug("Final resolved principal by [{}] without resolving attributes is [{}]", getName(), principal);
        return principal;
    }

    /**
     * Convert person attributes to principal pair.
     *
     * @param extractedPrincipalId the extracted principal id
     * @param attributes           the attributes
     * @return the pair
     */
    protected Pair<String, Map<String, List<Object>>> convertPersonAttributesToPrincipal(final String extractedPrincipalId,
                                                                                         final Map<String, List<Object>> attributes) {
        val convertedAttributes = new LinkedHashMap<String, List<Object>>();
        attributes.forEach((key, attrValue) -> {
            val values = CollectionUtils.toCollection(attrValue, ArrayList.class);
            LOGGER.debug("Found attribute [{}] with value(s) [{}]", key, values);
            if (values.size() == 1) {
                val value = CollectionUtils.firstElement(values).get();
                convertedAttributes.put(key, CollectionUtils.wrapList(value));
            } else {
                convertedAttributes.put(key, values);
            }
        });

        var principalId = extractedPrincipalId;

        if (StringUtils.isNotBlank(this.principalAttributeNames)) {
            val attrNames = org.springframework.util.StringUtils.commaDelimitedListToSet(this.principalAttributeNames);
            val result = attrNames.stream()
                .map(String::trim)
                .filter(attributes::containsKey)
                .map(attributes::get)
                .findFirst();

            if (result.isPresent()) {
                val values = result.get();
                if (!values.isEmpty()) {
                    principalId = CollectionUtils.firstElement(values).get().toString();
                    LOGGER.debug("Found principal id attribute value [{}] and removed it from the collection of attributes", principalId);
                }
            } else {
                LOGGER.warn("Principal resolution is set to resolve the authenticated principal via attribute(s) [{}], and yet "
                    + "the collection of attributes retrieved [{}] do not contain any of those attributes. This is likely due to misconfiguration "
                    + "and CAS will switch to use [{}] as the final principal id", this.principalAttributeNames, attributes.keySet(), principalId);
            }
        }

        return Pair.of(principalId, convertedAttributes);
    }

    /**
     * Retrieve person attributes map.
     *
     * @param principalId the principal id
     * @param credential  the credential whose id we have extracted. This is passed so that implementations
     *                    can extract useful bits of authN info such as attributes into the principal.
     * @return the map
     */
    @Synchronized
    protected Map<String, List<Object>> retrievePersonAttributes(final String principalId, final Credential credential) {
        return CoreAuthenticationUtils.retrieveAttributesFromAttributeRepository(this.attributeRepository, principalId, activeAttributeRepositoryIdentifiers);
    }

    /**
     * Extracts the id of the user from the provided credential. This method should be overridden by subclasses to
     * achieve more sophisticated strategies for producing a principal ID from a credential.
     *
     * @param credential       the credential provided by the user.
     * @param currentPrincipal the current principal
     * @return the username, or null if it could not be resolved.
     */
    protected String extractPrincipalId(final Credential credential, final Optional<Principal> currentPrincipal) {
        LOGGER.debug("Extracting credential id based on existing credential [{}]", credential);
        val id = credential.getId();
        if (currentPrincipal != null && currentPrincipal.isPresent()) {
            val principal = currentPrincipal.get();
            LOGGER.debug("Principal is currently resolved as [{}]", principal);
            if (useCurrentPrincipalId) {
                LOGGER.debug("Using the existing resolved principal id [{}]", principal.getId());
                return principal.getId();
            } else {
                LOGGER.debug("CAS will NOT be using the identifier from the resolved principal [{}] as it's not "
                    + "configured to use the currently-resolved principal id and will fall back onto using the identifier "
                    + "for the credential, that is [{}], for principal resolution", principal, id);
            }
        } else {
            LOGGER.debug("No principal is currently resolved and available. Falling back onto using the identifier "
                + " for the credential, that is [{}], for principal resolution", id);
        }
        LOGGER.debug("Extracted principal id [{}]", id);
        return id;
    }

}
