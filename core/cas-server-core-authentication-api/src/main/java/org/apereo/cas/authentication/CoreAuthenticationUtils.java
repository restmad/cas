package org.apereo.cas.authentication;

import org.apereo.cas.authentication.support.password.DefaultPasswordPolicyHandlingStrategy;
import org.apereo.cas.authentication.support.password.GroovyPasswordPolicyHandlingStrategy;
import org.apereo.cas.authentication.support.password.RejectResultCodePasswordPolicyHandlingStrategy;
import org.apereo.cas.configuration.model.core.authentication.PasswordPolicyProperties;
import org.apereo.cas.configuration.support.Beans;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.validation.Assertion;

import com.google.common.base.Splitter;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import groovy.lang.GroovyClassLoader;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.apereo.services.persondir.IPersonAttributeDaoFilter;
import org.apereo.services.persondir.support.merger.BaseAdditiveAttributeMerger;
import org.apereo.services.persondir.support.merger.IAttributeMerger;
import org.apereo.services.persondir.support.merger.MultivaluedAttributeMerger;
import org.apereo.services.persondir.support.merger.NoncollidingAttributeAdder;
import org.apereo.services.persondir.support.merger.ReplacingAttributeAdder;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.springframework.core.io.DefaultResourceLoader;

import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This is {@link CoreAuthenticationUtils}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */

@Slf4j
@UtilityClass
public class CoreAuthenticationUtils {

    /**
     * Convert attribute values to multi valued objects.
     *
     * @param attributes the attributes
     * @return the map of attributes to return
     */
    public static Map<String, List<Object>> convertAttributeValuesToMultiValuedObjects(final Map<String, Object> attributes) {
        val entries = attributes.entrySet();
        return entries
            .stream()
            .collect(Collectors.toMap(Map.Entry::getKey, entry -> {
                val value = entry.getValue();
                return CollectionUtils.toCollection(value, ArrayList.class);
            }));
    }

    /**
     * Retrieve attributes from attribute repository and return map.
     *
     * @param attributeRepository                  the attribute repository
     * @param principalId                          the principal id
     * @param activeAttributeRepositoryIdentifiers the active attribute repository identifiers
     * @return the map or null
     */
    public static Map<String, List<Object>> retrieveAttributesFromAttributeRepository(final IPersonAttributeDao attributeRepository,
                                                                                      final String principalId,
                                                                                      final Set<String> activeAttributeRepositoryIdentifiers) {
        var filter = IPersonAttributeDaoFilter.alwaysChoose();
        if (activeAttributeRepositoryIdentifiers != null && !activeAttributeRepositoryIdentifiers.isEmpty()) {
            val repoIdsArray = activeAttributeRepositoryIdentifiers.toArray(ArrayUtils.EMPTY_STRING_ARRAY);
            filter = dao -> Arrays.stream(dao.getId())
                .anyMatch(daoId -> daoId.equalsIgnoreCase(IPersonAttributeDao.WILDCARD)
                    || StringUtils.equalsAnyIgnoreCase(daoId, repoIdsArray)
                    || StringUtils.equalsAnyIgnoreCase(IPersonAttributeDao.WILDCARD, repoIdsArray));
        }
        val attrs = attributeRepository.getPerson(principalId, filter);
        if (attrs == null) {
            return new HashMap<>(0);
        }
        return attrs.getAttributes();

    }

    /**
     * Gets attribute merger.
     *
     * @param mergingPolicy the merging policy
     * @return the attribute merger
     */
    public static IAttributeMerger getAttributeMerger(final String mergingPolicy) {
        switch (mergingPolicy.toLowerCase()) {
            case "multivalued":
            case "multi_valued":
            case "combine":
                return new MultivaluedAttributeMerger();
            case "add":
                return new NoncollidingAttributeAdder();
            case "replace":
            case "overwrite":
            case "override":
                return new ReplacingAttributeAdder();
            default:
                return new BaseAdditiveAttributeMerger() {
                    @Override
                    protected Map<String, List<Object>> mergePersonAttributes(final Map<String, List<Object>> toModify,
                                                                              final Map<String, List<Object>> toConsider) {
                        return new LinkedHashMap<>(toModify);
                    }
                };
        }
    }

    /**
     * Is remember me authentication?
     * looks at the authentication object to find {@link RememberMeCredential#AUTHENTICATION_ATTRIBUTE_REMEMBER_ME}
     * and expects the assertion to also note a new login session.
     *
     * @param model     the model
     * @param assertion the assertion
     * @return true if remember-me, false if otherwise.
     */
    public static boolean isRememberMeAuthentication(final Authentication model, final Assertion assertion) {
        val authnAttributes = model.getAttributes();
        val authnMethod = authnAttributes.get(RememberMeCredential.AUTHENTICATION_ATTRIBUTE_REMEMBER_ME);
        return authnMethod != null && authnMethod.contains(Boolean.TRUE) && assertion.isFromNewLogin();
    }

    /**
     * Merge attributes map.
     *
     * @param currentAttributes the current attributes
     * @param attributesToMerge the attributes to merge
     * @return the map
     */
    public static Map<String, List<Object>> mergeAttributes(final Map<String, List<Object>> currentAttributes, final Map<String, List<Object>> attributesToMerge) {
        val merger = new MultivaluedAttributeMerger();

        val toModify = currentAttributes.entrySet()
            .stream()
            .map(entry -> Pair.of(entry.getKey(), CollectionUtils.toCollection(entry.getValue(), ArrayList.class)))
            .collect(Collectors.toMap(Pair::getKey, Pair::getValue));

        val toMerge = attributesToMerge.entrySet()
            .stream()
            .map(entry -> Pair.of(entry.getKey(), CollectionUtils.toCollection(entry.getValue(), ArrayList.class)))
            .collect(Collectors.toMap(Pair::getKey, Pair::getValue));

        LOGGER.trace("Merging current attributes [{}] with [{}]", toModify, toMerge);
        val results = merger.mergeAttributes((Map) toModify, (Map) toMerge);
        LOGGER.debug("Merged attributes with the final result as [{}]", results);
        return results;
    }

    /**
     * Transform principal attributes list into map map.
     *
     * @param list the list
     * @return the map
     */
    public static Map<String, Object> transformPrincipalAttributesListIntoMap(final List<String> list) {
        val map = transformPrincipalAttributesListIntoMultiMap(list);
        return CollectionUtils.wrap(map);
    }

    /**
     * Transform principal attributes into map.
     * Items in the list are defined in the syntax of "cn", or "cn:commonName" for virtual renaming and maps.
     *
     * @param list the list
     * @return the map
     */
    public static Multimap<String, Object> transformPrincipalAttributesListIntoMultiMap(final List<String> list) {
        val multimap = ArrayListMultimap.<String, Object>create();
        if (list.isEmpty()) {
            LOGGER.debug("No principal attributes are defined");
        } else {
            list.forEach(a -> {
                val attributeName = a.trim();
                if (attributeName.contains(":")) {
                    val attrCombo = Splitter.on(":").splitToList(attributeName);
                    val name = attrCombo.get(0).trim();
                    val value = attrCombo.get(1).trim();
                    LOGGER.debug("Mapped principal attribute name [{}] to [{}]", name, value);
                    multimap.put(name, value);
                } else {
                    LOGGER.debug("Mapped principal attribute name [{}]", attributeName);
                    multimap.put(attributeName, attributeName);
                }
            });
        }
        return multimap;
    }


    /**
     * Gets credential selection predicate.
     *
     * @param selectionCriteria the selection criteria
     * @return the credential selection predicate
     */
    public static Predicate<Credential> newCredentialSelectionPredicate(final String selectionCriteria) {
        try {
            if (StringUtils.isBlank(selectionCriteria)) {
                return credential -> true;
            }

            if (selectionCriteria.endsWith(".groovy")) {
                val loader = new DefaultResourceLoader();
                val resource = loader.getResource(selectionCriteria);
                val script = IOUtils.toString(resource.getInputStream(), StandardCharsets.UTF_8);

                val clz = AccessController.doPrivileged((PrivilegedAction<Class<Predicate>>) () -> {
                    val classLoader = new GroovyClassLoader(Beans.class.getClassLoader(),
                        new CompilerConfiguration(), true);
                    return classLoader.parseClass(script);
                });
                return clz.getDeclaredConstructor().newInstance();

            }

            val predicateClazz = ClassUtils.getClass(selectionCriteria);
            return (Predicate<org.apereo.cas.authentication.Credential>) predicateClazz.getDeclaredConstructor().newInstance();
        } catch (final Exception e) {
            val predicate = Pattern.compile(selectionCriteria).asPredicate();
            return credential -> predicate.test(credential.getId());
        }
    }

    /**
     * New password policy handling strategy.
     *
     * @param properties the properties
     * @return the authentication password policy handling strategy
     */
    public static AuthenticationPasswordPolicyHandlingStrategy newPasswordPolicyHandlingStrategy(final PasswordPolicyProperties properties) {
        if (properties.getStrategy() == PasswordPolicyProperties.PasswordPolicyHandlingOptions.REJECT_RESULT_CODE) {
            LOGGER.debug("Created password policy handling strategy based on blacklisted authentication result codes");
            return new RejectResultCodePasswordPolicyHandlingStrategy();
        }

        val location = properties.getGroovy().getLocation();
        if (properties.getStrategy() == PasswordPolicyProperties.PasswordPolicyHandlingOptions.GROOVY && location != null) {
            LOGGER.debug("Created password policy handling strategy based on Groovy script [{}]", location);
            return new GroovyPasswordPolicyHandlingStrategy(location);
        }

        LOGGER.trace("Created default password policy handling strategy");
        return new DefaultPasswordPolicyHandlingStrategy();
    }
}
