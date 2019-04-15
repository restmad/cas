package org.apereo.cas.web.view;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.support.WebUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.thymeleaf.IEngineConfiguration;
import org.thymeleaf.templateresolver.FileTemplateResolver;
import org.thymeleaf.templateresource.ITemplateResource;

import java.util.Map;

/**
 * This is {@link ThemeFileTemplateResolver}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@RequiredArgsConstructor
@Getter
@Slf4j
public class ThemeFileTemplateResolver extends FileTemplateResolver {
    /**
     * CAS settings.
     */
    protected final CasConfigurationProperties casProperties;

    @Override
    protected ITemplateResource computeTemplateResource(final IEngineConfiguration configuration, final String ownerTemplate,
                                                        final String template, final String resourceName, final String characterEncoding,
                                                        final Map<String, Object> templateResolutionAttributes) {
        val themeName = getCurrentTheme();
        if (StringUtils.isNotBlank(themeName)) {
            val themeTemplate = String.format(resourceName, themeName);
            LOGGER.trace("Computing template resource [{}]...", themeTemplate);
            return super.computeTemplateResource(configuration, ownerTemplate, template, themeTemplate, characterEncoding, templateResolutionAttributes);
        }
        return super.computeTemplateResource(configuration, ownerTemplate, template, resourceName, characterEncoding, templateResolutionAttributes);
    }

    /**
     * Gets current theme.
     *
     * @return the current theme
     */
    protected String getCurrentTheme() {
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext();
        if (request != null) {
            val session = request.getSession(false);
            val paramName = casProperties.getTheme().getParamName();
            if (session != null) {
                return (String) session.getAttribute(paramName);
            }
            return (String) request.getAttribute(paramName);
        }
        return null;
    }
}
