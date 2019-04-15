package org.apereo.cas.uma.web.controllers.resource;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicketFactory;
import org.apereo.cas.uma.ticket.resource.InvalidResourceSetException;
import org.apereo.cas.uma.ticket.resource.repository.ResourceSetRepository;
import org.apereo.cas.uma.web.controllers.BaseUmaEndpointController;
import org.apereo.cas.util.CollectionUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is {@link UmaUpdateResourceSetRegistrationEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Controller("umaUpdateResourceSetRegistrationEndpointController")
@Slf4j
public class UmaUpdateResourceSetRegistrationEndpointController extends BaseUmaEndpointController {

    public UmaUpdateResourceSetRegistrationEndpointController(final UmaPermissionTicketFactory umaPermissionTicketFactory,
                                                              final ResourceSetRepository umaResourceSetRepository,
                                                              final CasConfigurationProperties casProperties) {
        super(umaPermissionTicketFactory, umaResourceSetRepository, casProperties);
    }

    /**
     * Update resource set response entity.
     *
     * @param id       the id
     * @param body     the body
     * @param request  the request
     * @param response the response
     * @return the response entity
     */
    @PutMapping(value = '/' + OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.UMA_RESOURCE_SET_REGISTRATION_URL + "/{id}",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity updateResourceSet(@PathVariable("id") final long id, @RequestBody final String body,
                                            final HttpServletRequest request, final HttpServletResponse response) {
        try {
            val profileResult = getAuthenticatedProfile(request, response, OAuth20Constants.UMA_PROTECTION_SCOPE);
            val umaRequest = MAPPER.readValue(body, UmaResourceRegistrationRequest.class);
            val newResource = umaRequest.asResourceSet(profileResult);
            newResource.validate(profileResult);

            if (StringUtils.isBlank(newResource.getName()) || newResource.getScopes().isEmpty() || newResource.getId() != id) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "Provided resource-set body is missing required fields");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val resourceSetResult = umaResourceSetRepository.getById(id);
            if (resourceSetResult.isEmpty()) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "Requested resource-set cannot be found");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }
            val resourceSet = resourceSetResult.get();
            resourceSet.validate(profileResult);

            val saved = umaResourceSetRepository.update(resourceSet, newResource);
            val location = getResourceSetUriLocation(saved);
            val model = CollectionUtils.wrap("entity", saved,
                "resourceId", saved.getId(),
                "location", location);
            return new ResponseEntity(model, HttpStatus.OK);
        } catch (final InvalidResourceSetException e) {
            return new ResponseEntity(buildResponseEntityErrorModel(e), HttpStatus.BAD_REQUEST);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return new ResponseEntity("Unable to complete the resource-set update request.", HttpStatus.BAD_REQUEST);
    }

}
