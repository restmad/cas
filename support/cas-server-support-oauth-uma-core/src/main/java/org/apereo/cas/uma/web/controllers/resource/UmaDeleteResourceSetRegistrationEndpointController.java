package org.apereo.cas.uma.web.controllers.resource;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicketFactory;
import org.apereo.cas.uma.ticket.resource.InvalidResourceSetException;
import org.apereo.cas.uma.ticket.resource.repository.ResourceSetRepository;
import org.apereo.cas.uma.web.controllers.BaseUmaEndpointController;
import org.apereo.cas.util.CollectionUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is {@link UmaDeleteResourceSetRegistrationEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Controller("umaDeleteResourceSetRegistrationEndpointController")
@Slf4j
public class UmaDeleteResourceSetRegistrationEndpointController extends BaseUmaEndpointController {

    public UmaDeleteResourceSetRegistrationEndpointController(final UmaPermissionTicketFactory umaPermissionTicketFactory,
                                                              final ResourceSetRepository umaResourceSetRepository,
                                                              final CasConfigurationProperties casProperties) {
        super(umaPermissionTicketFactory, umaResourceSetRepository, casProperties);
    }

    /**
     * Delete resource set response entity.
     *
     * @param id       the id
     * @param request  the request
     * @param response the response
     * @return the response entity
     */
    @DeleteMapping(value = '/' + OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.UMA_RESOURCE_SET_REGISTRATION_URL + "/{id}",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity deleteResourceSet(@PathVariable("id") final long id, final HttpServletRequest request, final HttpServletResponse response) {
        try {
            val profileResult = getAuthenticatedProfile(request, response, OAuth20Constants.UMA_PROTECTION_SCOPE);
            val resourceSetResult = umaResourceSetRepository.getById(id);
            if (resourceSetResult.isEmpty()) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "Requested resource-set cannot be found");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }
            val resourceSet = resourceSetResult.get();
            resourceSet.validate(profileResult);
            if (!resourceSet.getClientId().equalsIgnoreCase(OAuth20Utils.getClientIdFromAuthenticatedProfile(profileResult))) {
                throw new InvalidResourceSetException(HttpStatus.FORBIDDEN.value(), "Resource-set owner does not match the authenticated profile");
            }
            umaResourceSetRepository.remove(resourceSet);
            return new ResponseEntity(CollectionUtils.wrap("code", HttpStatus.NO_CONTENT, "resourceId", resourceSet.getId()), HttpStatus.OK);
        } catch (final InvalidResourceSetException e) {
            return new ResponseEntity(buildResponseEntityErrorModel(e), HttpStatus.BAD_REQUEST);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return new ResponseEntity("Unable to complete the delete request.", HttpStatus.BAD_REQUEST);
    }
}
