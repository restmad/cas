package org.apereo.cas.uma.web.controllers.permission;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicketFactory;
import org.apereo.cas.uma.ticket.resource.repository.ResourceSetRepository;
import org.apereo.cas.uma.web.controllers.BaseUmaEndpointController;
import org.apereo.cas.util.CollectionUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is {@link UmaPermissionRegistrationEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Controller("umaPermissionRegistrationEndpointController")
@Slf4j
public class UmaPermissionRegistrationEndpointController extends BaseUmaEndpointController {

    private final TicketRegistry ticketRegistry;

    public UmaPermissionRegistrationEndpointController(final UmaPermissionTicketFactory umaPermissionTicketFactory,
                                                       final ResourceSetRepository umaResourceSetRepository,
                                                       final CasConfigurationProperties casProperties,
                                                       final TicketRegistry ticketRegistry) {
        super(umaPermissionTicketFactory, umaResourceSetRepository, casProperties);
        this.ticketRegistry = ticketRegistry;
    }

    /**
     * Gets permission ticket.
     *
     * @param body     the body
     * @param request  the request
     * @param response the response
     * @return the permission ticket
     */
    @PostMapping(value = '/' + OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.UMA_PERMISSION_URL,
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity handle(@RequestBody final String body, final HttpServletRequest request, final HttpServletResponse response) {
        try {
            val profileResult = getAuthenticatedProfile(request, response, OAuth20Constants.UMA_PROTECTION_SCOPE);

            val umaRequest = MAPPER.readValue(body, UmaPermissionRegistrationRequest.class);
            if (umaRequest == null) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "UMA request cannot be found or parsed");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val resourceSetResult = umaResourceSetRepository.getById(umaRequest.getResourceId());
            if (resourceSetResult.isEmpty()) {
                val model = buildResponseEntityErrorModel(HttpStatus.NOT_FOUND, "Requested resource-set cannot be found");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val resourceSet = resourceSetResult.get();
            if (!resourceSet.getOwner().equals(profileResult.getId())) {
                val model = buildResponseEntityErrorModel(HttpStatus.FORBIDDEN, "Resource-set owner does not match the authenticated profile");
                return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
            }

            val permission = umaPermissionTicketFactory.create(resourceSet, umaRequest.getScopes(), umaRequest.getClaims());

            if (permission != null) {
                ticketRegistry.addTicket(permission);

                val model = CollectionUtils.wrap("ticket", permission.getId(), "code", HttpStatus.CREATED);
                return new ResponseEntity(model, HttpStatus.OK);
            }

            val model = buildResponseEntityErrorModel(HttpStatus.INTERNAL_SERVER_ERROR, "Unable to generate permission ticket");
            return new ResponseEntity(model, model, HttpStatus.BAD_REQUEST);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return new ResponseEntity("Unable to complete the permission registration request.", HttpStatus.BAD_REQUEST);
    }
}
