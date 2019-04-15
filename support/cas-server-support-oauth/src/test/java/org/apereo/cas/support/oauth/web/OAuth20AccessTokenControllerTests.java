package org.apereo.cas.support.oauth.web;

import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.WebApplicationServiceFactory;
import org.apereo.cas.mock.MockTicketGrantingTicket;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20AccessTokenEndpointController;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20DeviceUserCodeApprovalEndpointController;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.code.DefaultOAuthCodeFactory;
import org.apereo.cas.ticket.refreshtoken.DefaultRefreshTokenFactory;
import org.apereo.cas.ticket.support.AlwaysExpiresExpirationPolicy;
import org.apereo.cas.util.CollectionUtils;

import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This class tests the {@link OAuth20AccessTokenEndpointController} class.
 *
 * @author Jerome Leleu
 * @since 3.5.2
 */
public class OAuth20AccessTokenControllerTests extends AbstractOAuth20Tests {

    @BeforeEach
    public void initialize() {
        clearAllServices();
    }

    @Test
    @SneakyThrows
    public void verifyClientNoClientId() {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get("error"));
    }

    @Test
    public void verifyClientNoRedirectUri() throws Exception {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get("error"));
    }

    @Test
    @SneakyThrows
    public void verifyClientNoAuthorizationCode() {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get("error"));
    }

    @Test
    @SneakyThrows
    public void verifyClientBadGrantType() {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, "badValue");
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get("error"));
    }

    @Test
    public void verifyClientDisallowedGrantType() throws Exception {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.PASSWORD.getType());
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get("error"));
    }

    @Test
    @SneakyThrows
    public void verifyClientNoClientSecret() {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get("error"));
    }

    @Test
    public void verifyClientNoCode() throws Exception {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));

        addCode(principal, service);

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    @SneakyThrows
    public void verifyClientNoCasService() {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val registeredService = getRegisteredService(
                REDIRECT_URI, CLIENT_SECRET, CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, registeredService);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyClientRedirectUriDoesNotStartWithServiceId() throws Exception {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, OTHER_REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyClientWrongSecret() throws Exception {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, WRONG_CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    @SneakyThrows
    public void verifyClientEmptySecret() {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, StringUtils.EMPTY);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        val principal = createPrincipal();
        val service = addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE), StringUtils.EMPTY);
        val code = addCode(principal, service);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_OK, mockResponse.getStatus());
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
    }

    @Test
    public void verifyClientExpiredCode() throws Exception {
        val registeredService = getRegisteredService(REDIRECT_URI, CLIENT_SECRET, CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        servicesManager.save(registeredService);

        val map = new HashMap<String, List<Object>>();
        map.put(NAME, List.of(VALUE));
        val list = List.of(VALUE, VALUE);
        map.put(NAME2, (List) list);

        val principal = CoreAuthenticationTestUtils.getPrincipal(ID, map);
        val authentication = getAuthentication(principal);
        val expiringOAuthCodeFactory = new DefaultOAuthCodeFactory(new AlwaysExpiresExpirationPolicy());
        val factory = new WebApplicationServiceFactory();
        val service = factory.createService(registeredService.getServiceId());
        val code = expiringOAuthCodeFactory.create(service, authentication,
            new MockTicketGrantingTicket("casuser"), new ArrayList<>(), null, null);
        this.ticketRegistry.addTicket(code);

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.REDIRECT_URI, REDIRECT_URI);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.CODE, code.getId());
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        servicesManager.save(getRegisteredService(REDIRECT_URI, CLIENT_SECRET,
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE)));

        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyClientAuthByParameter() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        assertClientOK(service, false);
    }

    @Test
    public void verifyDeviceFlowGeneratesCode() throws Exception {
        addRegisteredService();
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.RESPONSE_TYPE, OAuth20ResponseTypes.DEVICE_CODE.getType());
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        val model = mv.getModel();
        assertTrue(model.containsKey(OAuth20Constants.DEVICE_CODE));
        assertTrue(model.containsKey(OAuth20Constants.DEVICE_VERIFICATION_URI));
        assertTrue(model.containsKey(OAuth20Constants.DEVICE_USER_CODE));
        assertTrue(model.containsKey(OAuth20Constants.DEVICE_INTERVAL));
        assertTrue(model.containsKey(OAuth20Constants.EXPIRES_IN));

        val devCode = model.get(OAuth20Constants.DEVICE_CODE).toString();
        val userCode = model.get(OAuth20Constants.DEVICE_USER_CODE).toString();

        val devReq = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.DEVICE_AUTHZ_URL);
        devReq.setParameter(OAuth20DeviceUserCodeApprovalEndpointController.PARAMETER_USER_CODE, userCode);
        val devResp = new MockHttpServletResponse();
        val mvDev = deviceController.handlePostRequest(devReq, devResp);
        assertNotNull(mvDev);
        val status = mvDev.getStatus();
        assertNotNull(status);
        assertTrue(status.is2xxSuccessful());

        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.RESPONSE_TYPE, OAuth20ResponseTypes.DEVICE_CODE.getType());
        mockRequest.setParameter(OAuth20Constants.CODE, devCode);
        val approveResp = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, approveResp, null);
        val mvApproved = controller.handleRequest(mockRequest, approveResp);
        assertTrue(mvApproved.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
        assertTrue(mvApproved.getModel().containsKey(OAuth20Constants.EXPIRES_IN));
        assertTrue(mvApproved.getModel().containsKey(OAuth20Constants.TOKEN_TYPE));
    }

    @Test
    public void verifyClientAuthByHeader() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        assertClientOK(service, false);
    }

    @Test
    public void verifyClientAuthByParameterWithRefreshToken() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        service.setGenerateRefreshToken(true);
        assertClientOK(service, true);
    }

    @Test
    public void verifyClientAuthByHeaderWithRefreshToken() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        service.setGenerateRefreshToken(true);
        assertClientOK(service, true);
    }

    @Test
    public void verifyClientAuthJsonByParameter() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        assertClientOK(service, false);
    }

    @Test
    public void verifyClientAuthJsonByHeader() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        assertClientOK(service, false);
    }

    @Test
    public void verifyClientAuthJsonByParameterWithRefreshToken() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        service.setGenerateRefreshToken(true);
        assertClientOK(service, true);
    }

    @Test
    public void verifyClientAuthJsonByHeaderWithRefreshToken() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));
        service.setGenerateRefreshToken(true);
        assertClientOK(service, true);
    }

    @Test
    @SneakyThrows
    public void ensureOnlyRefreshTokenIsAcceptedForRefreshGrant() {
        addRegisteredService(true, CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD,
                OAuth20GrantTypes.REFRESH_TOKEN));
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        val mockSession = new MockHttpSession();
        mockRequest.setSession(mockSession);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.PASSWORD.name().toLowerCase());
        mockRequest.setParameter(USERNAME, GOOD_USERNAME);
        mockRequest.setParameter(PASSWORD, GOOD_PASSWORD);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);

        var mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        var mv = controller.handleRequest(mockRequest, mockResponse);

        assertTrue(mv.getModel().containsKey(OAuth20Constants.REFRESH_TOKEN));
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
        val refreshToken = mv.getModel().get(OAuth20Constants.REFRESH_TOKEN).toString();
        val accessToken = mv.getModel().get(OAuth20Constants.ACCESS_TOKEN).toString();

        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.REFRESH_TOKEN.name().toLowerCase());
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.REFRESH_TOKEN, accessToken);

        mockResponse = new MockHttpServletResponse();
        controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());

        mockRequest.setParameter(OAuth20Constants.REFRESH_TOKEN, refreshToken);
        mockResponse = new MockHttpServletResponse();
        mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_OK, mockResponse.getStatus());
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
    }

    @Test
    public void verifyUserNoClientId() throws Exception {
        addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD));

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.PASSWORD.name().toLowerCase());
        mockRequest.setParameter(USERNAME, GOOD_USERNAME);
        mockRequest.setParameter(PASSWORD, GOOD_PASSWORD);
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyUserNoCasService() throws Exception {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.PASSWORD.name().toLowerCase());
        mockRequest.setParameter(USERNAME, GOOD_USERNAME);
        mockRequest.setParameter(PASSWORD, GOOD_PASSWORD);
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyUserBadAuthorizationCode() throws Exception {
        addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.AUTHORIZATION_CODE));

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.AUTHORIZATION_CODE.name().toLowerCase());
        mockRequest.setParameter(USERNAME, GOOD_USERNAME);
        mockRequest.setParameter(PASSWORD, GOOD_PASSWORD);
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyUserBadCredentials() throws Exception {
        addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD));

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.PASSWORD.name().toLowerCase());
        mockRequest.setParameter(USERNAME, GOOD_USERNAME);
        mockRequest.setParameter(PASSWORD, "badPassword");
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyUserAuth() {
        addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD));
        assertUserAuth(false);
    }

    @Test
    public void verifyUserAuthWithRefreshToken() {
        val registeredService = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD));
        registeredService.setGenerateRefreshToken(true);
        assertUserAuth(true);
    }

    @Test
    public void verifyJsonUserAuth() {
        addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD));
        assertUserAuth(false);
    }

    @Test
    public void verifyJsonUserAuthWithRefreshToken() {
        val registeredService = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.PASSWORD));
        registeredService.setGenerateRefreshToken(true);
        assertUserAuth(true);
    }

    @SneakyThrows
    private void assertUserAuth(final boolean refreshToken) {
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.PASSWORD.name().toLowerCase());
        mockRequest.setParameter(USERNAME, GOOD_USERNAME);
        mockRequest.setParameter(PASSWORD, GOOD_PASSWORD);
        mockRequest.addHeader(CasProtocolConstants.PARAMETER_SERVICE, REDIRECT_URI);
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(200, mockResponse.getStatus());
        var accessTokenId = StringUtils.EMPTY;
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
        if (refreshToken) {
            assertTrue(mv.getModel().containsKey(OAuth20Constants.REFRESH_TOKEN));
        }
        assertTrue(mv.getModel().containsKey(OAuth20Constants.EXPIRES_IN));

        accessTokenId = mv.getModel().get(OAuth20Constants.ACCESS_TOKEN).toString();

        val accessToken = this.ticketRegistry.getTicket(accessTokenId, AccessToken.class);
        assertEquals(GOOD_USERNAME, accessToken.getAuthentication().getPrincipal().getId());

        val timeLeft = Integer.parseInt(mv.getModel().get(OAuth20Constants.EXPIRES_IN).toString());
        assertTrue(timeLeft >= TIMEOUT - 10 - DELTA);
    }

    @Test
    @SneakyThrows
    public void verifyRefreshTokenExpiredToken() {
        val principal = createPrincipal();
        val registeredService = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));
        val authentication = getAuthentication(principal);
        val factory = new WebApplicationServiceFactory();
        val service = factory.createService(registeredService.getServiceId());
        val expiringRefreshTokenFactory = new DefaultRefreshTokenFactory(new AlwaysExpiresExpirationPolicy());
        val refreshToken = expiringRefreshTokenFactory.create(service, authentication,
            new MockTicketGrantingTicket("casuser"), new ArrayList<>());
        this.ticketRegistry.addTicket(refreshToken);

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.REFRESH_TOKEN.name().toLowerCase());
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.REFRESH_TOKEN, refreshToken.getId());
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyRefreshTokenBadCredentials() throws Exception {
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));
        val refreshToken = addRefreshToken(principal, service);

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.REFRESH_TOKEN.name().toLowerCase());
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, WRONG_CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.REFRESH_TOKEN, refreshToken.getId());
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyRefreshTokenEmptySecret() throws Exception {
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN), StringUtils.EMPTY);
        val refreshToken = addRefreshToken(principal, service);

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.REFRESH_TOKEN.name().toLowerCase());
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, StringUtils.EMPTY);
        mockRequest.setParameter(OAuth20Constants.REFRESH_TOKEN, refreshToken.getId());
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_OK, mockResponse.getStatus());
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
    }

    @Test
    public void verifyRefreshTokenMissingToken() throws Exception {
        addRegisteredService(CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.REFRESH_TOKEN.name().toLowerCase());
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_BAD_REQUEST, mockResponse.getStatus());
        assertEquals(OAuth20Constants.INVALID_REQUEST, mv.getModel().get(OAuth20Constants.ERROR));
    }

    @Test
    public void verifyRefreshTokenOKWithExpiredTicketGrantingTicket() throws Exception {
        val principal = createPrincipal();
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));
        val refreshToken = addRefreshToken(principal, service);

        refreshToken.getTicketGrantingTicket().markTicketExpired();

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        mockRequest.setParameter(OAuth20Constants.GRANT_TYPE, OAuth20GrantTypes.REFRESH_TOKEN.name().toLowerCase());
        mockRequest.setParameter(OAuth20Constants.CLIENT_ID, CLIENT_ID);
        mockRequest.setParameter(OAuth20Constants.CLIENT_SECRET, CLIENT_SECRET);
        mockRequest.setParameter(OAuth20Constants.REFRESH_TOKEN, refreshToken.getId());
        val mockResponse = new MockHttpServletResponse();
        requiresAuthenticationInterceptor.preHandle(mockRequest, mockResponse, null);
        val mv = controller.handleRequest(mockRequest, mockResponse);
        assertEquals(HttpStatus.SC_OK, mockResponse.getStatus());

        val accessTokenId = mv.getModel().get(OAuth20Constants.ACCESS_TOKEN).toString();

        val accessToken = this.ticketRegistry.getTicket(accessTokenId, AccessToken.class);
        assertEquals(principal, accessToken.getAuthentication().getPrincipal());

        val timeLeft = Integer.parseInt(mv.getModel().get(OAuth20Constants.EXPIRES_IN).toString());
        assertTrue(timeLeft >= TIMEOUT - 10 - DELTA);
    }

    @Test
    public void verifyRefreshTokenOK() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));
        assertRefreshTokenOk(service);
    }

    @Test
    public void verifyRefreshTokenOKWithRefreshToken() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));
        service.setGenerateRefreshToken(true);
        assertRefreshTokenOk(service);
    }

    @Test
    public void verifyJsonRefreshTokenOK() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));

        assertRefreshTokenOk(service);
    }

    @Test
    public void verifyJsonRefreshTokenOKWithRefreshToken() {
        val service = addRegisteredService(
                CollectionUtils.wrapSet(OAuth20GrantTypes.REFRESH_TOKEN));
        service.setGenerateRefreshToken(true);
        assertRefreshTokenOk(service);
    }

}
