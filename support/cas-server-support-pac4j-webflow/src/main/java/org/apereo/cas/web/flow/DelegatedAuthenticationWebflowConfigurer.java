package org.apereo.cas.web.flow;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.configurer.AbstractCasWebflowConfigurer;
import org.apereo.cas.web.support.WebUtils;

import lombok.val;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.DecisionState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * The {@link DelegatedAuthenticationWebflowConfigurer} is responsible for
 * adjusting the CAS webflow context for pac4j integration.
 *
 * @author Misagh Moayyed
 * @since 4.2
 */
public class DelegatedAuthenticationWebflowConfigurer extends AbstractCasWebflowConfigurer {
    private static final String DECISION_STATE_CHECK_DELEGATED_AUTHN_FAILURE = "checkDelegatedAuthnFailureDecision";

    private final Action saml2ClientLogoutAction;

    public DelegatedAuthenticationWebflowConfigurer(final FlowBuilderServices flowBuilderServices,
                                                    final FlowDefinitionRegistry loginFlowDefinitionRegistry,
                                                    final FlowDefinitionRegistry logoutFlowDefinitionRegistry,
                                                    final Action saml2ClientLogoutAction,
                                                    final ApplicationContext applicationContext,
                                                    final CasConfigurationProperties casProperties) {
        super(flowBuilderServices, loginFlowDefinitionRegistry, applicationContext, casProperties);
        setLogoutFlowDefinitionRegistry(logoutFlowDefinitionRegistry);
        this.saml2ClientLogoutAction = saml2ClientLogoutAction;
    }

    @Override
    protected void doInitialize() {
        val flow = getLoginFlow();
        if (flow != null) {
            createClientActionActionState(flow);
            createStopWebflowViewState(flow);
            createSaml2ClientLogoutAction();
        }
    }

    private void createSaml2ClientLogoutAction() {
        val logoutFlow = getLogoutFlow();
        val state = getState(logoutFlow, CasWebflowConstants.STATE_ID_FINISH_LOGOUT, DecisionState.class);
        state.getEntryActionList().add(saml2ClientLogoutAction);
    }

    private void createClientActionActionState(final Flow flow) {
        val actionState = createActionState(flow, CasWebflowConstants.STATE_ID_DELEGATED_AUTHENTICATION,
            createEvaluateAction(CasWebflowConstants.ACTION_ID_DELEGATED_AUTHENTICATION));
        val transitionSet = actionState.getTransitionSet();
        transitionSet.add(createTransition(CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CREATE_TICKET_GRANTING_TICKET));

        val currentStartState = getStartState(flow).getId();
        transitionSet.add(createTransition(CasWebflowConstants.TRANSITION_ID_ERROR, currentStartState));
        transitionSet.add(createTransition(CasWebflowConstants.TRANSITION_ID_RESUME, currentStartState));
        transitionSet.add(createTransition(CasWebflowConstants.TRANSITION_ID_AUTHENTICATION_FAILURE, DECISION_STATE_CHECK_DELEGATED_AUTHN_FAILURE));
        transitionSet.add(createTransition(CasWebflowConstants.TRANSITION_ID_STOP, CasWebflowConstants.STATE_ID_STOP_WEBFLOW));
        transitionSet.add(createTransition(CasWebflowConstants.TRANSITION_ID_WARN, CasWebflowConstants.STATE_ID_WARN));
        setStartState(flow, actionState);
    }

    private void createStopWebflowViewState(final Flow flow) {
        createDecisionState(flow, DECISION_STATE_CHECK_DELEGATED_AUTHN_FAILURE, "flowScope.unauthorizedRedirectUrl != null",
            CasWebflowConstants.STATE_ID_SERVICE_UNAUTHZ_CHECK, CasWebflowConstants.STATE_ID_STOP_WEBFLOW);

        val state = createViewState(flow, CasWebflowConstants.STATE_ID_STOP_WEBFLOW, CasWebflowConstants.VIEW_ID_PAC4J_STOP_WEBFLOW);
        state.getEntryActionList().add(new AbstractAction() {
            @Override
            protected Event doExecute(final RequestContext requestContext) {
                val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(requestContext);
                val response = WebUtils.getHttpServletResponseFromExternalWebflowContext(requestContext);
                val mv = DelegatedClientAuthenticationAction.hasDelegationRequestFailed(request, response.getStatus());
                mv.ifPresent(modelAndView -> modelAndView.getModel().forEach((k, v) -> requestContext.getFlowScope().put(k, v)));
                return null;
            }
        });
    }
}
