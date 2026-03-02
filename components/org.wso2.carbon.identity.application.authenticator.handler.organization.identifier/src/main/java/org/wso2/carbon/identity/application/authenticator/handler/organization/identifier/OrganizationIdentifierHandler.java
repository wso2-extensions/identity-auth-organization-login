/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.handler.organization.identifier;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationData;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryInput;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryResult;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationLoginData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.OrgDiscoveryInputParameters;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants;
import org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.internal.OrganizationIdentifierHandlerDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.organization.config.service.exception.OrganizationConfigException;
import org.wso2.carbon.identity.organization.config.service.model.ConfigProperty;
import org.wso2.carbon.identity.organization.config.service.model.DiscoveryConfig;
import org.wso2.carbon.identity.organization.config.service.util.OrganizationConfigManagerUtil;
import org.wso2.carbon.identity.organization.discovery.service.AttributeBasedOrganizationDiscoveryHandler;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SESSION_DATA_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AMPERSAND_SIGN;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AUTHENTICATOR_ORGANIZATION_IDENTIFIER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AUTHENTICATOR_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.DISPLAY_LOGIN_HINT;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.DISPLAY_ORG_DISCOVERY_TYPE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.DISPLAY_ORG_HANDLE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.DISPLAY_ORG_ID;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.DISPLAY_ORG_NAME;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.EQUAL_SIGN;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ERROR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.I18N_LOGIN_HINT;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.I18N_ORG_DISCOVERY_TYPE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.I18N_ORG_HANDLE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.I18N_ORG_ID;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.I18N_ORG_NAME;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.INVALID_ORGANIZATION_DISCOVERY_TYPE_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.INVALID_ORGANIZATION_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.INVALID_ORGANIZATION_HANDLE_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.INVALID_ORGANIZATION_NAME_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.LogConstants.ActionIDs.INITIATE_ORG_DISCOVERY_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.LogConstants.ActionIDs.PROCESS_ORG_DISCOVERY_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.LogConstants.ORG_IDENTIFIER_HANDLER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ORGANIZATION_DISCOVERY_FAILURE_GENERIC_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ORGANIZATION_LOGIN_FAILURE;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ORGANIZATION_NOT_ASSOCIATED_WITH_APPLICATION_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ORG_DISCOVERY_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ORG_HANDLE_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.ORG_NAME_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.PROMPT_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.REQUEST_ORG_DISCOVERY_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.REQUEST_ORG_HANDLE_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.REQUEST_ORG_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.REQUEST_ORG_PAGE_URL_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.SP_ID_PARAMETER;
import static org.wso2.carbon.identity.organization.config.service.constant.OrganizationConfigConstants.DEFAULT_PARAM;
import static org.wso2.carbon.identity.organization.config.service.constant.OrganizationConfigConstants.ErrorMessages.ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST;
import static org.wso2.carbon.identity.organization.discovery.service.constant.DiscoveryConstants.ENABLE_CONFIG;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ORGANIZATION_DISCOVERY_CONFIG;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_THE_DEFAULT_DISCOVERY_PARAM;

/**
 * This class acts as Organization Identifier Handler.
 */
public class OrganizationIdentifierHandler extends AbstractApplicationAuthenticator implements
        AuthenticationFlowHandler {

    private static final Log LOG = LogFactory.getLog(OrganizationIdentifierHandler.class);

    @Override
    public String getName() {

        return OrganizationIdentifierHandlerConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return OrganizationIdentifierHandlerConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(OrganizationIdentifierHandlerConstants.CONTEXT_IDENTIFIER);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String orgId = request.getParameter(OrgDiscoveryInputParameters.ORG_ID);
        String orgHandle = request.getParameter(OrgDiscoveryInputParameters.ORG_HANDLE);
        String orgName = request.getParameter(OrgDiscoveryInputParameters.ORG_NAME);
        String loginHint = request.getParameter(OrgDiscoveryInputParameters.LOGIN_HINT);
        return StringUtils.isNotEmpty(orgId) || StringUtils.isNotEmpty(orgHandle)
                || StringUtils.isNotEmpty(orgName) || StringUtils.isNotEmpty(loginHint);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return super.process(request, response, context);
        }

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    ORG_IDENTIFIER_HANDLER, INITIATE_ORG_DISCOVERY_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating organization discovery request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        // Handling the organization discovery if any of the org identifier parameters are present.
        if (getParameter(request, context, OrgDiscoveryInputParameters.ORG_ID, true).isPresent()
                || getParameter(request, context, OrgDiscoveryInputParameters.ORG_HANDLE, true).isPresent()
                || getParameter(request, context, OrgDiscoveryInputParameters.ORG_NAME, true).isPresent()
                || getParameter(request, context, OrgDiscoveryInputParameters.LOGIN_HINT, true).isPresent()
        ) {
            boolean orgDiscoverySuccessful = handleOrganizationDiscovery(request, response, context, true);
            if (orgDiscoverySuccessful) {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        redirectToOrgDiscoveryInputCapture(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        // At this point, we only need to consider the request parameters for organization discovery.
        boolean orgDiscoverySuccessful = handleOrganizationDiscovery(request, response, context, false);
        if (!orgDiscoverySuccessful) {
            redirectToOrgDiscoveryInputCapture(request, response, context);
        }
    }

    private boolean handleOrganizationDiscovery(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationContext context, boolean considerRuntimeParams)
            throws AuthenticationFailedException {

        try {
            String orgId = getParameter(request, context, OrgDiscoveryInputParameters.ORG_ID,
                    considerRuntimeParams).orElse(null);
            String orgHandle = getParameter(request, context, OrgDiscoveryInputParameters.ORG_HANDLE,
                    considerRuntimeParams).orElse(null);
            String orgName = getParameter(request, context, OrgDiscoveryInputParameters.ORG_NAME,
                    considerRuntimeParams).orElse(null);
            String loginHint = getParameter(request, context, OrgDiscoveryInputParameters.LOGIN_HINT,
                    considerRuntimeParams).orElse(null);
            String orgDiscoveryType = getParameter(request, context, OrgDiscoveryInputParameters.ORG_DISCOVERY_TYPE,
                    considerRuntimeParams).orElse(null);
            OrganizationDiscoveryInput orgDiscoveryInput = new OrganizationDiscoveryInput.Builder()
                    .orgId(orgId)
                    .orgHandle(orgHandle)
                    .orgName(orgName)
                    .loginHint(loginHint)
                    .orgDiscoveryType(orgDiscoveryType)
                    .build();

            OrganizationDiscoveryResult orgDiscoveryResult = OrganizationIdentifierHandlerDataHolder.getInstance()
                    .getOrganizationDiscoveryHandler().discoverOrganization(orgDiscoveryInput, context);

            if (orgDiscoveryResult.isSuccessful()) {
                OrganizationLoginData organizationLoginData = getOrganizationLoginData(orgDiscoveryResult);
                context.setOrganizationLoginData(organizationLoginData);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            ORG_IDENTIFIER_HANDLER, PROCESS_ORG_DISCOVERY_RESPONSE);
                    diagnosticLogBuilder.resultMessage("Organization discovery completed successfully.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                            .inputParams(getApplicationDetails(context));
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return true;
            }

            // Handle the failure scenario and set the relevant error messages.
            OrganizationDiscoveryResult.FailureDetails failureDetails = orgDiscoveryResult.getFailureDetails();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Organization discovery failed." + (failureDetails != null ?
                        " Code: " + failureDetails.getCode() + ", Message: " + failureDetails.getMessage() : ""));
            }
            String failureErrorKey = resolveDiscoveryFailureErrorKey(orgDiscoveryInput, failureDetails);
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, failureErrorKey);
            context.setProperty(AUTHENTICATOR_MESSAGE, new AuthenticatorMessage(
                    FrameworkConstants.AuthenticatorMessageType.ERROR, failureErrorKey, null));
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        ORG_IDENTIFIER_HANDLER, PROCESS_ORG_DISCOVERY_RESPONSE);
                diagnosticLogBuilder.resultMessage("Organization discovery failed.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParams(getApplicationDetails(context));
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (FrameworkException e) {
            throw handleAuthFailures(e.getMessage(), e);
        }
        return false;
    }

    private OrganizationLoginData getOrganizationLoginData(OrganizationDiscoveryResult orgDiscoveryResult) {

        OrganizationLoginData organizationLoginData = new OrganizationLoginData();
        OrganizationData discoveredOrganization = new OrganizationData();
        discoveredOrganization.setId(orgDiscoveryResult.getDiscoveredOrganization().getId());
        discoveredOrganization.setName(orgDiscoveryResult.getDiscoveredOrganization().getName());
        discoveredOrganization.setHandle(
                orgDiscoveryResult.getDiscoveredOrganization().getOrganizationHandle());
        organizationLoginData.setAccessingOrganization(discoveredOrganization);
        organizationLoginData.setSharedApplicationId(orgDiscoveryResult.getSharedApplicationId());
        return organizationLoginData;
    }

    @SuppressFBWarnings(value = "UNVALIDATED_REDIRECT", justification = "Redirect params are not based on user inputs.")
    private void redirectToOrgDiscoveryInputCapture(HttpServletRequest request, HttpServletResponse response,
                                                    AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String discoveryDefaultParam = OrganizationConfigManagerUtil.resolveDefaultDiscoveryParam();

            StringBuilder queryStringBuilder = new StringBuilder();
            queryStringBuilder.append(SESSION_DATA_KEY).append(EQUAL_SIGN)
                    .append(urlEncode(context.getContextIdentifier()));
            addQueryParam(queryStringBuilder, AUTHENTICATOR_PARAMETER, getName());
            addQueryParam(queryStringBuilder, SP_ID_PARAMETER, context.getServiceProviderResourceId());
            addQueryParam(queryStringBuilder, DEFAULT_PARAM, discoveryDefaultParam);
            if (context.getProperty(ORGANIZATION_LOGIN_FAILURE) != null) {
                queryStringBuilder.append(ERROR_MESSAGE)
                        .append(urlEncode((String) context.getProperty(ORGANIZATION_LOGIN_FAILURE)));
            }

            String baseUrl = resolveBaseRedirectUrl(request, context, discoveryDefaultParam);
            String redirectUrl = FrameworkUtils.appendQueryParamsStringToUrl(baseUrl, queryStringBuilder.toString());
            response.sendRedirect(redirectUrl);
        } catch (IOException | URLBuilderException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT, e);
        } catch (OrganizationConfigException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RESOLVING_THE_DEFAULT_DISCOVERY_PARAM, e);
        }
    }

    private String resolveBaseRedirectUrl(HttpServletRequest request, AuthenticationContext context,
                                          String discoveryDefaultParam)
            throws URLBuilderException, AuthenticationFailedException {

        String promptParameter = request.getParameter(PROMPT_PARAMETER);
        boolean discoveryEnabled = isOrganizationDiscoveryEnabled(context);

        // Handling the discovery mode switching based on the prompt parameter.
        if (StringUtils.isNotEmpty(promptParameter)) {
            switch (promptParameter) {
                case OrganizationIdentifierHandlerConstants.ORGANIZATION_NAME_PROMPT_PARAMETER:
                    return getOrganizationRequestPageUrl(context);
                case OrganizationIdentifierHandlerConstants.ORG_HANDLE_PARAMETER:
                    return getOrganizationHandleRequestPageUrl();
                case OrganizationIdentifierHandlerConstants.ORG_DISCOVERY_PARAMETER:
                    if (discoveryEnabled) {
                        return getOrganizationDomainPageUrl();
                    }
                    break;
                default:
                    break;
            }
        }

        // Handling the retry scenarios based on the request parameters.
        if (request.getParameter(ORG_NAME_PARAMETER) != null) {
            return getOrganizationRequestPageUrl(context);
        }
        if (request.getParameter(ORG_HANDLE_PARAMETER) != null) {
            return getOrganizationHandleRequestPageUrl();
        }
        if (request.getParameter(ORG_DISCOVERY_PARAMETER) != null && discoveryEnabled) {
            return getOrganizationDomainPageUrl();
        }

        // Handling the initial redirection to organization discovery input capture page.
        if (discoveryEnabled) {
            return getOrganizationDomainPageUrl();
        }
        if (ORG_HANDLE_PARAMETER.equals(discoveryDefaultParam)) {
            return getOrganizationHandleRequestPageUrl();
        }
        return getOrganizationRequestPageUrl(context);
    }

    private boolean isOrganizationDiscoveryEnabled(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            DiscoveryConfig discoveryConfig = OrganizationIdentifierHandlerDataHolder.getInstance()
                    .getOrganizationConfigManager().getDiscoveryConfiguration();
            List<ConfigProperty> configProperties = discoveryConfig.getConfigProperties();
            Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers =
                    OrganizationIdentifierHandlerDataHolder.getInstance().getOrganizationDiscoveryManager()
                            .getAttributeBasedOrganizationDiscoveryHandlers();
            for (ConfigProperty configProperty : configProperties) {
                String type = configProperty.getKey().split(ENABLE_CONFIG)[0];
                if (discoveryHandlers.get(type) != null && Boolean.parseBoolean(configProperty.getValue())) {
                    return true;
                }
            }
        } catch (OrganizationConfigException e) {
            if (ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                return false;
            }
            throw handleAuthFailures(ERROR_CODE_ERROR_GETTING_ORGANIZATION_DISCOVERY_CONFIG, e);
        }
        return false;
    }

    private String getOrganizationRequestPageUrl(AuthenticationContext context) throws URLBuilderException {

        String requestOrgPageUrl = getConfiguration(context, REQUEST_ORG_PAGE_URL_CONFIG);
        if (StringUtils.isBlank(requestOrgPageUrl)) {
            requestOrgPageUrl = REQUEST_ORG_PAGE_URL;
        }
        return ServiceURLBuilder.create().addPath(requestOrgPageUrl).build().getAbsolutePublicURL();
    }

    private String getOrganizationHandleRequestPageUrl() throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(REQUEST_ORG_HANDLE_PAGE_URL).build().getAbsolutePublicURL();
    }

    private String getOrganizationDomainPageUrl() throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(REQUEST_ORG_DISCOVERY_PAGE_URL).build().getAbsolutePublicURL();
    }

    private String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        String tenantDomain = context.getTenantDomain();
        if ((propertiesFromLocal != null || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) &&
                super.getAuthenticatorConfig().getParameterMap().containsKey(configName)) {
            configValue = super.getAuthenticatorConfig().getParameterMap().get(configName);
        } else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        return configValue;
    }

    /**
     * Returns parameter value from the request or runtime parameters.
     *
     * @param request              HTTP servlet request.
     * @param context              Authentication context.
     * @param parameterKey         Key of the parameter to retrieve.
     * @param includeRuntimeParams Whether to include runtime parameters in adaptive script.
     * @return Optional containing the parameter value if present, otherwise empty.
     */
    private Optional<String> getParameter(HttpServletRequest request, AuthenticationContext context,
                                          String parameterKey, boolean includeRuntimeParams) {

        if (request.getParameterMap().containsKey(parameterKey)) {
            return Optional.of(request.getParameter(parameterKey));
        }
        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (includeRuntimeParams && runtimeParams.containsKey(parameterKey)) {
            return Optional.of(runtimeParams.get(parameterKey));
        }
        return Optional.empty();
    }

    private void addQueryParam(StringBuilder builder, String query, String param) throws
            UnsupportedEncodingException {

        builder.append(AMPERSAND_SIGN).append(query).append(EQUAL_SIGN).append(urlEncode(param));
    }

    private String urlEncode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, FrameworkUtils.UTF_8);
    }

    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_ORGANIZATION_IDENTIFIER;
    }

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        String idpName = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        AuthenticatorData authenticatorData = new AuthenticatorData();
        if (context != null && context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            AuthenticatorMessage authenticatorMessage = (AuthenticatorMessage) context.getProperty
                    (AUTHENTICATOR_MESSAGE);
            authenticatorData.setMessage(authenticatorMessage);
        }

        authenticatorData.setName(getName());
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setIdp(idpName);
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        setAuthParams(authenticatorData);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(OrgDiscoveryInputParameters.ORG_ID);
        requiredParams.add(OrgDiscoveryInputParameters.ORG_NAME);
        requiredParams.add(OrgDiscoveryInputParameters.ORG_HANDLE);
        requiredParams.add(OrgDiscoveryInputParameters.LOGIN_HINT);
        requiredParams.add(OrgDiscoveryInputParameters.ORG_DISCOVERY_TYPE);
        authenticatorData.setRequiredParams(requiredParams);

        return Optional.of(authenticatorData);
    }

    private static void setAuthParams(AuthenticatorData authenticatorData) {

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata orgIdMetadata = new AuthenticatorParamMetadata(
                OrgDiscoveryInputParameters.ORG_ID, DISPLAY_ORG_ID, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, I18N_ORG_ID);
        AuthenticatorParamMetadata orgNameMetadata = new AuthenticatorParamMetadata(
                OrgDiscoveryInputParameters.ORG_NAME, DISPLAY_ORG_NAME,
                FrameworkConstants.AuthenticatorParamType.STRING, 1, Boolean.FALSE, I18N_ORG_NAME);
        AuthenticatorParamMetadata orgHandleMetadata = new AuthenticatorParamMetadata(
                OrgDiscoveryInputParameters.ORG_HANDLE, DISPLAY_ORG_HANDLE,
                FrameworkConstants.AuthenticatorParamType.STRING, 2, Boolean.FALSE, I18N_ORG_HANDLE);
        AuthenticatorParamMetadata loginHintMetadata = new AuthenticatorParamMetadata(
                OrgDiscoveryInputParameters.LOGIN_HINT, DISPLAY_LOGIN_HINT,
                FrameworkConstants.AuthenticatorParamType.STRING, 3, Boolean.FALSE, I18N_LOGIN_HINT);
        AuthenticatorParamMetadata orgDiscoveryTypeMetadata = new AuthenticatorParamMetadata(
                OrgDiscoveryInputParameters.ORG_DISCOVERY_TYPE, DISPLAY_ORG_DISCOVERY_TYPE,
                FrameworkConstants.AuthenticatorParamType.STRING, 4, Boolean.FALSE, I18N_ORG_DISCOVERY_TYPE);
        authenticatorParamMetadataList.add(orgIdMetadata);
        authenticatorParamMetadataList.add(orgNameMetadata);
        authenticatorParamMetadataList.add(orgHandleMetadata);
        authenticatorParamMetadataList.add(loginHintMetadata);
        authenticatorParamMetadataList.add(orgDiscoveryTypeMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    private String resolveDiscoveryFailureErrorKey(OrganizationDiscoveryInput orgDiscoveryInput,
                                                   OrganizationDiscoveryResult.FailureDetails failureDetails) {

        if (failureDetails == null) {
            return ORGANIZATION_DISCOVERY_FAILURE_GENERIC_ERROR_KEY;
        }
        String code = failureDetails.getCode();
        if (FrameworkConstants.OrgDiscoveryFailureDetails.APPLICATION_NOT_SHARED.getCode().equals(code)) {
            return ORGANIZATION_NOT_ASSOCIATED_WITH_APPLICATION_ERROR_KEY;
        }
        if (FrameworkConstants.OrgDiscoveryFailureDetails.ORGANIZATION_DISCOVERY_TYPE_NOT_ENABLED_OR_SUPPORTED
                .getCode().equals(code)) {
            return INVALID_ORGANIZATION_DISCOVERY_TYPE_ERROR_KEY;
        }
        if (FrameworkConstants.OrgDiscoveryFailureDetails.ORGANIZATION_NOT_FOUND.getCode().equals(code)) {
            if (StringUtils.isNotBlank(orgDiscoveryInput.getOrgHandle())) {
                return INVALID_ORGANIZATION_HANDLE_ERROR_KEY;
            }
            if (StringUtils.isNotBlank(orgDiscoveryInput.getOrgName())) {
                return INVALID_ORGANIZATION_NAME_ERROR_KEY;
            }
            return INVALID_ORGANIZATION_ERROR_KEY;
        }
        return ORGANIZATION_DISCOVERY_FAILURE_GENERIC_ERROR_KEY;
    }

    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME, applicationName));
        return applicationDetailsMap;
    }

    private AuthenticationFailedException handleAuthFailures(OrganizationManagementConstants.ErrorMessages error,
                                                             Throwable e) {

        if (LOG.isDebugEnabled()) {
            LOG.debug(error.getMessage());
        }
        return new AuthenticationFailedException(error.getCode(), error.getMessage(), e);
    }

    private AuthenticationFailedException handleAuthFailures(String errorMessage, Throwable e) {

        if (LOG.isDebugEnabled()) {
            LOG.debug(errorMessage);
        }
        return new AuthenticationFailedException(errorMessage, e);
    }
}
