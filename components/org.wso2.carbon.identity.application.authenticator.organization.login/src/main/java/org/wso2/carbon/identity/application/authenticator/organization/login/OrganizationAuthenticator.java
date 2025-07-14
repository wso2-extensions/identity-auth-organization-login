/*
 * Copyright (c) 2022-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.organization.login;

import com.nimbusds.jose.util.JSONObjectUtils;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.organization.login.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.Claim;
import org.wso2.carbon.identity.client.attestation.mgt.utils.Constants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.config.service.exception.OrganizationConfigException;
import org.wso2.carbon.identity.organization.config.service.model.ConfigProperty;
import org.wso2.carbon.identity.organization.config.service.model.DiscoveryConfig;
import org.wso2.carbon.identity.organization.config.service.util.OrganizationConfigManagerUtil;
import org.wso2.carbon.identity.organization.discovery.service.AttributeBasedOrganizationDiscoveryHandler;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementClientException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.BasicOrganization;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.Application.CONSOLE_APP;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.Application.MY_ACCOUNT_APP;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SESSION_DATA_KEY;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.ActionIDs.INITIATE_OUTBOUND_AUTH_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AMPERSAND_SIGN;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.APP_ROLES_SCOPE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHORIZATION_ENDPOINT_ORGANIZATION_PATH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.DEFAULT_PARAM;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ENABLE_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.EQUAL_SIGN;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ERROR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.IDP_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ID_TOKEN_ORG_ID_PARAM;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.INBOUND_AUTH_TYPE_OAUTH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.INVALID_ORGANIZATION_HANDLE_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.INVALID_ORGANIZATION_NAME_ERROR_KEY;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.LOGIN_HINT_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.OIDC_CLAIM_DIALECT_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_ATTRIBUTE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_DISCOVERY_TYPE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_LOGIN_FAILURE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_COUNT_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DESCRIPTION_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DISCOVERY_ENABLED_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DISCOVERY_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DISCOVERY_TYPE_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_HANDLE_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_ID_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.PROMPT_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_DISCOVERY_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_HANDLE_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_PAGE_URL_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_SELECT_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.SELF_REGISTRATION_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.SP_ID_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.TOKEN_ENDPOINT_ORGANIZATION_PATH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.USERINFO_ENDPOINT_ORGANIZATION_PATH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.USERINFO_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.USERNAME_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.USER_ORGANIZATION_CLAIM;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.CALLBACK_URL;
import static org.wso2.carbon.identity.organization.config.service.constant.OrganizationConfigConstants.ErrorMessages.ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ORGANIZATION_DISCOVERY_CONFIG;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_ORGANIZATION_DOMAIN_FROM_TENANT_DOMAIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_ORGANIZATION_LOGIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_THE_DEFAULT_DISCOVERY_PARAM;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_APPLICATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_ORGANIZATIONS_BY_NAME;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_ORGANIZATION_ID_BY_HANDLE;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_VALIDATING_ORGANIZATION_DISCOVERY_ATTRIBUTE;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_VALIDATING_ORGANIZATION_LOGIN_HINT_ATTRIBUTE;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_APPLICATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_NOT_FOUND_FOR_TENANT;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ORG_PARAMETERS_NOT_RESOLVED;

/**
 * Authenticator implementation to redirect the authentication request to the access delegated business application in
 * the requested organization.
 * <p/>
 * Class extends the {@link OpenIDConnectAuthenticator}.
 */
public class OrganizationAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(OrganizationAuthenticator.class);
    private static final String samlSSOResponseFormPostPageTemplate = "<html>\n" +
            "<body onload=\"javascript:document.getElementById('samlsso-response-form').submit()\">\n" +
            "<h2>Please wait while we take you back to $app</h2>\n" +
            "<p><a href=\"javascript:document.getElementById('samlsso-response-form').submit()\">Click here</a>" +
            " if you have been waiting for too long.</p>\n" +
            "<form id=\"samlsso-response-form\" method=\"post\" action=\"$acUrl\">\n" +
            "    <!--$params-->\n" +
            "    <!--$additionalParams-->\n" +
            "</form>\n" +
            "</body>\n" +
            "</html>";
    private static final String EMAIL_DOMAIN_DISCOVERY_TYPE = "emailDomain";
    private static final String SSO_ADDITIONAL_PARAMS = "ssoAdditionalParams";
    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static final String DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX = "\\$authparam\\{(\\w+)\\}";
    private String discoveryDefaultParam = "orgHandle";

    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return AUTHENTICATOR_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        // Removed the property when setting it in shared application client exception check
        context.removeProperty(ORGANIZATION_LOGIN_FAILURE);
        resolvePropertiesForAuthenticator(context, response);
        // Check if the "organizationLoginFailure" property in the context,
        // when added in shared application client exception check.
        if (!context.getProperties().containsKey(ORGANIZATION_LOGIN_FAILURE)) {
            if (request.getParameter(AuthenticatorConstants.SAML_RESP) == null) {
                super.initiateAuthenticationRequest(request, response, context);
            } else {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
                if (LoggerUtils.isDiagnosticLogsEnabled() && context.getAuthenticatorProperties() != null) {
                    diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            getComponentId(), INITIATE_OUTBOUND_AUTH_REQUEST);
                    diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                            .inputParam("authenticator properties", context.getAuthenticatorProperties().keySet())
                            .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                            .inputParams(getApplicationDetails(context));
                }
                String loginPage = prepareLoginPage(request, context);
                try {
                    generateSamlPostPage(response, loginPage,
                            request.getParameter(AuthenticatorConstants.SAML_RESP), context);
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        String scopes = extractScopesFromURL(loginPage);
                        if (StringUtils.isNotEmpty(scopes)) {
                            diagnosticLogBuilder.inputParam("scopes", scopes);
                        }
                        diagnosticLogBuilder.resultMessage("Redirecting to organization's authorize endpoint.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                } catch (IOException e) {
                    throw new AuthenticationFailedException(
                            OIDCErrorConstants.ErrorMessages.IO_ERROR.getCode(), e.getMessage(), e);
                }
            }
        }
    }

    @SuppressFBWarnings(
            value = "XSS_SERVLET",
            justification = "Passed HTML content is provided from the server side. " +
                    "The only request passed param ('samlMessage') is sanitized with encoding."
    )
    private void generateSamlPostPage(HttpServletResponse resp, String loginPage, String samlMessage,
                                      AuthenticationContext context) throws IOException {

        String samlSSORedirectPage;
        if (AuthenticatorDataHolder.getInstance().isSamlSsoResponseHtmlPageAvailable()) {
            samlSSORedirectPage = AuthenticatorDataHolder.getInstance().getSamlSsoResponseHtmlPage();
        } else {
            samlSSORedirectPage = samlSSOResponseFormPostPageTemplate;
        }

        String pageWithLoginPage = samlSSORedirectPage.replace("$acUrl", loginPage);
        String pageWithApp = pageWithLoginPage.replace("$app", loginPage);

        String spName = getApplicationDetails(context).get("application name");
        if (StringUtils.isNotBlank(spName)) {
            pageWithApp = pageWithLoginPage.replace("$app", spName);
        }

        StringBuilder hiddenInputBuilder = new StringBuilder();
        hiddenInputBuilder.append("<!--$params-->\n").append("<input type='hidden' name='")
                .append(AuthenticatorConstants.SAML_RESP)
                .append("' value='").append(Encode.forHtmlAttribute(samlMessage)).append("'/>");
        String finalPage = pageWithApp.replace("<!--$params-->",
                hiddenInputBuilder.toString());

        PrintWriter out = resp.getWriter();
        out.print(finalPage);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        // Removed the property when setting it in shared application client exception check
        context.removeProperty(ORGANIZATION_LOGIN_FAILURE);
        resolvePropertiesForAuthenticator(context, response);
        // Check if the "organizationLoginFailure" property in the context,
        // when added in shared application client exception check.
        if (!context.getProperties().containsKey(ORGANIZATION_LOGIN_FAILURE)) {
            super.processAuthenticationResponse(request, response, context);

            // Add organization name to the user attributes.
            context.getSubject().getUserAttributes()
                    .put(ClaimMapping.build(USER_ORGANIZATION_CLAIM, USER_ORGANIZATION_CLAIM, null, false),
                            context.getAuthenticatorProperties().get(ORGANIZATION_ATTRIBUTE));
        }
    }

    @Override
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(scope)) {
            scope = "openid email profile phone address";
        }
        scope = addAppRolesScope(scope);
        return scope;
    }

    /**
     * Process the authenticator properties based on the user information.
     *
     * @param context  The authentication context.
     * @param response servlet response.
     * @throws AuthenticationFailedException thrown when resolving organization login authenticator properties.
     */
    private void resolvePropertiesForAuthenticator(AuthenticationContext context, HttpServletResponse response)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String application = context.getServiceProviderName();
        String appResideTenantDomain = context.getTenantDomain();

        if ((!context.getProperties().containsKey(ORG_PARAMETER)
                && !context.getProperties().containsKey(ORG_DISCOVERY_PARAMETER)
                && !context.getProperties().containsKey(ORG_HANDLE_PARAMETER))
                || !context.getProperties().containsKey(ORG_ID_PARAMETER)) {
            throw handleAuthFailures(ERROR_CODE_ORG_PARAMETERS_NOT_RESOLVED);
        }

        // Get the shared service provider based on the requested organization.
        String appResideOrgId = getOrgIdByTenantDomain(appResideTenantDomain);
        String sharedOrgId = context.getProperty(ORG_ID_PARAMETER).toString();
        String sharedOrgTenantDomain = getTenantDomainByOrgId(sharedOrgId);
        ServiceProvider sharedApplication;
        // If the shared application cannot be found for the particular organization,
        // will set a "organizationLoginFailure" property in the context and will check this in Authentication Process.
        try {
            sharedApplication = getOrgApplicationManager()
                    .resolveSharedApplication(application, appResideOrgId, sharedOrgId);
        } catch (OrganizationManagementClientException e) {
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, "Organization is not associated with this application.");
            redirectToOrgDiscoveryInputCapture(response, context);
            return;
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RETRIEVING_APPLICATION, e);
        }
        try {
            InboundAuthenticationRequestConfig oidcConfigurations =
                    getAuthenticationConfig(sharedApplication).orElseThrow(
                            () -> handleAuthFailures(ERROR_CODE_INVALID_APPLICATION));

            // Update the authenticator configurations based on the user's organization.
            String clientId = oidcConfigurations.getInboundAuthKey();
            OAuthConsumerAppDTO oauthApp = getOAuthAdminService()
                    .getOAuthApplicationData(clientId, sharedOrgTenantDomain);

            // Enable BasicAuth flow if shared app is a public client.
            if (oauthApp.isBypassClientCredentials()) {
                authenticatorProperties.put(IS_BASIC_AUTH_ENABLED, "true");
            }
            authenticatorProperties.put(CLIENT_ID, clientId);
            authenticatorProperties.put(CLIENT_SECRET, oauthApp.getOauthConsumerSecret());
            authenticatorProperties.put(ORGANIZATION_ATTRIBUTE, sharedOrgId);
            authenticatorProperties.put(OAUTH2_AUTHZ_URL, getAuthorizationEndpoint(sharedOrgId,
                    sharedOrgTenantDomain, oauthApp.getApplicationName()));
            authenticatorProperties.put(USERINFO_URL, getUserInfoEndpoint(sharedOrgId, sharedOrgTenantDomain));
            authenticatorProperties.put(OAUTH2_TOKEN_URL, getTokenEndpoint(sharedOrgId, sharedOrgTenantDomain));
            authenticatorProperties.put(CALLBACK_URL, oauthApp.getCallbackUrl());
            authenticatorProperties.put(FrameworkConstants.QUERY_PARAMS, getQueryParams(context,
                    sharedApplication.getClaimConfig().getClaimMappings(), appResideTenantDomain));
        } catch (IdentityOAuthAdminException | ClaimMetadataException | URLBuilderException |
                 UnsupportedEncodingException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RESOLVING_ORGANIZATION_LOGIN, e);
        }
    }

    private String getOrgIdByTenantDomain(String tenantDomain) throws AuthenticationFailedException {

        try {
            return getOrganizationManager().resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementClientException e) {
            throw handleAuthFailures(ERROR_CODE_ORGANIZATION_NOT_FOUND_FOR_TENANT, e);
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RESOLVING_ORGANIZATION_DOMAIN_FROM_TENANT_DOMAIN, e);
        }
    }

    private String getTenantDomainByOrgId(String orgId) throws AuthenticationFailedException {

        try {
            return getOrganizationManager().resolveTenantDomain(orgId);
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN, e);
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {

        if (context.isLogoutRequest()) {
            String idTokenHint = getIdTokenHint(context);
            String orgId;
            if (StringUtils.isNotBlank(idTokenHint)) {
                orgId = getIdTokenClaim(idTokenHint, ID_TOKEN_ORG_ID_PARAM);
            } else {
                orgId = getUserOrgIdFromContext(context);
            }
            if (StringUtils.isNotBlank(orgId)) {
                try {
                    setOIDCLogoutURL(context, orgId);
                    setCallbackURL(context);
                } catch (URLBuilderException e) {
                    throw new AuthenticationFailedException(e.getMessage());
                }
            }
            return super.process(request, response, context);
        }

        if (request.getParameter(SELF_REGISTRATION_PARAMETER) != null) {
            context.setProperty(SELF_REGISTRATION_PARAMETER, request.getParameter(SELF_REGISTRATION_PARAMETER));
        }

        Map<String, String> runtimeParams = getRuntimeParams(context);
        try {
            discoveryDefaultParam = OrganizationConfigManagerUtil.resolveDefaultDiscoveryParam();
        } catch (OrganizationConfigException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RESOLVING_THE_DEFAULT_DISCOVERY_PARAM, e);
        }

        /**
         * First priority for organization Id.
         * Check for the organization Id in the request attribute first since the organization Id is set in the
         * request attribute if a previous session exists.
         */
        if (StringUtils.isNotBlank((String) request.getAttribute(ORG_ID_PARAMETER))) {
            String organizationId = (String) request.getAttribute(ORG_ID_PARAMETER);
            context.setProperty(ORG_ID_PARAMETER, organizationId);
            String organizationName = getOrganizationNameById(organizationId);
            if (StringUtils.isNotBlank(organizationName)) {
                context.setProperty(ORG_PARAMETER, organizationName);
            }
        } else if (isParameterExists(request, runtimeParams, ORG_ID_PARAMETER)) {
            String organizationId = getParameter(request, runtimeParams, ORG_ID_PARAMETER);
            context.setProperty(ORG_ID_PARAMETER, organizationId);
            String organizationName = getOrganizationNameById(organizationId);
            if (StringUtils.isNotBlank(organizationName)) {
                context.setProperty(ORG_PARAMETER, organizationName);
            }
        } else if (isParameterExists(request, runtimeParams, LOGIN_HINT_PARAMETER)) {
            String loginHint = getParameter(request, runtimeParams, LOGIN_HINT_PARAMETER);
            context.setProperty(ORG_DISCOVERY_PARAMETER, loginHint);
            if (!validateLoginHintAttributeValue(loginHint, runtimeParams, context, request, response)) {
                context.removeProperty(ORG_DISCOVERY_PARAMETER);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        } else if (request.getParameterMap().containsKey(ORG_DISCOVERY_PARAMETER)) {
            // `orgDiscovery` request parameter is deprecated. `login_hint` should be used instead.
            String discoveryInput = request.getParameter(ORG_DISCOVERY_PARAMETER);
            context.setProperty(ORG_DISCOVERY_PARAMETER, discoveryInput);
            if (!validateDiscoveryAttributeValue(discoveryInput, context, response)) {
                context.removeProperty(ORG_DISCOVERY_PARAMETER);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        } else {
            if (ORG_HANDLE_PARAMETER.equals(discoveryDefaultParam)
                    && isParameterExists(request, runtimeParams, ORG_HANDLE_PARAMETER)) {
                String organizationHandle = getParameter(request, runtimeParams, ORG_HANDLE_PARAMETER);
                context.setProperty(ORG_HANDLE_PARAMETER, organizationHandle);
                if (!validateOrganizationHandle(organizationHandle, context, response)) {
                    context.removeProperty(ORG_HANDLE_PARAMETER);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
            } else if (ORG_PARAMETER.equals(discoveryDefaultParam)
                    && isParameterExists(request, runtimeParams, ORG_PARAMETER)) {
                String organizationName = getParameter(request, runtimeParams, ORG_PARAMETER);
                context.setProperty(ORG_PARAMETER, organizationName);
                if (!validateOrganizationName(organizationName, context, response)) {
                    context.removeProperty(ORG_PARAMETER);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }
            }
        }

        if (!context.getProperties().containsKey(ORG_PARAMETER) &&
                !context.getProperties().containsKey(ORG_HANDLE_PARAMETER) &&
                !context.getProperties().containsKey(ORG_DISCOVERY_PARAMETER)) {
            if (request.getParameterMap().containsKey(PROMPT_PARAMETER)) {
                String prompt = request.getParameter(PROMPT_PARAMETER);
                context.setProperty(PROMPT_PARAMETER, prompt);
            }
            redirectToOrgDiscoveryInputCapture(response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        return super.process(request, response, context);
    }

    private String getIdTokenHint(AuthenticationContext context) {

        if (context.getStateInfo() instanceof OIDCStateInfo) {
            return ((OIDCStateInfo) context.getStateInfo()).getIdTokenHint();
        }
        return null;
    }

    private String getIdTokenClaim(String idToken, String claimName) {

        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.getDecoder().decode(base64Body);
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parse(new String(decoded, StandardCharsets.UTF_8)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT : ", e);
        }
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            if (StringUtils.equals(claimName, entry.getKey())) {
                return String.valueOf(entry.getValue());
            }
        }
        return StringUtils.EMPTY;
    }

    private String getUserOrgIdFromContext(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = (AuthenticatedUser)
                context.getParameter(FrameworkConstants.AUTHENTICATED_USER);
        if (authenticatedUser != null) {
            Map<ClaimMapping, String> attributesMap = authenticatedUser.getUserAttributes();
            for (Map.Entry<ClaimMapping, String> entry : attributesMap.entrySet()) {
                ClaimMapping claimMapping = entry.getKey();
                if (FrameworkConstants.USER_ORGANIZATION_CLAIM.equals(claimMapping.getLocalClaim().getClaimUri())) {
                    return entry.getValue();
                }
            }
        }
        return StringUtils.EMPTY;
    }

    private String getOrganizationNameById(String organizationId) {

        try {
            return getOrganizationManager().getOrganizationNameById(organizationId);
        } catch (OrganizationManagementException e) {
            log.debug(e.getMessage());
            return null;
        }
    }

    private boolean validateOrganizationName(String organizationName, AuthenticationContext context,
                                             HttpServletResponse response) throws AuthenticationFailedException {

        try {
            List<Organization> organizations = getOrganizationManager().getOrganizationsByName(organizationName);
            List<String> mainAppSharedOrganizations =
                    getMainApplicationSharedOrganizationIds(context.getServiceProviderName(),
                            context.getTenantDomain());
            organizations = organizations.stream()
                    .filter(organization -> mainAppSharedOrganizations.contains(organization.getId()))
                    .collect(Collectors.toList());
            if (CollectionUtils.isNotEmpty(organizations)) {
                if (organizations.size() == 1) {
                    context.setProperty(ORG_ID_PARAMETER, organizations.get(0).getId());
                    return true;
                }
                redirectToSelectOrganization(response, context, organizations);
            } else {
                context.setProperty(ORGANIZATION_LOGIN_FAILURE,
                        "Organization is not associated with this application.");
                redirectToOrgDiscoveryInputCapture(response, context);
            }
        } catch (OrganizationManagementClientException e) {
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, INVALID_ORGANIZATION_NAME_ERROR_KEY);
            redirectToOrgDiscoveryInputCapture(response, context);
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RETRIEVING_ORGANIZATIONS_BY_NAME, e);
        }
        return false;
    }

    private boolean validateOrganizationHandle(String organizationHandle, AuthenticationContext context,
                                               HttpServletResponse response) throws AuthenticationFailedException {

        try {
            String organizationId = getOrganizationManager().resolveOrganizationId(organizationHandle);
            String organizationName = getOrganizationNameById(organizationId);
            if (StringUtils.isNotBlank(organizationName)) {
                return validateOrganizationName(organizationName, context, response);
            }
        } catch (OrganizationManagementClientException e) {
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, INVALID_ORGANIZATION_HANDLE_ERROR_KEY);
            redirectToOrgDiscoveryInputCapture(response, context);
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RETRIEVING_ORGANIZATION_ID_BY_HANDLE, e);
        }
        return false;
    }

    /**
     * Validates given login_hint parameter.
     *
     * @param loginHintInput Given login_hint parameter value.
     * @param context        Authentication context.
     * @param request        Servlet request.
     * @param response       Servlet response.
     * @return True if the login_hint parameter is valid.
     * @throws AuthenticationFailedException If an error occurs while validating login_hint parameter.
     */
    private boolean validateLoginHintAttributeValue(String loginHintInput, Map<String, String> runtimeParams,
                                                    AuthenticationContext context, HttpServletRequest request,
                                                    HttpServletResponse response)
            throws AuthenticationFailedException {

        // Default discovery type is set to `emailDomain`.
        String discoveryType = EMAIL_DOMAIN_DISCOVERY_TYPE;
        if (isParameterExists(request, runtimeParams, ORG_DISCOVERY_TYPE_PARAMETER)) {
            discoveryType = getParameter(request, runtimeParams, ORG_DISCOVERY_TYPE_PARAMETER);
        }

        if (!isOrganizationDiscoveryTypeEnabled(discoveryType)) {
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, "invalid.organization.discovery.type");
            redirectToOrgDiscoveryInputCapture(response, context);
            return false;
        }
        context.setProperty(ORGANIZATION_DISCOVERY_TYPE, discoveryType);

        try {
            String appResideOrgId = getOrgIdByTenantDomain(context.getLoginTenantDomain());
            String organizationId = getOrganizationDiscoveryManager().getOrganizationIdByDiscoveryAttribute
                    (discoveryType, loginHintInput, appResideOrgId, context);
            if (StringUtils.isNotBlank(organizationId)) {
                context.setProperty(ORG_ID_PARAMETER, organizationId);
                return true;
            }
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, "Can't identify organization");
            redirectToOrgDiscoveryInputCapture(response, context);
            return false;
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_VALIDATING_ORGANIZATION_LOGIN_HINT_ATTRIBUTE, e);
        }
    }

    private boolean validateDiscoveryAttributeValue(String discoveryInput, AuthenticationContext context,
                                                    HttpServletResponse response) throws AuthenticationFailedException {

        String appResideOrgId = getOrgIdByTenantDomain(context.getLoginTenantDomain());
        Object discoveryType = context.getProperty(ORGANIZATION_DISCOVERY_TYPE);
        try {
            if (discoveryType != null) {
                String organizationId = getOrganizationDiscoveryManager().getOrganizationIdByDiscoveryAttribute
                        (discoveryType.toString(), discoveryInput, appResideOrgId, context);
                if (StringUtils.isNotBlank(organizationId)) {
                    context.setProperty(ORG_ID_PARAMETER, organizationId);
                    return true;
                }
            }
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, "Can't identify organization");
            redirectToOrgDiscoveryInputCapture(response, context);
            return false;
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_VALIDATING_ORGANIZATION_DISCOVERY_ATTRIBUTE, e);
        }
    }

    /**
     * @param mainAppName               The SaaS application name.
     * @param mainAppResideTenantDomain The tenant domain of the SaaS application resides.
     * @return List of organization IDs the main application is shared.
     * @throws AuthenticationFailedException On error when retrieving the application shared organization IDs.
     */
    private List<String> getMainApplicationSharedOrganizationIds(String mainAppName, String mainAppResideTenantDomain)
            throws AuthenticationFailedException {

        String mainAppResideOrgId = getOrgIdByTenantDomain(mainAppResideTenantDomain);
        ServiceProvider mainApplication;
        try {
            mainApplication = Optional.ofNullable(
                    getApplicationManagementService().getServiceProvider(mainAppName, mainAppResideTenantDomain))
                    .orElseThrow(() -> handleAuthFailures(ERROR_CODE_INVALID_APPLICATION));
            return getOrgApplicationManager().getApplicationSharedOrganizations(mainAppResideOrgId,
                            mainApplication.getApplicationResourceId()).stream().map(BasicOrganization::getId)
                    .collect(Collectors.toList());
        } catch (IdentityApplicationManagementException | OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RETRIEVING_ORGANIZATIONS_BY_NAME, e);
        }
    }

    /**
     * This method construct the redirect URL to capture the organization discovery input / organization name.
     *
     * @param response servlet response.
     * @param context  authentication context.
     * @throws AuthenticationFailedException on errors when setting the redirect URL to capture the organization name.
     */
    @SuppressFBWarnings(value = "UNVALIDATED_REDIRECT", justification = "Redirect params are not based on user inputs.")
    private void redirectToOrgDiscoveryInputCapture(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            StringBuilder queryStringBuilder = new StringBuilder();
            queryStringBuilder.append(SESSION_DATA_KEY).append(EQUAL_SIGN)
                    .append(urlEncode(context.getContextIdentifier()));
            addQueryParam(queryStringBuilder, IDP_PARAMETER, context.getExternalIdP().getName());
            addQueryParam(queryStringBuilder, AUTHENTICATOR_PARAMETER, getName());
            addQueryParam(queryStringBuilder, SP_ID_PARAMETER, context.getServiceProviderResourceId());
            addQueryParam(queryStringBuilder, DEFAULT_PARAM, discoveryDefaultParam);
            boolean discoveryEnabled = isOrganizationDiscoveryEnabled(context);
            if (discoveryEnabled) {
                addQueryParam(queryStringBuilder, ORG_DISCOVERY_ENABLED_PARAMETER, "true");
            }
            String prompt = (String) context.getProperty(PROMPT_PARAMETER);
            if (prompt != null) {
                context.removeProperty(ORGANIZATION_LOGIN_FAILURE);
                context.removeProperty(PROMPT_PARAMETER);
            }
            if (context.getProperties().get(ORGANIZATION_LOGIN_FAILURE) != null) {
                queryStringBuilder.append(ERROR_MESSAGE)
                        .append(urlEncode((String) context.getProperties().get(ORGANIZATION_LOGIN_FAILURE)));
            }
            if (context.getProperty(SELF_REGISTRATION_PARAMETER) != null) {
                addQueryParam(queryStringBuilder, SELF_REGISTRATION_PARAMETER,
                        (String) context.getProperty(SELF_REGISTRATION_PARAMETER));
            }
            response.sendRedirect(resolveRedirectURL(context, queryStringBuilder, prompt, discoveryEnabled));
        } catch (IOException | URLBuilderException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT, e);
        }
    }

    private String resolveRedirectURL(AuthenticationContext context, StringBuilder queryStringBuilder,
                                      String prompt, boolean discoveryEnabled) throws URLBuilderException {

        AuthenticatorConstants.DiscoveryPromptOptions discoveryPromptOption
                = determineDiscoveryPromptOption(context, prompt, discoveryEnabled);
        String baseUrl = getRoutingBaseUrl(discoveryPromptOption, context);

        return FrameworkUtils.appendQueryParamsStringToUrl(baseUrl, queryStringBuilder.toString());
    }

    private AuthenticatorConstants.DiscoveryPromptOptions determineDiscoveryPromptOption(
            AuthenticationContext context, String prompt, boolean discoveryEnabled) {

        boolean isOrgParamDefault = ORG_PARAMETER.equals(discoveryDefaultParam);

        if (isOrgParamDefault) {
            if (StringUtils.equals(prompt, ORGANIZATION_NAME) || (prompt == null
                    && shouldRedirect(context, ORG_DISCOVERY_PARAMETER, ORG_PARAMETER, discoveryEnabled))) {
                return AuthenticatorConstants.DiscoveryPromptOptions.ORG_NAME;
            }
        } else {
            if (StringUtils.equals(prompt, ORG_HANDLE_PARAMETER) || (prompt == null
                    && shouldRedirect(context, ORG_DISCOVERY_PARAMETER, ORG_HANDLE_PARAMETER, discoveryEnabled))) {
                return AuthenticatorConstants.DiscoveryPromptOptions.ORG_HANDLE;
            }
        }
        return AuthenticatorConstants.DiscoveryPromptOptions.ORG_DISCOVERY;
    }

    private boolean shouldRedirect(AuthenticationContext context, String discoveryParam, String targetParam,
                                   boolean discoveryEnabled) {

        return context.getProperty(discoveryParam) == null
                && context.getProperty(targetParam) == null
                && !discoveryEnabled
                || context.getProperty(targetParam) != null;
    }

    private String getRoutingBaseUrl(AuthenticatorConstants.DiscoveryPromptOptions routingType,
                                     AuthenticationContext context) throws URLBuilderException {

        switch (routingType) {
            case ORG_NAME:
                return getOrganizationRequestPageUrl(context);
            case ORG_HANDLE:
                return getOrganizationHandleRequestPageUrl();
            case ORG_DISCOVERY:
            default:
                return getOrganizationDomainPageUrl();
        }
    }

    /**
     * Constructs the query parameters string to be included in an authorization request.
     *
     * @param context       The authentication context.
     * @param claimMappings An array of claim mappings for attribute extraction.
     * @param tenantDomain  Tenant domain.
     * @return Query parameters string .
     * @throws UnsupportedEncodingException on errors when encoding.
     * @throws ClaimMetadataException       on errors when getting claim query param.
     */
    private String getQueryParams(AuthenticationContext context, ClaimMapping[] claimMappings, String tenantDomain)
            throws UnsupportedEncodingException, ClaimMetadataException {

        StringBuilder paramBuilder = new StringBuilder();
        // Set claims query param based on the application's requested attributes.
        paramBuilder.append(getRequestedClaims(claimMappings, tenantDomain));

        String discoveryInput = (String) context.getProperty(ORG_DISCOVERY_PARAMETER);
        if (StringUtils.isNotBlank(discoveryInput)) {
            paramBuilder.append(AMPERSAND_SIGN).append(LOGIN_HINT_PARAMETER).append(EQUAL_SIGN).append(discoveryInput);
        }

        if (Boolean.parseBoolean((String) context.getProperty(FrameworkConstants.IS_API_BASED))) {
            paramBuilder.append(AMPERSAND_SIGN).append(Constants.RESPONSE_MODE).append(EQUAL_SIGN)
                    .append(Constants.DIRECT);
        }

        if (context.getProperty(SELF_REGISTRATION_PARAMETER) != null) {
            paramBuilder.append(AMPERSAND_SIGN).append(SELF_REGISTRATION_PARAMETER).append(EQUAL_SIGN)
                    .append(context.getProperty(SELF_REGISTRATION_PARAMETER));

            // Used to auto complete the username in self-registration page.
            if (context.getProperty(ORG_DISCOVERY_PARAMETER) != null &&
                    EMAIL_DOMAIN_DISCOVERY_TYPE.equals(context.getProperty(ORGANIZATION_DISCOVERY_TYPE))) {
                paramBuilder.append(AMPERSAND_SIGN).append(USERNAME_PARAMETER).append(EQUAL_SIGN)
                        .append(context.getProperty(ORG_DISCOVERY_PARAMETER));
            }
        }

        String additionalQueryParams = resolveAdditionalQueryParams(context);
        if (StringUtils.isNotBlank(additionalQueryParams)) {
            paramBuilder.append(AMPERSAND_SIGN).append(additionalQueryParams);
        }

        return paramBuilder.toString();
    }

    private String resolveAdditionalQueryParams(AuthenticationContext context) {

        Map<String, String> runtimeParams =  getRuntimeParams(context);
        String additionalQueryParams = runtimeParams.get(SSO_ADDITIONAL_PARAMS);
        if (StringUtils.isBlank(additionalQueryParams)) {
            return StringUtils.EMPTY;
        }
        additionalQueryParams = handleAuthParams(runtimeParams, additionalQueryParams);
        additionalQueryParams = handleRequestParams(context, additionalQueryParams);
        return additionalQueryParams;
    }

    private String handleAuthParams(Map<String, String> runtimeParams, String queryString) {

        Matcher matcher = Pattern.compile(DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX)
                .matcher(queryString);
        while (matcher.find()) {
            String value = StringUtils.EMPTY;
            String paramName = matcher.group(1);
            if (StringUtils.isNotEmpty(runtimeParams.get(paramName))) {
                value = runtimeParams.get(paramName);
            }
            queryString = queryString.replaceAll("\\$authparam\\{" + paramName + "}", Matcher.quoteReplacement(value));
        }
        return queryString;
    }

    private String handleRequestParams(AuthenticationContext context, String queryString) {

        String requestParamsString = context.getQueryParams();
        Map<String, String> requestParams = new HashMap<>();
        if (StringUtils.isNotBlank(requestParamsString)) {
            String[] params = requestParamsString.split(AMPERSAND_SIGN);
            for (String param : params) {
                String[] keyValue = param.split(EQUAL_SIGN);
                if (keyValue.length == 2) {
                    requestParams.put(keyValue[0], keyValue[1]);
                }
            }
        }
        Matcher matcher = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX)
                .matcher(queryString);
        while (matcher.find()) {
            String paramName = matcher.group(1);
            String value = StringUtils.EMPTY;
            if (requestParams.containsKey(paramName)) {
                value = requestParams.get(paramName);
            }
            queryString = queryString.replaceAll("\\$\\{" + paramName + "}", Matcher.quoteReplacement(value));
        }
        return queryString;
    }

    /**
     * Check whether the given organization discovery type is enabled.
     *
     * @param discoveryType Organization discovery type.
     * @return True if the organization discovery type is enabled.
     * @throws AuthenticationFailedException If an error occurs while checking the organization discovery type.
     */
    private boolean isOrganizationDiscoveryTypeEnabled(String discoveryType)
            throws AuthenticationFailedException {

        try {
            DiscoveryConfig discoveryConfig = getOrganizationConfigManager().getDiscoveryConfiguration();
            Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers =
                    getOrganizationDiscoveryManager().getAttributeBasedOrganizationDiscoveryHandlers();

            List<ConfigProperty> configProperties = discoveryConfig.getConfigProperties();
            for (ConfigProperty configProperty : configProperties) {
                String type = configProperty.getKey().split(ENABLE_CONFIG)[0];
                if (discoveryType.equals(type) && discoveryHandlers.get(type) != null &&
                        Boolean.parseBoolean(configProperty.getValue())) {
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

    private boolean isOrganizationDiscoveryEnabled(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            DiscoveryConfig discoveryConfig = getOrganizationConfigManager().getDiscoveryConfiguration();
            List<ConfigProperty> configProperties = discoveryConfig.getConfigProperties();
            for (ConfigProperty configProperty : configProperties) {
                String type = configProperty.getKey().split(ENABLE_CONFIG)[0];
                Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers =
                        getOrganizationDiscoveryManager().getAttributeBasedOrganizationDiscoveryHandlers();
                if (discoveryHandlers.get(type) != null && Boolean.parseBoolean(configProperty.getValue())) {
                    context.setProperty(ORGANIZATION_DISCOVERY_TYPE, type);
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

    private String getRequestedClaims(ClaimMapping[] claimMappings, String tenantDomain) throws ClaimMetadataException {

        if (claimMappings != null && claimMappings.length > 0) {
            StringBuilder paramBuilder = new StringBuilder("&claims={\"userinfo\":{");
            for (ClaimMapping claimMapping : claimMappings) {
                String oidcClaim = StringUtils.EMPTY;
                List<Claim> claims = getClaimManager().getMappedExternalClaimsForLocalClaim(
                        claimMapping.getLocalClaim().getClaimUri(), tenantDomain);
                if (claims != null) {
                    for (Claim claim : claims) {
                        if (OIDC_CLAIM_DIALECT_URL.equals(claim.getClaimDialectURI())) {
                            oidcClaim = String.format("\"%s\":{\"essential\": true},", claim.getClaimURI());
                            paramBuilder.append(oidcClaim);
                        }
                    }
                }
            }
            paramBuilder.deleteCharAt(paramBuilder.length() - 1);
            paramBuilder.append("}}");
            return paramBuilder.toString();
        }
        return StringUtils.EMPTY;
    }

    /**
     * When organizations with same name exists, this method construct the redirect url to select the correct
     * organization out of the similar name organizations by passing the organization name and description.
     *
     * @param response      servlet response.
     * @param context       authentication context.
     * @param organizations The list of organizations with similar name.
     * @throws AuthenticationFailedException on errors when setting the redirect URL to select the relevant
     *                                       organization.
     */
    @SuppressFBWarnings(value = "UNVALIDATED_REDIRECT", justification = "Redirect params are not based on user inputs.")
    private void redirectToSelectOrganization(HttpServletResponse response, AuthenticationContext context,
                                              List<Organization> organizations) throws AuthenticationFailedException {

        try {
            StringBuilder queryStringBuilder = new StringBuilder();
            queryStringBuilder.append(SESSION_DATA_KEY).append(EQUAL_SIGN)
                    .append(urlEncode(context.getContextIdentifier()));
            addQueryParam(queryStringBuilder, IDP_PARAMETER, context.getExternalIdP().getName());
            addQueryParam(queryStringBuilder, AUTHENTICATOR_PARAMETER, getName());
            addQueryParam(queryStringBuilder, ORG_COUNT_PARAMETER, String.valueOf(organizations.size()));
            int count = 1;
            for (Organization organization : organizations) {
                addQueryParam(queryStringBuilder, ORG_ID_PARAMETER + "_" + count, organization.getId());
                addQueryParam(queryStringBuilder, ORG_PARAMETER + "_" + count, organization.getName());
                String orgDescription = StringUtils.EMPTY;
                if (organization.getDescription() != null) {
                    orgDescription = organization.getDescription();
                }
                addQueryParam(queryStringBuilder, ORG_DESCRIPTION_PARAMETER + "_" + count, orgDescription);
                count += 1;
            }

            String url = FrameworkUtils.appendQueryParamsStringToUrl(ServiceURLBuilder.create()
                            .addPath(REQUEST_ORG_SELECT_PAGE_URL).build().getAbsolutePublicURL(),
                    queryStringBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException | URLBuilderException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT, e);
        }
    }

    private void addQueryParam(StringBuilder builder, String query, String param) throws UnsupportedEncodingException {

        builder.append(AMPERSAND_SIGN).append(query).append(EQUAL_SIGN).append(urlEncode(param));
    }

    /**
     * Obtain inbound authentication configuration of the application registered for the organization.
     *
     * @param application oauth application of the fragment.
     * @return InboundAuthenticationRequestConfig  Inbound authentication request configurations.
     */
    private Optional<InboundAuthenticationRequestConfig> getAuthenticationConfig(ServiceProvider application) {

        InboundAuthenticationConfig inboundAuthConfig = application.getInboundAuthenticationConfig();
        if (inboundAuthConfig == null) {
            return Optional.empty();
        }

        InboundAuthenticationRequestConfig[] inbounds = inboundAuthConfig.getInboundAuthenticationRequestConfigs();
        if (inbounds == null) {
            return Optional.empty();
        }

        return Arrays.stream(inbounds).filter(inbound -> INBOUND_AUTH_TYPE_OAUTH.equals(inbound.getInboundAuthType()))
                .findAny();
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        return Collections.emptyList();
    }

    /**
     * Returns the authorization endpoint url for a given organization.
     *
     * @param organizationId    Id of the organization.
     * @param tenantDomain      Tenant domain of the organization.
     * @param applicationName   Name of the application.
     * @return The authorization endpoint URL.
     */
    private String getAuthorizationEndpoint(String organizationId, String tenantDomain, String applicationName)
            throws URLBuilderException {

        ServiceURLBuilder serviceURLBuilder =
                ServiceURLBuilder.create().addPath(AUTHORIZATION_ENDPOINT_ORGANIZATION_PATH).setTenant(tenantDomain)
                        .setOrganization(organizationId);
        if ((MY_ACCOUNT_APP.equals(applicationName) || CONSOLE_APP.equals(applicationName))) {
            serviceURLBuilder.setSkipDomainBranding(true);
        }
        return serviceURLBuilder.build().getAbsolutePublicURL();
    }

    /**
     * Returns the userinfo endpoint url for a given organization.
     *
     * @param organizationId Id of the organization.
     * @param tenantDomain   Tenant domain of the organization.
     * @return The userinfo endpoint URL.
     */
    private String getUserInfoEndpoint(String organizationId, String tenantDomain) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(USERINFO_ENDPOINT_ORGANIZATION_PATH).setTenant(tenantDomain)
                .setOrganization(organizationId).build().getAbsoluteInternalURL();
    }

    /**
     * Returns the token endpoint url for a given organization.
     *
     * @param organizationId Id of the organization.
     * @param tenantDomain   Tenant domain of the organization.
     * @return The token endpoint URL.
     */
    private String getTokenEndpoint(String organizationId, String tenantDomain) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(TOKEN_ENDPOINT_ORGANIZATION_PATH).setTenant(tenantDomain)
                .setOrganization(organizationId).build().getAbsoluteInternalURL();
    }

    /**
     * Get the request organization page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return The url path to request organization name.
     */
    private String getOrganizationRequestPageUrl(AuthenticationContext context) throws URLBuilderException {

        String requestOrgPageUrl = getConfiguration(context, REQUEST_ORG_PAGE_URL_CONFIG);
        if (StringUtils.isBlank(requestOrgPageUrl)) {
            requestOrgPageUrl = REQUEST_ORG_PAGE_URL;
        }
        return ServiceURLBuilder.create().addPath(requestOrgPageUrl).build().getAbsolutePublicURL();
    }

    /**
     * Get the request organization handle page url.
     *
     * @return The url path to request organization handle.
     */
    private String getOrganizationHandleRequestPageUrl() throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(REQUEST_ORG_HANDLE_PAGE_URL).build().getAbsolutePublicURL();
    }

    private String getOrganizationDomainPageUrl() throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(REQUEST_ORG_DISCOVERY_PAGE_URL).build().getAbsolutePublicURL();
    }

    private String urlEncode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, FrameworkUtils.UTF_8);
    }

    /**
     * Read configurations from application-authentication.xml for given authenticator.
     *
     * @param context    Authentication Context.
     * @param configName Name of the config.
     * @return Config value.
     */
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
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + " for tenant " + tenantDomain + " : " + configValue);
        }
        return configValue;
    }

    private AuthenticationFailedException handleAuthFailures(OrganizationManagementConstants.ErrorMessages error) {

        return handleAuthFailures(error, null);
    }

    private AuthenticationFailedException handleAuthFailures(OrganizationManagementConstants.ErrorMessages error,
                                                             Throwable e) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage());
        }
        return new AuthenticationFailedException(error.getCode(), error.getMessage(), e);
    }

    private ApplicationManagementService getApplicationManagementService() {

        return AuthenticatorDataHolder.getInstance().getApplicationManagementService();
    }

    private OAuthAdminServiceImpl getOAuthAdminService() {

        return AuthenticatorDataHolder.getInstance().getOAuthAdminService();
    }

    private OrgApplicationManager getOrgApplicationManager() {

        return AuthenticatorDataHolder.getInstance().getOrgApplicationManager();
    }

    private OrganizationManager getOrganizationManager() {

        return AuthenticatorDataHolder.getInstance().getOrganizationManager();
    }

    private OrganizationConfigManager getOrganizationConfigManager() {

        return AuthenticatorDataHolder.getInstance().getOrganizationConfigManager();
    }

    private OrganizationDiscoveryManager getOrganizationDiscoveryManager() {

        return AuthenticatorDataHolder.getInstance().getOrganizationDiscoveryManager();
    }

    private ClaimMetadataManagementService getClaimManager() {

        return AuthenticatorDataHolder.getInstance().getClaimMetadataManagementService();
    }

    /**
     * Add app_roles scope to the scopes.
     *
     * @param scopes space separated scopes
     * @return scopes with app_roles scope
     */
    private String addAppRolesScope(String scopes) {

        return scopes + " " + APP_ROLES_SCOPE;
    }

    @Override
    protected String resolveCallBackURLForAPIBasedAuthFlow(AuthenticationContext context) {

        /*
         Even though the usual OIDC authenticator's callbackURL should be changed as client application's callbackURL
         in API_BASED auth flow to stop consuming the authorization code from commonAuth endpoint,
         OrganizationAuthenticator should not change the callbackURL.
         Even in the API_BASED auth flow, the callbackURL should be the commonAuth endpoint to consume the
         authorization code.
         */
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        return authenticatorProperties.get(CALLBACK_URL);
    }

    @Override
    protected String prepareLoginPage(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        return super.prepareLoginPage(request, context);
    }

    /**
     * Checks whether the given parameter is available in request parameters or in runtime parameters.
     *
     * @param request       Servlet request.
     * @param runtimeParams Runtime parameters given via adaptive script.
     * @param parameter     Parameter to be checked.
     * @return True if parameter exists in request parameters or runtime parameters.
     */
    private boolean isParameterExists(HttpServletRequest request, Map<String, String> runtimeParams, String parameter) {

        return request.getParameterMap().containsKey(parameter) || runtimeParams.containsKey(parameter);
    }

    /**
     * Retrieve the given parameter from request parameters or runtime parameters.
     *
     * @param request       Servlet request.
     * @param runtimeParams Runtime parameters given via adaptive script.
     * @param parameter     Parameter to be retrieved.
     * @return Parameter value retrieved from request parameters or runtime parameters.
     */
    private String getParameter(HttpServletRequest request, Map<String, String> runtimeParams, String parameter) {

        if (request.getParameterMap().containsKey(parameter)) {
            return request.getParameter(parameter);
        } else if (runtimeParams.containsKey(parameter)) {
            return runtimeParams.get(parameter);
        }
        return StringUtils.EMPTY;
    }

    /**
     * Sets the OIDC logout URL for the authenticator.
     *
     * @param context Authentication context.
     * @param orgId   Organization ID.
     * @throws AuthenticationFailedException If an error occurs while setting the logout URL.
     * @throws URLBuilderException           If an error occurs while building the URL.
     */
    private void setOIDCLogoutURL(AuthenticationContext context, String orgId)
            throws AuthenticationFailedException, URLBuilderException {

        String applicationName = context.getServiceProviderName();
        ServiceURLBuilder serviceURLBuilder = ServiceURLBuilder.create()
                .addPath("/oidc/logout")
                .setTenant(getTenantDomainByOrgId(orgId))
                .setOrganization(orgId);
        if ((MY_ACCOUNT_APP.equals(applicationName) || CONSOLE_APP.equals(applicationName))) {
            serviceURLBuilder.setSkipDomainBranding(true);
        }
        String logoutUrl = serviceURLBuilder.build().getAbsolutePublicURL();
        context.getAuthenticatorProperties().put(OIDC_LOGOUT_URL, logoutUrl);
    }

    /**
     * Sets the callback URL for the authenticator.
     * For the My Account and Console applications, the callback URL is set with domain branding skipped.
     * For all other applications, the organization's default callback URL is used (maintaining the previous behavior
     * before special handling for Console and My Account).
     *
     * @param context Authentication context.
     * @throws URLBuilderException If an error occurs while building the URL.
     */
    private static void setCallbackURL(AuthenticationContext context)
            throws URLBuilderException {

        String applicationName = context.getServiceProviderName();
        if ((MY_ACCOUNT_APP.equals(applicationName) || CONSOLE_APP.equals(applicationName))) {
            String callbackUrl =  ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH)
                    .setSkipDomainBranding(true).build().getAbsolutePublicURL();
            context.getAuthenticatorProperties().put(IdentityApplicationConstants.OAuth2.CALLBACK_URL, callbackUrl);
        }
    }
}
