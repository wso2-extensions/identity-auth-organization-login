/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.organization.login.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementClientException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.BasicOrganization;
import org.wso2.carbon.identity.organization.management.service.model.Organization;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SESSION_DATA_KEY;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AMPERSAND_SIGN;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHORIZATION_ENDPOINT_ORGANIZATION_PATH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.EQUAL_SIGN;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ERROR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.IDP_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.INBOUND_AUTH_TYPE_OAUTH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_ATTRIBUTE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_LOGIN_FAILURE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_PLACEHOLDER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_USER_ATTRIBUTE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_COUNT_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DESCRIPTION_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_ID_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_PAGE_URL_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.REQUEST_ORG_SELECT_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.TOKEN_ENDPOINT_ORGANIZATION_PATH;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.CALLBACK_URL;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_ORGANIZATION_DOMAIN_FROM_TENANT_DOMAIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_ORGANIZATION_LOGIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_APPLICATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_ORGANIZATIONS_BY_NAME;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_ORGANIZATION_NAME_BY_ID;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_APPLICATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
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
            super.initiateAuthenticationRequest(request, response, context);
        }
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
                    .put(ClaimMapping.build(ORGANIZATION_USER_ATTRIBUTE, ORGANIZATION_USER_ATTRIBUTE, null, false),
                            context.getAuthenticatorProperties().get(ORGANIZATION_ATTRIBUTE));
        }
    }

    @Override
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(scope)) {
            scope = "openid email profile phone address";
        }
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

        if (!context.getProperties().containsKey(ORG_PARAMETER) || !context.getProperties()
                .containsKey(ORG_ID_PARAMETER)) {
            throw handleAuthFailures(ERROR_CODE_ORG_PARAMETERS_NOT_RESOLVED);
        }
        String organizationName = context.getProperty(ORG_PARAMETER).toString();

        // Get the shared service provider based on the requested organization.
        String appResideOrgId = getOrgIdByTenantDomain(appResideTenantDomain);
        String sharedOrgId = context.getProperty(ORG_ID_PARAMETER).toString();
        ServiceProvider sharedApplication;
        // If the shared application cannot be found for the particular organization,
        // will set a "organizationLoginFailure" property in the context and will check this in Authentication Process.
        try {
            sharedApplication = getOrgApplicationManager()
                    .resolveSharedApplication(application, appResideOrgId, sharedOrgId);
        } catch (OrganizationManagementClientException e) {
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, "Organization is not associated with this application.");
            redirectToOrgNameCapture(response, context);
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
            OAuthConsumerAppDTO oauthApp = getOAuthAdminService().getOAuthApplicationData(clientId);

            authenticatorProperties.put(CLIENT_ID, clientId);
            authenticatorProperties.put(CLIENT_SECRET, oauthApp.getOauthConsumerSecret());
            authenticatorProperties.put(ORGANIZATION_ATTRIBUTE, organizationName);
            authenticatorProperties.put(OAUTH2_AUTHZ_URL, getAuthorizationEndpoint(sharedOrgId));
            authenticatorProperties.put(OAUTH2_TOKEN_URL, getTokenEndpoint(sharedOrgId));
            authenticatorProperties.put(CALLBACK_URL, oauthApp.getCallbackUrl());

        } catch (IdentityOAuthAdminException | URLBuilderException e) {
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

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {

        if (context.isLogoutRequest()) {
            super.processLogoutResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // First priority for organization Id.
        if (request.getParameterMap().containsKey(ORG_ID_PARAMETER)) {
            String organizationId = request.getParameter(ORG_ID_PARAMETER);
            context.setProperty(ORG_ID_PARAMETER, organizationId);
            String organizationName = getOrganizationNameById(organizationId);
            context.setProperty(ORG_PARAMETER, organizationName);
        } else if (request.getParameterMap().containsKey(ORG_PARAMETER)) {
            String organizationName = request.getParameter(ORG_PARAMETER);
            context.setProperty(ORG_PARAMETER, organizationName);
            if (!validateOrganizationName(organizationName, context, response)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }

        if (!context.getProperties().containsKey(ORG_PARAMETER)) {
            redirectToOrgNameCapture(response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        return super.process(request, response, context);
    }

    private String getOrganizationNameById(String organizationId) throws AuthenticationFailedException {

        try {
            return getOrganizationManager().getOrganizationNameById(organizationId);
        } catch (OrganizationManagementClientException e) {
            throw handleAuthFailures(ERROR_CODE_INVALID_ORGANIZATION_ID);
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RETRIEVING_ORGANIZATION_NAME_BY_ID, e);
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
                redirectToOrgNameCapture(response, context);
            }
        } catch (OrganizationManagementClientException e) {
            context.setProperty(ORGANIZATION_LOGIN_FAILURE, "Invalid Organization Name");
            redirectToOrgNameCapture(response, context);
        } catch (OrganizationManagementException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_RETRIEVING_ORGANIZATIONS_BY_NAME, e);
        }
        return false;
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
     * When the organization name is not found or invalid, this method construct the redirect URL to capture the
     * organization name.
     *
     * @param response servlet response.
     * @param context  authentication context.
     * @throws AuthenticationFailedException on errors when setting the redirect URL to capture the organization name.
     */
    @SuppressFBWarnings(value = "UNVALIDATED_REDIRECT", justification = "Redirect params are not based on user inputs.")
    private void redirectToOrgNameCapture(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            StringBuilder queryStringBuilder = new StringBuilder();
            queryStringBuilder.append(SESSION_DATA_KEY).append(EQUAL_SIGN)
                    .append(urlEncode(context.getContextIdentifier()));
            addQueryParam(queryStringBuilder, IDP_PARAMETER, context.getExternalIdP().getName());
            addQueryParam(queryStringBuilder, AUTHENTICATOR_PARAMETER, getName());

            if (context.getProperties().get(ORGANIZATION_LOGIN_FAILURE) != null) {
                queryStringBuilder.append(ERROR_MESSAGE)
                        .append(urlEncode((String) context.getProperties().get(ORGANIZATION_LOGIN_FAILURE)));
            }

            String url = FrameworkUtils.appendQueryParamsStringToUrl(getOrganizationRequestPageUrl(context),
                    queryStringBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException | URLBuilderException e) {
            throw handleAuthFailures(ERROR_CODE_ERROR_REQUEST_ORGANIZATION_REDIRECT, e);
        }
    }

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
     * @param organizationId Id of the organization.
     * @return The authorization endpoint URL.
     */
    private String getAuthorizationEndpoint(String organizationId) throws URLBuilderException {

        return ServiceURLBuilder.create()
                .addPath(AUTHORIZATION_ENDPOINT_ORGANIZATION_PATH.replace(ORGANIZATION_PLACEHOLDER, organizationId))
                .build().getAbsolutePublicURL();
    }

    /**
     * Returns the token endpoint url for a given organization.
     *
     * @param organizationId Id of the organization.
     * @return The token endpoint URL.
     */
    private String getTokenEndpoint(String organizationId) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(TOKEN_ENDPOINT_ORGANIZATION_PATH.replace(ORGANIZATION_PLACEHOLDER,
                organizationId)).build().getAbsolutePublicURL();
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
}
