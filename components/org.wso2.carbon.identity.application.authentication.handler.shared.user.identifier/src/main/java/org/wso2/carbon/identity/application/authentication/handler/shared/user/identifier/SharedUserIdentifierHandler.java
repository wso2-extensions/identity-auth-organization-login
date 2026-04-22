/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants;
import org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.internal.SharedUserIdentifierAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.DISPLAY_USER_NAME;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.ErrorMessages;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.LogConstants.ActionIDs.AUTHENTICATOR_SHARED_USER_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.LogConstants.ActionIDs.INITIATE_SHARED_USER_IDENTIFIER_AUTH_REQUEST;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.LogConstants.SHARED_USER_IDENTIFIER_AUTH_SERVICE;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.USERNAME_USER_INPUT;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.USER_NAME;

/**
 * Shared user identifier based handler.
 * <p>
 * This handler is responsible for taking a user identifier input and checking if the user is a shared user
 * in the accessing organization. It extends {@link AbstractApplicationAuthenticator} and implements
 * {@link AuthenticationFlowHandler}.
 * </p>
 */
public class SharedUserIdentifierHandler extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final Log LOG = LogFactory.getLog(SharedUserIdentifierHandler.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String userName = request.getParameter(USER_NAME);
        boolean canHandle = StringUtils.isNotBlank(userName);
        if (LoggerUtils.isDiagnosticLogsEnabled() && canHandle) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE,
                    FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("Shared User Identifier Handler is handling the request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        return super.process(request, response, context);
    }

    @Override
    @SuppressFBWarnings(value = "UNVALIDATED_REDIRECT", justification = "Redirect params are not based on user inputs.")
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE, INITIATE_SHARED_USER_IDENTIFIER_AUTH_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating shared user identifier first authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        try {
            response.sendRedirect(buildRedirectURL(context));
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(getName() + " failed while initiating the authentication request.", e);
            }
            throw new AuthenticationFailedException(ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        DiagnosticLog.DiagnosticLogBuilder authProcessCompletedDiagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing shared user identifier first authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);

            authProcessCompletedDiagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            authProcessCompletedDiagnosticLogBuilder.inputParams(getApplicationDetails(context))
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep());
        }

        String identifierFromRequest = request.getParameter(USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new InvalidCredentialsException(ErrorMessages.EMPTY_USERNAME.getCode(),
                    ErrorMessages.EMPTY_USERNAME.getMessage());
        }
        context.setProperty(USERNAME_USER_INPUT, identifierFromRequest);

        AuthenticatedUser user = new AuthenticatedUser();
        String tenantDomain = context.getTenantDomain();
        String userStoreDomain = IdentityUtil.extractDomainFromName(identifierFromRequest);
        Optional<String> userId = resolveUserIdFromUserStore(tenantDomain, identifierFromRequest, userStoreDomain,
                user);
        // To autopopulate username at later steps.
        persistUsername(context, identifierFromRequest);

        if (userId.isEmpty()) {
            /* User does not exist in the accessing organization.
             * Skip shared user resolution and pass the flow to the next step.
             */
            user.setUserName(identifierFromRequest);
            context.setSubject(user);
            return;
        }

        // Check if the user is a shared user using OrganizationUserSharingService.
        resolveSharedUser(userId.get(), tenantDomain, identifierFromRequest, user, context);
        if (LoggerUtils.isDiagnosticLogsEnabled() && authProcessCompletedDiagnosticLogBuilder != null) {
            authProcessCompletedDiagnosticLogBuilder
                    .resultMessage("Shared user identifier first authentication successful.")
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable
                            ? LoggerUtils.getMaskedContent(identifierFromRequest) : identifierFromRequest)
                    .inputParam(LogConstants.InputKeys.USER_ID, userId.get());
            LoggerUtils.triggerDiagnosticLogEvent(authProcessCompletedDiagnosticLogBuilder);
        }
    }

    /**
     * Resolves the user ID from the user store for the given tenant domain and username.
     *
     * @param tenantDomain        The tenant domain.
     * @param tenantAwareUsername The tenant aware username.
     * @return The resolved user ID.
     * @throws AuthenticationFailedException If user resolution fails.
     */
    private Optional<String> resolveUserIdFromUserStore(String tenantDomain, String tenantAwareUsername,
                                                        String userStoreDomain, AuthenticatedUser user)
            throws AuthenticationFailedException {

        try {
            int tenantId = SharedUserIdentifierAuthenticatorDataHolder
                    .getInstance().getRealmService().getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = SharedUserIdentifierAuthenticatorDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);
            if (userRealm == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Cannot find the user realm for the tenant ID: " + tenantId);
                }
                throw new AuthenticationFailedException(
                        ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getCode(),
                        String.format(ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getMessage(),
                                tenantId), User.getUserFromUserName(tenantAwareUsername));
            }
            String userId = searchUserInUserStores(tenantAwareUsername, userRealm, userStoreDomain, user);
            if (userId == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("User does not exist in tenant: " + tenantDomain);
                }
                return Optional.empty();
            }

            return Optional.of(userId);
        } catch (UserStoreException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SharedUserIdentifierHandler failed while trying to authenticate.", e);
            }

            throw new AuthenticationFailedException(
                    ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(),
                    e.getMessage(), User.getUserFromUserName(tenantAwareUsername), e);
        }
    }

    /**
     * Searches for a user across user stores within the given user realm and returns the user ID if found.
     * If a specific user store domain is provided, the search is scoped to that domain; otherwise, the
     * primary user store and all secondary user stores are iterated until the user is located.
     * When the user is found, the matched user store domain is set on the {@link AuthenticatedUser} object.
     *
     * @param username        The tenant-aware username to search for.
     * @param userRealm       The user realm of the tenant.
     * @param userStoreDomain The user store domain to scope the search, or blank to search all stores.
     * @param user            The authenticated user object to update with the resolved user store domain.
     * @return The user ID if the user is found, or {@code null} if the user does not exist in any user store.
     * @throws UserStoreException If an error occurs while accessing the user store.
     */
    private static String searchUserInUserStores(String username, UserRealm userRealm, String userStoreDomain,
                                                 AuthenticatedUser user) throws UserStoreException {

        if (StringUtils.isNotBlank(userStoreDomain)) {
            username = UserCoreUtil.addDomainToName(username, userStoreDomain);
        }

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
        String userId = userStoreManager.getUserIDFromUserName(username);

        while (userId == null && userStoreManager.getSecondaryUserStoreManager() != null) {
            userStoreManager = (AbstractUserStoreManager) userStoreManager.getSecondaryUserStoreManager();
            userId = userStoreManager.getUserIDFromUserName(username);
        }

        if (userId != null) {
            user.setUserStoreDomain(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()));
        }

        return userId;
    }

    /**
     * Validates whether the given user is a shared user in the current tenant by checking
     * the user association using the {@link OrganizationUserSharingService}.
     *
     * @param userId          The user ID.
     * @param tenantDomain    The tenant domain.
     * @param username        The full username (used for error context).
     * @param context         The authentication context.
     * @throws AuthenticationFailedException If an error occurs while resolving the shared user.
     */
    private void resolveSharedUser(String userId, String tenantDomain, String username, AuthenticatedUser user,
                                   AuthenticationContext context) throws AuthenticationFailedException {

        user.setUserName(username);
        try {
            OrganizationManager organizationManager = SharedUserIdentifierAuthenticatorDataHolder
                    .getInstance().getOrganizationManager();
            String organizationId = organizationManager.resolveOrganizationId(tenantDomain);
            OrganizationUserSharingService userSharingService = SharedUserIdentifierAuthenticatorDataHolder
                    .getInstance().getOrganizationUserSharingService();
            UserAssociation userAssociation = userSharingService.getUserAssociation(userId, organizationId);
            if (userAssociation != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("User with ID: " + userId + " is confirmed as a shared user in organization: "
                            + organizationId + " (associated user ID: " + userAssociation.getAssociatedUserId()
                            + ", resident org: " + userAssociation.getUserResidentOrganizationId() + ")");
                }

                /*
                 * If the user is confirmed as a shared user, update the authenticated user to reflect that they are
                 * accessing a sub-organization. The authenticated user is treated as a shared user in the framework
                 * only when these properties are set by this handler.
                 */
                user.setUserResidentOrganization(userAssociation.getUserResidentOrganizationId());
                user.setAccessingOrganization(organizationManager.resolveOrganizationId(context.getTenantDomain()));
                user.setTenantDomain(organizationManager.resolveTenantDomain(
                        userAssociation.getUserResidentOrganizationId()));
                user.setSharedUserId(userId);
                user.setSharedUser(true);
            }

            context.setSubject(user);
        } catch (OrganizationManagementException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SharedUserIdentifierHandler failed while checking shared user status.", e);
            }
            throw new AuthenticationFailedException(ErrorMessages.ORGANIZATION_MGT_EXCEPTION.getCode(),
                    e.getMessage(), User.getUserFromUserName(username), e);
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    @Override
    public String getFriendlyName() {

        return SharedUserIdentifierHandlerConstants.HANDLER_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return SharedUserIdentifierHandlerConstants.HANDLER_NAME;
    }

    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
    }

    /**
     * Build the redirect URL for the authentication request.
     *
     * @param context The authentication context.
     * @return The redirect URL.
     */
    private String buildRedirectURL(AuthenticationContext context) {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = context.getContextIdIncludedQueryParams();

        StringBuilder queryStringBuilder = new StringBuilder(queryParams);
        queryStringBuilder.append(SharedUserIdentifierHandlerConstants.AMPERSAND_SIGN)
                .append(SharedUserIdentifierHandlerConstants.AUTHENTICATORS_PARAM)
                .append(SharedUserIdentifierHandlerConstants.EQUAL_SIGN)
                .append(getName())
                .append(SharedUserIdentifierHandlerConstants.COLON_SIGN)
                .append(SharedUserIdentifierHandlerConstants.LOCAL);

        if (context.isRetrying()) {
            queryStringBuilder.append(SharedUserIdentifierHandlerConstants.AMPERSAND_SIGN)
                    .append(SharedUserIdentifierHandlerConstants.AUTH_FAILURE)
                    .append(SharedUserIdentifierHandlerConstants.EQUAL_SIGN)
                    .append(SharedUserIdentifierHandlerConstants.TRUE)
                    .append(SharedUserIdentifierHandlerConstants.AMPERSAND_SIGN)
                    .append(SharedUserIdentifierHandlerConstants.AUTH_FAILURE_MSG)
                    .append(SharedUserIdentifierHandlerConstants.EQUAL_SIGN)
                    .append(SharedUserIdentifierHandlerConstants.LOGIN_FAILED_GENERIC);
        }

        return FrameworkUtils.appendQueryParamsStringToUrl(loginPage, queryStringBuilder.toString());
    }

    /**
     * Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map with application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME, applicationName));
        return applicationDetailsMap;
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        String idpName = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(USER_NAME);
        authenticatorData.setRequiredParams(requiredParams);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USER_NAME, DISPLAY_USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, USER_NAME);
        authenticatorParamMetadataList.add(usernameMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);

        return Optional.of(authenticatorData);
    }

    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_SHARED_USER_IDENTIFIER;
    }
}
