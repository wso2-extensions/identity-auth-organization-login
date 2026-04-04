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

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.internal.SharedUserIdentifierAuthenticatorDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.HANDLER_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.constants.SharedUserIdentifierHandlerConstants.HANDLER_NAME;

/**
 * Unit test class for {@link SharedUserIdentifierHandler}.
 */
public class SharedUserIdentifierHandlerTest {

    private static final String TEST_USERNAME = "testUser";
    private static final String TEST_TENANT_DOMAIN = "test-tenant.com";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_ORG_ID = "test-org-id";
    private static final String TEST_RESIDENT_ORG_ID = "resident-org-id";
    private static final String TEST_ASSOCIATED_USER_ID = "associated-user-id";
    private static final String TEST_RESIDENT_TENANT_DOMAIN = "resident-tenant.com";
    private static final String TEST_USER_STORE_DOMAIN = "PRIMARY";
    private static final String LOGIN_PAGE = "https://localhost:9443/authenticationendpoint/login.do";
    private static final String QUERY_PARAMS = "sessionDataKey=test-session-key";
    private static final int TEST_TENANT_ID = 1;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private AuthenticationContext context;
    @Mock
    private ExternalIdPConfig externalIdPConfig;
    @Mock
    private SharedUserIdentifierAuthenticatorDataHolder dataHolder;
    @Mock
    private RealmService realmService;
    @Mock
    private TenantManager tenantManager;
    @Mock
    private UserRealm userRealm;
    @Mock
    private AbstractUserStoreManager userStoreManager;
    @Mock
    private OrganizationManager organizationManager;
    @Mock
    private OrganizationUserSharingService organizationUserSharingService;

    private AutoCloseable closeable;
    private MockedStatic<SharedUserIdentifierAuthenticatorDataHolder> dataHolderStatic;
    private MockedStatic<LoggerUtils> loggerUtilsStatic;
    private MockedStatic<FrameworkUtils> frameworkUtilsStatic;
    private MockedStatic<IdentityUtil> identityUtilStatic;
    private MockedStatic<ConfigurationFacade> configurationFacadeStatic;

    private SharedUserIdentifierHandler sharedUserIdentifierHandler;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
        dataHolderStatic = mockStatic(SharedUserIdentifierAuthenticatorDataHolder.class);
        loggerUtilsStatic = mockStatic(LoggerUtils.class);
        frameworkUtilsStatic = mockStatic(FrameworkUtils.class);
        identityUtilStatic = mockStatic(IdentityUtil.class);
        configurationFacadeStatic = mockStatic(ConfigurationFacade.class);

        loggerUtilsStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        dataHolderStatic.when(SharedUserIdentifierAuthenticatorDataHolder::getInstance).thenReturn(dataHolder);

        when(dataHolder.getRealmService()).thenReturn(realmService);
        when(dataHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(organizationUserSharingService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);

        sharedUserIdentifierHandler = spy(new SharedUserIdentifierHandler());
    }

    @AfterMethod
    public void tearDown() throws Exception {

        configurationFacadeStatic.close();
        identityUtilStatic.close();
        frameworkUtilsStatic.close();
        loggerUtilsStatic.close();
        dataHolderStatic.close();
        closeable.close();
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(sharedUserIdentifierHandler.getName(), HANDLER_NAME);
    }

    @Test
    public void testGetFriendlyName() {

        Assert.assertEquals(sharedUserIdentifierHandler.getFriendlyName(), HANDLER_FRIENDLY_NAME);
    }

    @Test
    public void testGetI18nKey() {

        Assert.assertEquals(sharedUserIdentifierHandler.getI18nKey(),
                "authenticator.shared-user-identifier");
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        Assert.assertTrue(sharedUserIdentifierHandler.isAPIBasedAuthenticationSupported());
    }

    @DataProvider(name = "canHandleDataProvider")
    public Object[][] canHandleDataProvider() {

        return new Object[][]{
                {TEST_USERNAME, true},
                {"", false},
                {null, false},
                {"  ", false},
        };
    }

    @Test(dataProvider = "canHandleDataProvider")
    public void testCanHandle(String username, boolean expectedResult) {

        when(request.getParameter("username")).thenReturn(username);
        Assert.assertEquals(sharedUserIdentifierHandler.canHandle(request), expectedResult);
    }

    @Test
    public void testProcessWithLogoutRequest() throws Exception {

        when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = sharedUserIdentifierHandler.process(request, response, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testInitiateAuthenticationRequest() throws Exception {

        setupRedirectStubs();
        when(context.isRetrying()).thenReturn(false);

        sharedUserIdentifierHandler.initiateAuthenticationRequest(request, response, context);

        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(redirectCaptor.capture());
        String redirectUrl = redirectCaptor.getValue();
        Assert.assertTrue(redirectUrl.contains("authenticators=" + HANDLER_NAME + ":LOCAL"));
    }

    @Test
    public void testInitiateAuthenticationRequestWithRetry() throws Exception {

        setupRedirectStubs();
        when(context.isRetrying()).thenReturn(true);

        sharedUserIdentifierHandler.initiateAuthenticationRequest(request, response, context);

        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(redirectCaptor.capture());
        String redirectUrl = redirectCaptor.getValue();
        Assert.assertTrue(redirectUrl.contains("authFailure=true"));
        Assert.assertTrue(redirectUrl.contains("authFailureMsg=login.failed.generic"));
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testInitiateAuthenticationRequestIOException() throws Exception {

        setupRedirectStubs();
        when(context.isRetrying()).thenReturn(false);
        Mockito.doThrow(new IOException("redirect failed")).when(response).sendRedirect(anyString());

        sharedUserIdentifierHandler.initiateAuthenticationRequest(request, response, context);
    }

    @Test(expectedExceptions = InvalidCredentialsException.class)
    public void testProcessAuthenticationResponseWithEmptyUsername() throws Exception {

        when(request.getParameter("username")).thenReturn("");

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);
    }

    @Test(expectedExceptions = InvalidCredentialsException.class)
    public void testProcessAuthenticationResponseWithNullUsername() throws Exception {

        when(request.getParameter("username")).thenReturn(null);

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);
    }

    @Test
    public void testProcessAuthenticationResponseUserNotFound() throws Exception {

        setupUserResolutionMocks();
        when(userStoreManager.getUserIDFromUserName(TEST_USERNAME)).thenReturn(null);

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);

        ArgumentCaptor<AuthenticatedUser> userCaptor = ArgumentCaptor.forClass(AuthenticatedUser.class);
        verify(context).setSubject(userCaptor.capture());
        AuthenticatedUser capturedUser = userCaptor.getValue();
        Assert.assertEquals(capturedUser.getUserName(), TEST_USERNAME);
        Assert.assertFalse(capturedUser.isSharedUser());
    }

    @Test
    public void testProcessAuthenticationResponseSharedUser() throws Exception {

        setupUserResolutionMocks();
        when(userStoreManager.getUserIDFromUserName(TEST_USERNAME)).thenReturn(TEST_USER_ID);
        when(organizationManager.resolveOrganizationId(TEST_TENANT_DOMAIN)).thenReturn(TEST_ORG_ID);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);

        UserAssociation userAssociation = mock(UserAssociation.class);
        when(userAssociation.getAssociatedUserId()).thenReturn(TEST_ASSOCIATED_USER_ID);
        when(userAssociation.getUserResidentOrganizationId()).thenReturn(TEST_RESIDENT_ORG_ID);
        when(organizationUserSharingService.getUserAssociation(TEST_USER_ID, TEST_ORG_ID))
                .thenReturn(userAssociation);
        when(organizationManager.resolveTenantDomain(TEST_RESIDENT_ORG_ID))
                .thenReturn(TEST_RESIDENT_TENANT_DOMAIN);

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);

        ArgumentCaptor<AuthenticatedUser> userCaptor = ArgumentCaptor.forClass(AuthenticatedUser.class);
        verify(context).setSubject(userCaptor.capture());
        AuthenticatedUser capturedUser = userCaptor.getValue();
        Assert.assertEquals(capturedUser.getUserName(), TEST_USERNAME);
        Assert.assertTrue(capturedUser.isSharedUser());
        Assert.assertEquals(capturedUser.getUserResidentOrganization(), TEST_RESIDENT_ORG_ID);
        Assert.assertEquals(capturedUser.getTenantDomain(), TEST_RESIDENT_TENANT_DOMAIN);
        Assert.assertEquals(capturedUser.getAccessingOrganization(), TEST_ORG_ID);
    }

    @Test
    public void testProcessAuthenticationResponseNonSharedUser() throws Exception {

        setupUserResolutionMocks();
        when(userStoreManager.getUserIDFromUserName(TEST_USERNAME)).thenReturn(TEST_USER_ID);
        when(organizationManager.resolveOrganizationId(TEST_TENANT_DOMAIN)).thenReturn(TEST_ORG_ID);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        when(organizationUserSharingService.getUserAssociation(TEST_USER_ID, TEST_ORG_ID))
                .thenReturn(null);

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);

        ArgumentCaptor<AuthenticatedUser> userCaptor = ArgumentCaptor.forClass(AuthenticatedUser.class);
        verify(context).setSubject(userCaptor.capture());
        AuthenticatedUser capturedUser = userCaptor.getValue();
        Assert.assertEquals(capturedUser.getUserName(), TEST_USERNAME);
        Assert.assertFalse(capturedUser.isSharedUser());
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseNullUserRealm() throws Exception {

        when(request.getParameter("username")).thenReturn(TEST_USERNAME);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        identityUtilStatic.when(() -> IdentityUtil.extractDomainFromName(TEST_USERNAME))
                .thenReturn(TEST_USER_STORE_DOMAIN);
        when(tenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);
        when(realmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(null);

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseUserStoreException() throws Exception {

        when(request.getParameter("username")).thenReturn(TEST_USERNAME);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        identityUtilStatic.when(() -> IdentityUtil.extractDomainFromName(TEST_USERNAME))
                .thenReturn(TEST_USER_STORE_DOMAIN);
        when(tenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenThrow(
                new UserStoreException("user store error"));

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseOrgManagementException() throws Exception {

        setupUserResolutionMocks();
        when(userStoreManager.getUserIDFromUserName(TEST_USERNAME)).thenReturn(TEST_USER_ID);
        when(organizationManager.resolveOrganizationId(TEST_TENANT_DOMAIN))
                .thenThrow(new OrganizationManagementException("org error"));
        when(context.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);

        sharedUserIdentifierHandler.processAuthenticationResponse(request, response, context);
    }

    @Test
    public void testGetAuthInitiationData() {

        Optional<AuthenticatorData> result = sharedUserIdentifierHandler.getAuthInitiationData(context);

        Assert.assertTrue(result.isPresent());
        AuthenticatorData data = result.get();
        Assert.assertEquals(data.getName(), HANDLER_NAME);
        Assert.assertEquals(data.getI18nKey(), "authenticator.shared-user-identifier");
        Assert.assertEquals(data.getDisplayName(), HANDLER_FRIENDLY_NAME);
        Assert.assertEquals(data.getPromptType(), FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        Assert.assertEquals(data.getRequiredParams().size(), 1);
        Assert.assertTrue(data.getRequiredParams().contains("username"));
        Assert.assertEquals(data.getAuthParams().size(), 1);
    }

    private void setupRedirectStubs() {

        ConfigurationFacade configurationFacade = mock(ConfigurationFacade.class);
        configurationFacadeStatic.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(LOGIN_PAGE);
        when(context.getContextIdIncludedQueryParams()).thenReturn(QUERY_PARAMS);
        frameworkUtilsStatic.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));
    }

    private void setupUserResolutionMocks() throws Exception {

        when(request.getParameter("username")).thenReturn(TEST_USERNAME);
        when(context.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        identityUtilStatic.when(() -> IdentityUtil.extractDomainFromName(TEST_USERNAME))
                .thenReturn(TEST_USER_STORE_DOMAIN);
        when(tenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);
        when(realmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
    }
}
