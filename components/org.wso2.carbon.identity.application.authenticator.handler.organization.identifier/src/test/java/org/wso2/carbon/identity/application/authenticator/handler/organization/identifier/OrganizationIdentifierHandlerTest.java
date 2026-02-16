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
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.orgdiscovery.OrganizationDiscoveryHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryInput;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.internal.OrganizationIdentifierHandlerDataHolder;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.config.service.exception.OrganizationConfigException;
import org.wso2.carbon.identity.organization.config.service.model.ConfigProperty;
import org.wso2.carbon.identity.organization.config.service.model.DiscoveryConfig;
import org.wso2.carbon.identity.organization.config.service.util.OrganizationConfigManagerUtil;
import org.wso2.carbon.identity.organization.discovery.service.AttributeBasedOrganizationDiscoveryHandler;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;
import org.wso2.carbon.identity.organization.management.service.model.Organization;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.organization.config.service.constant.OrganizationConfigConstants.ErrorMessages.ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST;
import static org.wso2.carbon.identity.organization.discovery.service.constant.DiscoveryConstants.ENABLE_CONFIG;

/**
 * Unit test class for {@link OrganizationIdentifierHandler}.
 */
public class OrganizationIdentifierHandlerTest {

    private static final String CONTEXT_ID = "test-context-id";
    private static final String SP_RESOURCE_ID = "test-sp-resource-id";
    private static final String ORG_ID = "test-org-id";
    private static final String ORG_NAME = "test-org";
    private static final String ORG_HANDLE = "test-org-handle";
    private static final String LOGIN_HINT = "user@example.com";
    private static final String SHARED_APP_ID = "shared-app-id";
    private static final String BASE_URL = "https://localhost:9443";
    private static final String EMAIL_DOMAIN_TYPE = "emailDomain";

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private AuthenticationContext context;
    @Mock
    private ExternalIdPConfig externalIdPConfig;
    @Mock
    private OrganizationDiscoveryHandler organizationDiscoveryHandler;
    @Mock
    private OrganizationConfigManager organizationConfigManager;
    @Mock
    private OrganizationDiscoveryManager organizationDiscoveryManager;
    @Mock
    private OrganizationDiscoveryResult organizationDiscoveryResult;
    @Mock
    private OrganizationIdentifierHandlerDataHolder dataHolder;

    private AutoCloseable closeable;
    private MockedStatic<OrganizationIdentifierHandlerDataHolder> organizationIdentifierHandlerDataHolderStatic;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderStatic;
    private MockedStatic<FrameworkUtils> frameworkUtilsStatic;
    private MockedStatic<OrganizationConfigManagerUtil> organizationConfigManagerUtilStatic;

    private OrganizationIdentifierHandler organizationIdentifierHandler;

    @BeforeMethod
    public void setUp() {

        closeable = MockitoAnnotations.openMocks(this);
        organizationIdentifierHandlerDataHolderStatic = mockStatic(OrganizationIdentifierHandlerDataHolder.class);
        serviceURLBuilderStatic = mockStatic(ServiceURLBuilder.class);
        frameworkUtilsStatic = mockStatic(FrameworkUtils.class);
        organizationConfigManagerUtilStatic = mockStatic(OrganizationConfigManagerUtil.class);

        organizationIdentifierHandlerDataHolderStatic.when(OrganizationIdentifierHandlerDataHolder::getInstance)
                .thenReturn(dataHolder);
        when(dataHolder.getOrganizationDiscoveryHandler()).thenReturn(organizationDiscoveryHandler);
        when(dataHolder.getOrganizationConfigManager()).thenReturn(organizationConfigManager);
        when(dataHolder.getOrganizationDiscoveryManager()).thenReturn(organizationDiscoveryManager);

        organizationIdentifierHandler = spy(new OrganizationIdentifierHandler());

        when(context.getContextIdentifier()).thenReturn(CONTEXT_ID);
        when(context.getServiceProviderResourceId()).thenReturn(SP_RESOURCE_ID);
        doReturn(new HashMap<String, String>()).when(organizationIdentifierHandler).getRuntimeParams(context);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        organizationConfigManagerUtilStatic.close();
        frameworkUtilsStatic.close();
        serviceURLBuilderStatic.close();
        organizationIdentifierHandlerDataHolderStatic.close();
        closeable.close();
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(organizationIdentifierHandler.getName(), "OrganizationIdentifierHandler");
    }

    @Test
    public void testGetFriendlyName() {

        Assert.assertEquals(organizationIdentifierHandler.getFriendlyName(), "Organization SSO");
    }

    @Test
    public void testGetContextIdentifier() {

        when(request.getParameter("sessionDataKey")).thenReturn("test-session-key");

        Assert.assertEquals(organizationIdentifierHandler.getContextIdentifier(request), "test-session-key");
    }

    @Test
    public void testGetI18nKey() {

        Assert.assertEquals(organizationIdentifierHandler.getI18nKey(), "authenticator.organization.identifier");
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        Assert.assertTrue(organizationIdentifierHandler.isAPIBasedAuthenticationSupported());
    }

    @DataProvider(name = "canHandleDataProvider")
    public Object[][] canHandleDataProvider() {

        return new Object[][]{
                {ORG_ID, null, null, null, true},
                {null, ORG_HANDLE, null, null, true},
                {null, null, ORG_NAME, null, true},
                {null, null, null, LOGIN_HINT, true},
                {ORG_ID, ORG_HANDLE, null, null, true},
                {null, null, null, null, false},
        };
    }

    @Test(dataProvider = "canHandleDataProvider")
    public void testCanHandle(String orgId, String orgHandle, String orgName, String loginHint,
                              boolean expectedResult) {

        when(request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID)).thenReturn(orgId);
        when(request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.ORG_HANDLE)).thenReturn(orgHandle);
        when(request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.ORG_NAME)).thenReturn(orgName);
        when(request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.LOGIN_HINT)).thenReturn(loginHint);

        Assert.assertEquals(organizationIdentifierHandler.canHandle(request), expectedResult);
    }

    @Test
    public void testProcessWithLogoutRequest() throws Exception {

        when(context.isLogoutRequest()).thenReturn(true);

        AuthenticatorFlowStatus status = organizationIdentifierHandler.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithOrgIdInRequest() throws Exception {

        setupRequestParamMap(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID, ORG_ID);
        setupSuccessfulDiscovery();

        AuthenticatorFlowStatus status = organizationIdentifierHandler.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithOrgIdInRuntimeParams() throws Exception {

        when(request.getParameterMap()).thenReturn(new HashMap<>());
        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID, ORG_ID);
        doReturn(runtimeParams).when(organizationIdentifierHandler).getRuntimeParams(context);
        setupSuccessfulDiscovery();

        AuthenticatorFlowStatus status = organizationIdentifierHandler.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithDiscoveryFailure() throws Exception {

        when(request.getParameterMap()).thenReturn(new HashMap<>());
        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID, ORG_ID);
        doReturn(runtimeParams).when(organizationIdentifierHandler).getRuntimeParams(context);
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenReturn(organizationDiscoveryResult);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(false);
        setupRedirectStubs("orgHandle");
        setupDiscoveryDisabled();
        when(context.getTenantDomain()).thenReturn("test-tenant");
        frameworkUtilsStatic.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));

        AuthenticatorFlowStatus status = organizationIdentifierHandler.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessWithFrameworkException() throws Exception {

        setupRequestParamMap(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID, ORG_ID);
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenThrow(new FrameworkException("Discovery error"));

        organizationIdentifierHandler.process(request, response, context);
    }

    @Test
    public void testProcessAuthenticationResponseSuccess() throws Exception {

        setupRequestParamMap(FrameworkConstants.OrgDiscoveryInputParameters.ORG_NAME, ORG_NAME);
        Organization discoveredOrg = new Organization();
        discoveredOrg.setId(ORG_ID);
        discoveredOrg.setName(ORG_NAME);
        discoveredOrg.setOrganizationHandle(ORG_HANDLE);
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenReturn(organizationDiscoveryResult);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(true);
        when(organizationDiscoveryResult.getDiscoveredOrganization()).thenReturn(discoveredOrg);
        when(organizationDiscoveryResult.getSharedApplicationId()).thenReturn(SHARED_APP_ID);

        AuthenticatorFlowStatus status = organizationIdentifierHandler.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        verify(context).setOrganizationLoginData(any());
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseFailure() throws Exception {

        when(request.getParameterMap()).thenReturn(new HashMap<>());
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenReturn(organizationDiscoveryResult);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(false);

        organizationIdentifierHandler.processAuthenticationResponse(request, response, context);
    }

    @DataProvider(name = "redirectUrlDataProvider")
    public Object[][] redirectUrlDataProvider() {

        return new Object[][]{
                // prompt=orgName → org_name.do
                {"orgName", null, null, false, "orgHandle", "org_name.do"},
                // prompt=orgHandle → org_handle.do
                {"orgHandle", null, null, false, "orgHandle", "org_handle.do"},
                // prompt=orgDiscovery + discovery enabled → org_discovery.do
                {"orgDiscovery", null, null, true, "orgHandle", "org_discovery.do"},
                // prompt=orgDiscovery + discovery disabled → falls through to default (org_handle.do)
                {"orgDiscovery", null, null, false, "orgHandle", "org_handle.do"},
                // retry: org param present → org_name.do
                {null, "org", null, false, "orgHandle", "org_name.do"},
                // retry: orgHandle param present → org_handle.do
                {null, null, "orgHandle", false, "orgHandle", "org_handle.do"},
                // initial: discovery enabled → org_discovery.do
                {null, null, null, true, "orgHandle", "org_discovery.do"},
                // initial: discovery disabled, default=orgHandle → org_handle.do
                {null, null, null, false, "orgHandle", "org_handle.do"},
                // initial: discovery disabled, default=orgName → org_name.do
                {null, null, null, false, "orgName", "org_name.do"},
        };
    }

    @Test(dataProvider = "redirectUrlDataProvider")
    public void testInitiateAuthenticationRequestRedirect(String prompt, String orgParam, String orgHandleParam,
                                                          boolean discoveryEnabled, String defaultParam,
                                                          String expectedUrlPath)
            throws Exception {

        when(request.getParameter("prompt")).thenReturn(prompt);
        when(request.getParameter("org")).thenReturn(orgParam);
        when(request.getParameter("orgHandle")).thenReturn(orgHandleParam);
        when(request.getParameter("orgDiscovery")).thenReturn(null);
        setupRedirectStubs(defaultParam);
        if (discoveryEnabled) {
            setupDiscoveryEnabled();
        } else {
            setupDiscoveryDisabled();
        }
        when(context.getTenantDomain()).thenReturn("test-tenant");

        frameworkUtilsStatic.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));

        organizationIdentifierHandler.initiateAuthenticationRequest(request, response, context);

        verify(response).sendRedirect(anyString());
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testInitiateAuthenticationRequestIOException() throws Exception {

        setupRedirectStubs("orgHandle");
        setupDiscoveryDisabled();
        when(context.getTenantDomain()).thenReturn("test-tenant");
        frameworkUtilsStatic.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));
        Mockito.doThrow(new IOException("redirect failed")).when(response).sendRedirect(anyString());

        organizationIdentifierHandler.initiateAuthenticationRequest(request, response, context);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testInitiateAuthenticationRequestConfigException() throws Exception {

        organizationConfigManagerUtilStatic.when(OrganizationConfigManagerUtil::resolveDefaultDiscoveryParam)
                .thenThrow(new OrganizationConfigException("config error"));

        organizationIdentifierHandler.initiateAuthenticationRequest(request, response, context);
    }

    @Test
    public void testDiscoveryConfigNotExist() throws Exception {

        when(request.getParameterMap()).thenReturn(new HashMap<>());
        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID, ORG_ID);
        doReturn(runtimeParams).when(organizationIdentifierHandler).getRuntimeParams(context);
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenReturn(organizationDiscoveryResult);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(false);

        OrganizationConfigException configException = new OrganizationConfigException(
                ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST.getCode(),
                ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST.getMessage());
        when(organizationConfigManager.getDiscoveryConfiguration()).thenThrow(configException);
        setupRedirectStubs("orgHandle");
        when(context.getTenantDomain()).thenReturn("test-tenant");
        frameworkUtilsStatic.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));

        AuthenticatorFlowStatus status = organizationIdentifierHandler.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testDiscoveryConfigError() throws Exception {

        when(request.getParameterMap()).thenReturn(new HashMap<>());
        Map<String, String> runtimeParams = new HashMap<>();
        runtimeParams.put(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID, ORG_ID);
        doReturn(runtimeParams).when(organizationIdentifierHandler).getRuntimeParams(context);
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenReturn(organizationDiscoveryResult);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(false);

        OrganizationConfigException configException = new OrganizationConfigException("some other error", "ORG-60000");
        when(organizationConfigManager.getDiscoveryConfiguration()).thenThrow(configException);
        setupRedirectStubs("orgHandle");
        when(context.getTenantDomain()).thenReturn("test-tenant");

        organizationIdentifierHandler.process(request, response, context);
    }

    @Test
    public void testGetAuthInitiationData() {

        Optional<AuthenticatorData> result = organizationIdentifierHandler.getAuthInitiationData(context);

        Assert.assertTrue(result.isPresent());
        AuthenticatorData data = result.get();
        Assert.assertEquals(data.getName(), "OrganizationIdentifierHandler");
        Assert.assertEquals(data.getI18nKey(), "authenticator.organization.identifier");
        Assert.assertEquals(data.getDisplayName(), "Organization SSO");
        Assert.assertEquals(data.getPromptType(), FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        Assert.assertEquals(data.getRequiredParams().size(), 5);
        Assert.assertEquals(data.getAuthParams().size(), 5);
    }

    @Test
    public void testGetAuthInitiationDataWithMessage() {

        AuthenticatorMessage message = mock(AuthenticatorMessage.class);
        when(context.getProperty(AUTHENTICATOR_MESSAGE)).thenReturn(message);

        Optional<AuthenticatorData> result = organizationIdentifierHandler.getAuthInitiationData(context);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.get().getMessage(), message);
    }

    @Test
    public void testGetAuthInitiationDataWithExternalIdP() {

        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("testIdP");

        Optional<AuthenticatorData> result = organizationIdentifierHandler.getAuthInitiationData(context);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.get().getIdp(), "testIdP");
    }

    private void setupRequestParamMap(String key, String value) {

        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put(key, new String[]{value});
        when(request.getParameterMap()).thenReturn(paramMap);
        when(request.getParameter(key)).thenReturn(value);
    }

    private void setupSuccessfulDiscovery() throws FrameworkException {

        Organization discoveredOrg = new Organization();
        discoveredOrg.setId(ORG_ID);
        discoveredOrg.setName(ORG_NAME);
        discoveredOrg.setOrganizationHandle(ORG_HANDLE);
        when(organizationDiscoveryHandler.discoverOrganization(any(OrganizationDiscoveryInput.class), any()))
                .thenReturn(organizationDiscoveryResult);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(true);
        when(organizationDiscoveryResult.getDiscoveredOrganization()).thenReturn(discoveredOrg);
        when(organizationDiscoveryResult.getSharedApplicationId()).thenReturn(SHARED_APP_ID);
    }

    private void setupRedirectStubs(String defaultParam) throws Exception {

        organizationConfigManagerUtilStatic.when(OrganizationConfigManagerUtil::resolveDefaultDiscoveryParam)
                .thenReturn(defaultParam);

        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);
        ServiceURL mockServiceURL = mock(ServiceURL.class);
        serviceURLBuilderStatic.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(anyString())).thenAnswer(invocation -> {
            String path = invocation.getArgument(0);
            when(mockServiceURL.getAbsolutePublicURL()).thenReturn(BASE_URL + "/" + path);
            return mockBuilder;
        });
        when(mockBuilder.build()).thenReturn(mockServiceURL);
    }

    private void setupDiscoveryEnabled() throws OrganizationConfigException {

        DiscoveryConfig discoveryConfig = mock(DiscoveryConfig.class);
        when(organizationConfigManager.getDiscoveryConfiguration()).thenReturn(discoveryConfig);
        List<ConfigProperty> configProperties = new ArrayList<>();
        configProperties.add(new ConfigProperty(EMAIL_DOMAIN_TYPE + ENABLE_CONFIG, String.valueOf(true)));
        when(discoveryConfig.getConfigProperties()).thenReturn(configProperties);

        Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers = new HashMap<>();
        discoveryHandlers.put(EMAIL_DOMAIN_TYPE, mock(AttributeBasedOrganizationDiscoveryHandler.class));
        when(organizationDiscoveryManager.getAttributeBasedOrganizationDiscoveryHandlers())
                .thenReturn(discoveryHandlers);
    }

    private void setupDiscoveryDisabled() throws OrganizationConfigException {

        DiscoveryConfig discoveryConfig = mock(DiscoveryConfig.class);
        when(organizationConfigManager.getDiscoveryConfiguration()).thenReturn(discoveryConfig);
        when(discoveryConfig.getConfigProperties()).thenReturn(Collections.emptyList());
    }
}
