/*
 * Copyright (c) 2022-2024, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.organization.login.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.Claim;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.config.service.model.ConfigProperty;
import org.wso2.carbon.identity.organization.config.service.model.DiscoveryConfig;
import org.wso2.carbon.identity.organization.discovery.service.AttributeBasedOrganizationDiscoveryHandler;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.identity.organization.management.service.model.BasicOrganization;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ENABLE_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.INBOUND_AUTH_TYPE_OAUTH;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.LOGIN_HINT_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.OIDC_CLAIM_DIALECT_URL;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DISCOVERY_TYPE_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_ID_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_PARAMETER;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_APPLICATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_RETRIEVING_ORGANIZATIONS_BY_NAME;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.handleClientException;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Unit test class for {@link OrganizationAuthenticator} class.
 */

@WithAxisConfiguration
public class OrganizationAuthenticatorTest {

    private static final String contextIdentifier = "4952b467-86b2-31df-b63c-0bf25cec4f86s";
    private static final String orgId = "ef35863f-58f0-4a18-aef1-a8d9dd20cfbe";
    private static final String org = "greater";
    private static final String saasApp = "medlife";
    private static final String saasAppResourceId = "4f412c8a-ace8-4189-bbfb-c7c0d93b8662";
    private static final String saasAppOwnedTenant = "carbon.super";
    private static final String saasAppOwnedOrgId = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String clientId = "3_TCRZ93rTQtPL8k02_trEYTfVca";
    private static final String secretKey = "uW4q6dYgSaHJIv11Llqi1nvOQBUa";

    private static final String emailDomainDiscoveryType = "emailDomain";
    private static final String invalidDiscoveryType = "invalidDiscoveryType";
    private static final String userEmailWithValidDomain = "john@wso2.com";
    private static final String userEmailWithInvalidDomain = "john@incorrect.wso2.com";

    private static Map<String, String> authenticatorParamProperties;
    private static Map<String, String> authenticatorProperties;
    private static Map<String, Object> mockContextParam;

    private HttpServletRequest mockServletRequest;
    private HttpServletResponse mockServletResponse;
    private AuthenticationContext mockAuthenticationContext;
    private RealmService mockRealmService;
    private OrganizationManager mockOrganizationManager;
    private ApplicationManagementService mockApplicationManagementService;
    private OrgApplicationManager mockOrgApplicationManager;
    private ServiceProvider mockServiceProvider;
    private InboundAuthenticationConfig mockInboundAuthenticationConfig;
    private OAuthAdminServiceImpl mockOAuthAdminServiceImpl;
    private OAuthConsumerAppDTO mockOAuthConsumerAppDTO;
    private ExternalIdPConfig mockExternalIdPConfig;
    private Organization mockOrganization;
    private BasicOrganization mockBasicOrganization;
    private OrganizationAuthenticator organizationAuthenticator;
    private AuthenticatorDataHolder authenticatorDataHolder;
    private ClaimMetadataManagementService mockClaimMetadataManagementService;
    private ClaimConfig mockClaimConfig;
    private OrganizationConfigManager mockOrganizationConfigManager;
    private DiscoveryConfig mockDiscoveryConfig;
    private MockedStatic<IdentityTenantUtil> mockedUtilities;

    @Mock
    private OrganizationDiscoveryManager mockOrganizationDiscoveryManager;

    @BeforeClass
    public void setUp() {

        mockCarbonContext();
        mockIdentityTenantUtils();
    }

    @BeforeMethod
    public void init() throws UserStoreException {

        initMocks(this);
        mockServletRequest = mock(HttpServletRequest.class);
        mockServletResponse = mock(HttpServletResponse.class);
        mockAuthenticationContext = mock(AuthenticationContext.class);
        mockRealmService = mock(RealmService.class);
        mockOrganizationManager = mock(OrganizationManager.class);
        mockOrgApplicationManager = mock(OrgApplicationManager.class);
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        mockServiceProvider = mock(ServiceProvider.class);
        mockInboundAuthenticationConfig = mock(InboundAuthenticationConfig.class);
        mockOAuthAdminServiceImpl = mock(OAuthAdminServiceImpl.class);
        mockOAuthConsumerAppDTO = mock(OAuthConsumerAppDTO.class);
        mockExternalIdPConfig = mock(ExternalIdPConfig.class);
        mockOrganization = mock(Organization.class);
        mockBasicOrganization = mock(BasicOrganization.class);
        mockClaimMetadataManagementService = mock(ClaimMetadataManagementService.class);
        mockClaimConfig = mock(ClaimConfig.class);
        mockOrganizationConfigManager = mock(OrganizationConfigManager.class);
        mockDiscoveryConfig = mock(DiscoveryConfig.class);
        organizationAuthenticator = new OrganizationAuthenticator();
        authenticatorParamProperties = new HashMap<>();
        authenticatorProperties = new HashMap<>();
        mockContextParam = new HashMap<>();

        authenticatorDataHolder = AuthenticatorDataHolder.getInstance();
        authenticatorDataHolder.setRealmService(mockRealmService);
        authenticatorDataHolder.setOrganizationManager(mockOrganizationManager);
        authenticatorDataHolder.setOrgApplicationManager(mockOrgApplicationManager);
        authenticatorDataHolder.setOAuthAdminService(mockOAuthAdminServiceImpl);
        authenticatorDataHolder.setApplicationManagementService(mockApplicationManagementService);
        authenticatorDataHolder.setClaimMetadataManagementService(mockClaimMetadataManagementService);
        authenticatorDataHolder.setOrganizationConfigManager(mockOrganizationConfigManager);
        authenticatorDataHolder.setOrganizationDiscoveryManager(mockOrganizationDiscoveryManager);
        Tenant tenant = mock(Tenant.class);
        TenantManager mockTenantManager = mock(TenantManager.class);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
        when(mockRealmService.getTenantManager().getTenant(anyInt())).thenReturn(tenant);
        when(tenant.getAssociatedOrganizationUUID()).thenReturn(orgId);
        when(mockAuthenticationContext.getProperties()).thenReturn(mockContextParam);
    }

    private void mockCarbonContext() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(CarbonBaseConstants.CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome,
                "repository/conf").toString());

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("admin");
    }

    private void mockIdentityTenantUtils() {

        mockedUtilities = Mockito.mockStatic(IdentityTenantUtil.class, Mockito.withSettings()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS));
        mockedUtilities.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
    }

    @Test
    public void testGetFriendlyName() {

        Assert.assertEquals(organizationAuthenticator.getFriendlyName(), AUTHENTICATOR_FRIENDLY_NAME,
                "Invalid friendly name.");
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(organizationAuthenticator.getName(), AUTHENTICATOR_NAME,
                "Invalid authenticator name.");
    }

    @Test
    public void testProcessLogoutRequest() throws Exception {

        when(mockAuthenticationContext.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithoutOrgParameter() throws Exception {

        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockAuthenticationContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);

        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessInvalidOrgParam() throws Exception {

        setupMockParam(ORG_PARAMETER, org);
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationsByName(anyString()))
                .thenThrow(handleClientException(ERROR_CODE_RETRIEVING_ORGANIZATIONS_BY_NAME));

        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockAuthenticationContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);

        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessInvalidOrgIdParam() throws Exception {

        setupMockParam(ORG_ID_PARAMETER, orgId);
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationNameById(anyString()))
                .thenThrow(handleClientException(ERROR_CODE_INVALID_ORGANIZATION_ID));
        organizationAuthenticator.process(mockServletRequest, mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testProcessOrgParamForOrgsWithSameName() throws Exception {

        setupMockParam(ORG_PARAMETER, org);
        when(mockOrganization.getId()).thenReturn(orgId);
        when(mockOrganization.getName()).thenReturn(org);
        when(mockBasicOrganization.getId()).thenReturn(orgId);
        when(mockOrganization.getDescription()).thenReturn("description");
        when(mockOrganizationManager.getOrganizationsByName(anyString()))
                .thenReturn(Arrays.asList(mockOrganization, mockOrganization));
        when(mockOrganizationManager.resolveOrganizationId(anyString())).thenReturn(saasAppOwnedOrgId);
        when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                .thenReturn(mockServiceProvider);
        when(mockOrgApplicationManager.getApplicationSharedOrganizations(anyString(), anyString())).
                thenReturn(Arrays.asList(mockBasicOrganization, mockBasicOrganization));

        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);
        when(mockAuthenticationContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);

        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessWithValidOrgIdParamSet() throws Exception {

        setupMockParam(ORG_ID_PARAMETER, orgId);
        setupInboundAuthenticationRequestConfigs();
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationNameById(anyString()))
                .thenReturn(org);

        authenticatorParamProperties.put(ORG_PARAMETER, "");
        when(organizationAuthenticator.getRuntimeParams(mockAuthenticationContext))
                .thenReturn(authenticatorParamProperties);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        setMockContextParamForValidOrganization();
        when(authenticatorDataHolder.getOrgApplicationManager()
                .resolveSharedApplication(anyString(), anyString(), anyString())).thenReturn(mockServiceProvider);
        when(mockServiceProvider.getClaimConfig()).thenReturn(mockClaimConfig);
        when(authenticatorDataHolder.getOrganizationManager().resolveTenantDomain(anyString()))
                .thenReturn(orgId);
        when(authenticatorDataHolder.getOAuthAdminService().getOAuthApplicationData(anyString(), anyString()))
                .thenReturn(mockOAuthConsumerAppDTO);
        when(mockOAuthConsumerAppDTO.getOauthConsumerSecret()).thenReturn(secretKey);

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        List<Claim> claims = new ArrayList<>();
        claims.add(new Claim(OIDC_CLAIM_DIALECT_URL, "custom", null));
        when(authenticatorDataHolder.getClaimMetadataManagementService().getMappedExternalClaimsForLocalClaim(
                anyString(), anyString())).thenReturn(claims);
        when(mockAuthenticationContext.getQueryParams()).thenReturn("scope=openid profile email groups");

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);

        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @DataProvider(name = "testProcessWithSharedAppPublicClientStatusData")
    public Object[][] testProcessWithSharedAppPublicClientStatusData() {

        return new Object[][]{
                {true, "true"},
                {false, null}
        };
    }

    @Test(dataProvider = "testProcessWithSharedAppPublicClientStatusData")
    public void testProcessWithSharedAppPublicClientStatus(boolean isPublicClient,
                                                           String expectedBasicAuthEnabledStatus) throws Exception {

        setupMockParam(ORG_ID_PARAMETER, orgId);
        setupInboundAuthenticationRequestConfigs();
        setMockContextParamForValidOrganization();

        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);

        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrgApplicationManager()
                .resolveSharedApplication(anyString(), anyString(), anyString())).thenReturn(mockServiceProvider);
        when(authenticatorDataHolder.getOrganizationManager().resolveTenantDomain(anyString()))
                .thenReturn(orgId);
        when(authenticatorDataHolder.getOAuthAdminService().getOAuthApplicationData(anyString(), anyString()))
                .thenReturn(mockOAuthConsumerAppDTO);

        when(mockServiceProvider.getClaimConfig()).thenReturn(mockClaimConfig);
        when(mockOAuthConsumerAppDTO.isBypassClientCredentials()).thenReturn(isPublicClient);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);

        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertEquals(authenticatorProperties.get(IS_BASIC_AUTH_ENABLED), expectedBasicAuthEnabledStatus);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithoutOrgParameter() throws AuthenticationFailedException {

        organizationAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestNoSharedApp() throws Exception {

        setMockContextParamForValidOrganization();
        authenticatorParamProperties.put(ORG_PARAMETER, orgId);
        authenticatorParamProperties.put(ORG_ID_PARAMETER, orgId);
        when(organizationAuthenticator.getRuntimeParams(mockAuthenticationContext))
                .thenReturn(authenticatorParamProperties);

        when(mockOrganizationManager
                .getOrganizationIdByName(anyString())).thenReturn(orgId);
        when(mockOrganizationManager
                .getOrganization(anyString(), anyBoolean(), anyBoolean())).thenReturn(mockOrganization);

        when(mockOrganizationManager.resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);
        when(mockOrgApplicationManager.resolveSharedApplication(anyString(),
                anyString(), anyString())).thenThrow(
                new OrganizationManagementServerException(ERROR_CODE_APPLICATION_NOT_SHARED.getCode(),
                        ERROR_CODE_APPLICATION_NOT_SHARED.getMessage()));
        organizationAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestInvalidSharedAppInbound() throws Exception {

        setMockContextParamForValidOrganization();
        authenticatorParamProperties.put(ORG_PARAMETER, orgId);
        authenticatorParamProperties.put(ORG_ID_PARAMETER, orgId);
        when(organizationAuthenticator.getRuntimeParams(mockAuthenticationContext))
                .thenReturn(authenticatorParamProperties);

        when(authenticatorDataHolder.getOrganizationManager()
                .getOrganizationIdByName(anyString())).thenReturn(orgId);
        when(authenticatorDataHolder.getOrganizationManager()
                .getOrganization(anyString(), anyBoolean(), anyBoolean())).thenReturn(mockOrganization);
        when(authenticatorDataHolder.getOrgApplicationManager().resolveSharedApplication(anyString(),
                anyString(), anyString())).thenReturn(mockServiceProvider);

        when(authenticatorDataHolder.getOrgApplicationManager().resolveSharedApplication(anyString(),
                anyString(), anyString())).thenThrow(
                new OrganizationManagementServerException(ERROR_CODE_INVALID_APPLICATION.getCode(),
                        ERROR_CODE_INVALID_APPLICATION.getMessage()));
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);

        organizationAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestInvalidSharedApp() throws Exception {

        setMockContextParamForValidOrganization();
        authenticatorParamProperties.put(ORG_PARAMETER, orgId);
        authenticatorParamProperties.put(ORG_ID_PARAMETER, orgId);
        when(organizationAuthenticator.getRuntimeParams(mockAuthenticationContext))
                .thenReturn(authenticatorParamProperties);

        when(authenticatorDataHolder.getOrganizationManager()
                .getOrganizationIdByName(anyString())).thenReturn(orgId);
        when(authenticatorDataHolder.getOrganizationManager()
                .getOrganization(anyString(), anyBoolean(), anyBoolean())).thenReturn(mockOrganization);
        when(authenticatorDataHolder.getOrganizationManager().resolveTenantDomain(anyString())).thenReturn(
                orgId);

        when(authenticatorDataHolder.getOrgApplicationManager().resolveSharedApplication(anyString(),
                anyString(), anyString())).thenReturn(mockServiceProvider);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(mockServiceProvider.getInboundAuthenticationConfig()).thenReturn(mockInboundAuthenticationConfig);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);

        organizationAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }

    @DataProvider(name = "invalidOrgDiscoveryParams")
    public Object[][] getInvalidOrgDiscoveryParams() {

        return new Object[][]{
                // When the given discovery type is not valid.
                {userEmailWithValidDomain, invalidDiscoveryType, true},
                // When the given discovery type is valid but not enabled.
                {userEmailWithValidDomain, emailDomainDiscoveryType, false},
                // When the given email domain of the user email is invalid.
                {userEmailWithInvalidDomain, emailDomainDiscoveryType, true}
        };
    }

    @Test(dataProvider = "invalidOrgDiscoveryParams")
    public void testProcessWithInvalidOrgDiscoveryParam(String userEmail, String discoveryType,
                                                        boolean isEmailDomainDiscoveryEnabled) throws Exception {

        setupMockParam(LOGIN_HINT_PARAMETER, userEmail);
        setupMockParam(ORG_DISCOVERY_TYPE_PARAMETER, discoveryType);

        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);
        List<ConfigProperty> configProperties = new ArrayList<>();
        configProperties.add(new ConfigProperty(emailDomainDiscoveryType + ENABLE_CONFIG,
                String.valueOf(isEmailDomainDiscoveryEnabled)));
        when(mockDiscoveryConfig.getConfigProperties()).thenReturn(configProperties);

        Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers = new HashMap<>();
        AttributeBasedOrganizationDiscoveryHandler discoveryHandler =
                mock(AttributeBasedOrganizationDiscoveryHandler.class);
        discoveryHandlers.put(emailDomainDiscoveryType, discoveryHandler);
        when(authenticatorDataHolder.getOrganizationDiscoveryManager().getAttributeBasedOrganizationDiscoveryHandlers())
                .thenReturn(discoveryHandlers);

        when(mockAuthenticationContext.getLoginTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(saasAppOwnedTenant)).thenReturn(
                saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrganizationDiscoveryManager()
                .getOrganizationIdByDiscoveryAttribute(discoveryType, userEmail, saasAppOwnedOrgId)).thenReturn(null);

        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockAuthenticationContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    private void setMockContextParamForValidOrganization() {

        mockContextParam.put(ORG_PARAMETER, org);
        when(mockAuthenticationContext.getProperty(ORG_PARAMETER)).thenReturn(org);
        mockContextParam.put(ORG_ID_PARAMETER, orgId);
        when(mockAuthenticationContext.getProperty(ORG_ID_PARAMETER)).thenReturn(orgId);
    }

    private void setupMockParam(String paramKey, String paramValue) {

        Map<String, String[]> mockParamMap = new HashMap<>();
        mockParamMap.put(paramKey, new String[]{paramValue});
        when(mockServletRequest.getParameterMap()).thenReturn(mockParamMap);
        when(mockServletRequest.getParameter(paramKey)).thenReturn(paramValue);
    }

    private void setupInboundAuthenticationRequestConfigs() {

        InboundAuthenticationRequestConfig inbound = new InboundAuthenticationRequestConfig();
        inbound.setInboundAuthType(INBOUND_AUTH_TYPE_OAUTH);
        inbound.setInboundAuthKey(clientId);
        InboundAuthenticationRequestConfig[] inbounds = {inbound};
        when(mockInboundAuthenticationConfig.getInboundAuthenticationRequestConfigs()).thenReturn(inbounds);
        when(mockServiceProvider.getInboundAuthenticationConfig()).thenReturn(mockInboundAuthenticationConfig);
    }
}
