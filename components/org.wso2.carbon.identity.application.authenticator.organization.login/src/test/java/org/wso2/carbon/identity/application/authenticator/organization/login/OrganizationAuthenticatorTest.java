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

import org.apache.commons.lang.StringUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
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
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.Claim;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.config.service.model.ConfigProperty;
import org.wso2.carbon.identity.organization.config.service.model.DiscoveryConfig;
import org.wso2.carbon.identity.organization.config.service.util.OrganizationConfigManagerUtil;
import org.wso2.carbon.identity.organization.discovery.service.AttributeBasedOrganizationDiscoveryHandler;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.identity.organization.management.service.model.BasicOrganization;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.PrintWriter;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_DISCOVERY_TYPE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORGANIZATION_HANDLE;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DISCOVERY_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_DISCOVERY_TYPE_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_ID_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.ORG_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.SAML_RESP;
import static org.wso2.carbon.identity.application.authenticator.organization.login.constant.AuthenticatorConstants.SELF_REGISTRATION_PARAMETER;
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

    private static final String samlResponse =
            "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6" +
                    "cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRp" +
                    "b24iIElEPSJfYWJjMTIzIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyNC0xMC0yNFQx" +
                    "MjozNDo1NloiIERlc3RpbmF0aW9uPSJodHRwczovL3NlcnZpY2Vwcm92aWRlci5jb20vU0FNTDIv" +
                    "U1NPL1BPU1QiIEluUmVzcG9uc2VUbz0iX3JlcXVlc3QxMjMiPgoJPHNhbWw6SXNzdWVyPmh0dHBz" +
                    "Oi8vaWRlbnRpdHlwcm92aWRlci5jb20vPC9zYW1sOklzc3Vlcj4KCQk8c2FtbHA6U3RhdHVzPgoJ" +
                    "CQk8c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0" +
                    "YXR1czpTdWNjZXNzIi8+CgkJPC9zYW1scDpTdGF0dXM+CgkJPHNhbWw6QXNzZXJ0aW9uIFZlcnNp" +
                    "b249IjIuMCIgSUQ9Il9hc3NlcnRpb24xMjMiIElzc3VlSW5zdGFudD0iMjAyNC0xMC0yNFQxMjoz" +
                    "NDo1NloiPgoJCQk8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9pZGVudGl0eXByb3ZpZGVyLmNvbS88L3Nh" +
                    "bWw6SXNzdWVyPgoJCQk8c2FtbDpTdWJqZWN0PgoJCQkJPHNhbWw6TmFtZUlEIEZvcm1hdD0idXJu" +
                    "Om9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj51c2Vy" +
                    "QGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD4KCQkJCTxzYW1sOlN1YmplY3RDb25maXJtYXRpb24g" +
                    "TWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj4KCQkJCQk8c2Ft" +
                    "bDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Il9yZXF1ZXN0MTIzIiBOb3RP" +
                    "bk9yQWZ0ZXI9IjIwMjQtMTAtMjRUMTI6NDQ6NTZaIiBSZWNpcGllbnQ9Imh0dHBzOi8vc2Vydmlj" +
                    "ZXByb3ZpZGVyLmNvbS9TQU1MMi9TU08vUE9TVCIvPgoJCQk8L3NhbWw6U3ViamVjdENvbmZpcm1h" +
                    "dGlvbj4KCQk8L3NhbWw6U3ViamVjdD4KCQk8c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAy" +
                    "NC0xMC0yNFQxMjozNDo1NloiIE5vdE9uT3JBZnRlcj0iMjAyNC0xMC0yNFQxMjo0NDo1NloiPgoJ" +
                    "CQk8c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPgoJCQkJPHNhbWw6QXVkaWVuY2U+aHR0cHM6Ly9z" +
                    "ZXJ2aWNlcHJvdmlkZXIuY29tLzwvc2FtbDpBdWRpZW5jZT4KCQkJPC9zYW1sOkF1ZGllbmNlUmVz" +
                    "dHJpY3Rpb24+CgkJPC9zYW1sOkNvbmRpdGlvbnM+CgkJPHNhbWw6QXR0cmlidXRlU3RhdGVtZW50" +
                    "PgoJCQk8c2FtbDpBdHRyaWJ1dGUgTmFtZT0iRmlyc3ROYW1lIj4KCQkJCTxzYW1sOkF0dHJpYnV0" +
                    "ZVZhbHVlPkpvaG48L3NhbWw6QXR0cmlid";

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
    private MockedStatic<OrganizationConfigManagerUtil> mockedOrganizationConfigManagerUtil;
    private MockedStatic<LoggerUtils> mockedLoggerUtils;

    @Mock
    private OrganizationDiscoveryManager mockOrganizationDiscoveryManager;

    @BeforeClass
    public void setUp() {

        mockCarbonContext();
        mockIdentityTenantUtils();
        mockLoggerUtils();
        mockOrganizationConfigManagerUtil();
    }

    @AfterClass
    public void cleanup() {

        mockedUtilities.close();
        mockedOrganizationConfigManagerUtil.close();
        mockedLoggerUtils.close();
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

    private void mockOrganizationConfigManagerUtil() {

        mockedOrganizationConfigManagerUtil = Mockito.mockStatic(OrganizationConfigManagerUtil.class,
                Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));
        mockedOrganizationConfigManagerUtil.when(
                OrganizationConfigManagerUtil::resolveDefaultDiscoveryParam).thenReturn(ORGANIZATION_HANDLE);
    }

    private void mockLoggerUtils() {

        mockedLoggerUtils = Mockito.mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
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

    @Test
    public void testProcessInvalidOrgIdParam() throws Exception {

        setupMockParam(ORG_ID_PARAMETER, orgId);
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationNameById(anyString()))
                .thenThrow(handleClientException(ERROR_CODE_INVALID_ORGANIZATION_ID));
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockAuthenticationContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);
        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);
        AuthenticatorFlowStatus status =
                organizationAuthenticator.process(mockServletRequest, mockServletResponse, mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
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

        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);
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
    public void testProcessWithValidOrgIdParamSet() throws Exception {

        setupMockParam(ORG_ID_PARAMETER, orgId);
        setupInboundAuthenticationRequestConfigs();
        mockOrganizationManager();

        authenticatorParamProperties.put(ORG_PARAMETER, "");
        when(organizationAuthenticator.getRuntimeParams(mockAuthenticationContext))
                .thenReturn(authenticatorParamProperties);

        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);
        setMockContextParamForValidOrganization();
        mockOrgApplicationManager();

        when(mockServiceProvider.getInboundAuthenticationConfig()).thenReturn(mockInboundAuthenticationConfig);
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

    @Test
    public void testProcessWithSelfRegParam() throws Exception {

        when(mockServletRequest.getParameter(SELF_REGISTRATION_PARAMETER)).thenReturn("true");
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);
        when(mockAuthenticationContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);
        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);
        when(mockAuthenticationContext.getProperty(SELF_REGISTRATION_PARAMETER)).thenReturn("true");
        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessWithSelfRegContext() throws Exception {

        setMockContextParamForValidOrganization();
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(saasApp);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrganizationManager().resolveTenantDomain(anyString())).thenReturn(
                orgId);
        when(authenticatorDataHolder.getOrgApplicationManager()
                .resolveSharedApplication(anyString(), anyString(), anyString())).thenReturn(mockServiceProvider);

        List<Claim> claims = new ArrayList<>();
        claims.add(new Claim(OIDC_CLAIM_DIALECT_URL, "custom", null));
        when(authenticatorDataHolder.getClaimMetadataManagementService().getMappedExternalClaimsForLocalClaim(
                anyString(), anyString())).thenReturn(claims);
        when(mockServiceProvider.getInboundAuthenticationConfig()).thenReturn(mockInboundAuthenticationConfig);
        when(mockServiceProvider.getClaimConfig()).thenReturn(mockClaimConfig);

        InboundAuthenticationRequestConfig inbound = new InboundAuthenticationRequestConfig();
        inbound.setInboundAuthType(INBOUND_AUTH_TYPE_OAUTH);
        inbound.setInboundAuthKey(clientId);
        InboundAuthenticationRequestConfig[] inbounds = {inbound};
        when(mockInboundAuthenticationConfig.getInboundAuthenticationRequestConfigs()).thenReturn(inbounds);

        when(authenticatorDataHolder.getOAuthAdminService().getOAuthApplicationData(anyString(), anyString()))
                .thenReturn(mockOAuthConsumerAppDTO);
        when(mockOAuthConsumerAppDTO.getOauthConsumerSecret()).thenReturn(secretKey);

        when(mockAuthenticationContext.getProperty(SELF_REGISTRATION_PARAMETER)).thenReturn("true");
        when(mockAuthenticationContext.getProperty(ORG_DISCOVERY_PARAMETER)).thenReturn(userEmailWithValidDomain);
        when(mockAuthenticationContext.getProperty(ORGANIZATION_DISCOVERY_TYPE)).thenReturn(emailDomainDiscoveryType);
        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @DataProvider(name = "testGetValidAuthenticatorParamsData")
    public Object[][] testGetValidAuthenticatorParamsData() {

        return new Object[][]{
                {ORG_ID_PARAMETER, orgId},
                {ORG_PARAMETER, org},
                {LOGIN_HINT_PARAMETER, userEmailWithValidDomain}
        };
    }

    @Test(dataProvider = "testGetValidAuthenticatorParamsData")
    public void testProcessWithValidAuthenticatorParam(String paramKey, String paramValue) throws Exception {

        AuthenticationContext spyContext = Mockito.spy(new AuthenticationContext());
        authenticatorParamProperties.put(paramKey, paramValue);
        when(organizationAuthenticator.getRuntimeParams(spyContext)).thenReturn(authenticatorParamProperties);

        setupInboundAuthenticationRequestConfigs();
        when(mockServiceProvider.getApplicationResourceId()).thenReturn(saasAppResourceId);
        when(mockServiceProvider.getClaimConfig()).thenReturn(mockClaimConfig);
        when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                .thenReturn(mockServiceProvider);

        when(mockOrganization.getId()).thenReturn(orgId);
        when(mockOrganization.getName()).thenReturn(org);
        when(mockBasicOrganization.getId()).thenReturn(orgId);
        when(mockOrganizationManager.getOrganizationsByName(anyString()))
                .thenReturn(Collections.singletonList(mockOrganization));

        when(spyContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(spyContext.getServiceProviderName()).thenReturn(saasApp);
        when(spyContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        doReturn(saasAppOwnedTenant).when(spyContext).getLoginTenantDomain();

        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);
        List<ConfigProperty> configProperties = new ArrayList<>();
        configProperties.add(new ConfigProperty(emailDomainDiscoveryType + ENABLE_CONFIG,
                String.valueOf(true)));
        when(mockDiscoveryConfig.getConfigProperties()).thenReturn(configProperties);

        Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers = new HashMap<>();
        AttributeBasedOrganizationDiscoveryHandler discoveryHandler =
                mock(AttributeBasedOrganizationDiscoveryHandler.class);
        discoveryHandlers.put(emailDomainDiscoveryType, discoveryHandler);
        when(authenticatorDataHolder.getOrganizationDiscoveryManager().getAttributeBasedOrganizationDiscoveryHandlers())
                .thenReturn(discoveryHandlers);

        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(saasAppOwnedTenant)).thenReturn(
                saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationNameById(anyString()))
                .thenReturn(org);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrganizationManager().resolveTenantDomain(anyString()))
                .thenReturn(orgId);

        when(authenticatorDataHolder.getOrganizationDiscoveryManager()
                .getOrganizationIdByDiscoveryAttribute(emailDomainDiscoveryType, userEmailWithValidDomain,
                        saasAppOwnedOrgId, spyContext)).thenReturn(orgId);

        when(mockOrgApplicationManager.getApplicationSharedOrganizations(anyString(), anyString())).
                thenReturn(Collections.singletonList(mockBasicOrganization));
        when(authenticatorDataHolder.getOrgApplicationManager()
                .resolveSharedApplication(anyString(), anyString(), anyString())).thenReturn(mockServiceProvider);

        when(authenticatorDataHolder.getOAuthAdminService().getOAuthApplicationData(anyString(), anyString()))
                .thenReturn(mockOAuthConsumerAppDTO);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                spyContext);

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        // Capture the redirect URL and verify the redirection to /authorize request.
        verify(mockServletResponse, times(1)).sendRedirect(urlCaptor.capture());
        String url = urlCaptor.getValue();
        Assert.assertTrue(url.contains("/oauth2/authorize"));
        // Verify the authentication flow status.
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @DataProvider(name = "testGetInvalidAuthenticatorParamsData")
    public Object[][] testGetInvalidAuthenticatorParamsData() {

        return new Object[][]{
                {ORG_ID_PARAMETER, orgId, "/org_discovery.do", ORG_PARAMETER},
                {ORG_PARAMETER, org, "/org_name.do", ORG_PARAMETER},
                {LOGIN_HINT_PARAMETER, userEmailWithInvalidDomain, "/org_discovery.do", ORG_PARAMETER}
        };
    }

    @Test(dataProvider = "testGetInvalidAuthenticatorParamsData")
    public void testProcessWithInvalidAuthenticatorParam(String paramKey, String paramValue, String redirectPage,
                                                         String defaultParam)
            throws Exception {

        mockedOrganizationConfigManagerUtil.when(OrganizationConfigManagerUtil::resolveDefaultDiscoveryParam)
                .thenReturn(defaultParam);

        AuthenticationContext spyContext = Mockito.spy(new AuthenticationContext());
        authenticatorParamProperties.put(paramKey, paramValue);
        when(organizationAuthenticator.getRuntimeParams(spyContext)).thenReturn(authenticatorParamProperties);

        setupInboundAuthenticationRequestConfigs();
        when(mockApplicationManagementService.getServiceProvider(anyString(), anyString()))
                .thenReturn(mockServiceProvider);

        when(spyContext.getTenantDomain()).thenReturn(saasAppOwnedTenant);
        when(spyContext.getServiceProviderName()).thenReturn(saasApp);
        doReturn(saasAppOwnedTenant).when(spyContext).getLoginTenantDomain();
        when(spyContext.getContextIdentifier()).thenReturn(contextIdentifier);
        when(spyContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockExternalIdPConfig.getName()).thenReturn(AUTHENTICATOR_FRIENDLY_NAME);
        when(spyContext.getServiceProviderResourceId()).thenReturn(saasAppResourceId);

        when(authenticatorDataHolder.getOrganizationConfigManager().getDiscoveryConfiguration())
                .thenReturn(mockDiscoveryConfig);
        List<ConfigProperty> configProperties = new ArrayList<>();
        configProperties.add(new ConfigProperty(emailDomainDiscoveryType + ENABLE_CONFIG,
                String.valueOf(true)));
        when(mockDiscoveryConfig.getConfigProperties()).thenReturn(configProperties);

        Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers = new HashMap<>();
        AttributeBasedOrganizationDiscoveryHandler discoveryHandler =
                mock(AttributeBasedOrganizationDiscoveryHandler.class);
        discoveryHandlers.put(emailDomainDiscoveryType, discoveryHandler);
        when(authenticatorDataHolder.getOrganizationDiscoveryManager().getAttributeBasedOrganizationDiscoveryHandlers())
                .thenReturn(discoveryHandlers);

        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(saasAppOwnedTenant)).thenReturn(
                saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString())).thenReturn(orgId);
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationNameById(anyString()))
                .thenThrow(handleClientException(ERROR_CODE_INVALID_ORGANIZATION_ID));

        when(authenticatorDataHolder.getOrganizationDiscoveryManager()
                .getOrganizationIdByDiscoveryAttribute(emailDomainDiscoveryType, userEmailWithInvalidDomain,
                        saasAppOwnedOrgId, spyContext)).thenReturn(null);

        AuthenticatorFlowStatus status = organizationAuthenticator.process(mockServletRequest, mockServletResponse,
                spyContext);

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        // Capture the redirect URL and verify the redirection to org discovery pages.
        verify(mockServletResponse, times(1)).sendRedirect(urlCaptor.capture());
        String url = urlCaptor.getValue();
        Assert.assertTrue(url.contains(redirectPage));
        // Verify the authentication flow status.
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
        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);

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

        mockOrganizationManager();

        when(mockOrganizationManager.resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);
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

        mockOrganizationManager();
        mockOrgApplicationManager();

        when(authenticatorDataHolder.getOrgApplicationManager().resolveSharedApplication(anyString(),
                anyString(), anyString())).thenThrow(
                new OrganizationManagementServerException(ERROR_CODE_INVALID_APPLICATION.getCode(),
                        ERROR_CODE_INVALID_APPLICATION.getMessage()));

        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);

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

        mockOrganizationManager();
        mockOrgApplicationManager();
        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);

        when(mockServiceProvider.getInboundAuthenticationConfig()).thenReturn(mockInboundAuthenticationConfig);

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

    @DataProvider(name = "samlIdPInitiatedB2BLoginFlowTestData")
    public Object[][] getSAMLIdPInitiatedB2BLoginFlowTestData() {

        String samlRedirectionHtmlPage = "<html>\n" +
                "<body onload=\"javascript:document.getElementById('samlsso-response-form').submit()\">\n" +
                "<h2>Please wait while we take you back to $acUrl</h2>\n" +
                "<p><a href=\"javascript:document.getElementById('samlsso-response-form').submit()\">Click here</a>" +
                " if you have been waiting for too long.</p>\n" +
                "<form id=\"samlsso-response-form\" method=\"post\" action=\"$acUrl\">\n" +
                "    <!--$params-->\n" +
                "</form>\n" +
                "</body>\n" +
                "</html>";

        return new Object[][]{
                // When saml redirection html page is not available.
                {false, StringUtils.EMPTY},
                // When saml redirection html page is available.
                {true, samlRedirectionHtmlPage}
        };
    }

    @Test(dataProvider = "samlIdPInitiatedB2BLoginFlowTestData")
    public void testSAMLIdPInitiatedB2BLoginFlow(boolean isSamlRedirectionHtmlPageAvailable,
                                                 String samlRedirectionHtmlPage) throws Exception {

        // Set mock context parameters for a valid organization.
        setMockContextParamForValidOrganization();

        // Set authenticator parameters.
        authenticatorParamProperties.put(ORG_PARAMETER, org);
        authenticatorParamProperties.put(ORG_ID_PARAMETER, orgId);
        when(organizationAuthenticator.getRuntimeParams(mockAuthenticationContext))
                .thenReturn(authenticatorParamProperties);

        // Mock organization manager.
        mockOrganizationManager();

        // Mock authentication context.
        mockBasicAuthenticationContext(saasAppOwnedTenant, saasApp);

        // Mock application manager.
        mockOrgApplicationManager();

        // Mock service provider.
        when(mockServiceProvider.getInboundAuthenticationConfig()).thenReturn(mockInboundAuthenticationConfig);

        // Set OIDC configuration for the shared app.
        InboundAuthenticationRequestConfig oidcConfiguration = new InboundAuthenticationRequestConfig();
        oidcConfiguration.setInboundAuthType(INBOUND_AUTH_TYPE_OAUTH);
        oidcConfiguration.setInboundAuthKey(clientId);
        when(mockInboundAuthenticationConfig.getInboundAuthenticationRequestConfigs()).thenReturn(
                new InboundAuthenticationRequestConfig[]{oidcConfiguration});

        // Mock OAuth admin service.
        when(authenticatorDataHolder.getOAuthAdminService().getOAuthApplicationData(anyString(), anyString()))
                .thenReturn(mockOAuthConsumerAppDTO);
        when(mockOAuthConsumerAppDTO.getOauthConsumerSecret()).thenReturn(secretKey);
        when(mockOAuthConsumerAppDTO.getCallbackUrl()).thenReturn("https://localhost:9443/commonauth");

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class)) {

            // Mock ServiceURLBuilder.
            String orgOAuth2AuthorizeURL = "https://localhost:9443/o/" + orgId + "/oauth2/authorize";
            ServiceURL mockedServiceURL = mock(ServiceURL.class);
            when(mockedServiceURL.getAbsolutePublicURL()).thenReturn(orgOAuth2AuthorizeURL);

            ServiceURLBuilder mockedServiceURLBuilder = mock(ServiceURLBuilder.class);
            serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockedServiceURLBuilder);
            when(mockedServiceURLBuilder.addPath(anyString())).thenReturn(mockedServiceURLBuilder);
            when(mockedServiceURLBuilder.setTenant(anyString())).thenReturn(mockedServiceURLBuilder);
            when(mockedServiceURLBuilder.setOrganization(anyString())).thenReturn(mockedServiceURLBuilder);
            when(mockedServiceURLBuilder.build()).thenReturn(mockedServiceURL);

            // Mock claim configs.
            when(mockServiceProvider.getClaimConfig()).thenReturn(mockClaimConfig);

            // Mock servlet request parameters to return saml response.
            Map<String, String[]> mockParamMap = new HashMap<>();
            mockParamMap.put(SAML_RESP, new String[]{samlResponse});
            when(mockServletRequest.getParameterMap()).thenReturn(mockParamMap);
            when(mockServletRequest.getParameter(SAML_RESP)).thenReturn(samlResponse);

            // Set SAML SSO response HTML page configuration.
            authenticatorDataHolder.setUseSamlSsoResponseHtmlPage(isSamlRedirectionHtmlPageAvailable);
            authenticatorDataHolder.setSamlSsoResponseHtmlPage(samlRedirectionHtmlPage);

            // Mock servlet response writer.
            PrintWriter mockedPrintWriter = mock(PrintWriter.class);
            when(mockServletResponse.getWriter()).thenReturn(mockedPrintWriter);

            // Spy on OrganizationAuthenticator and initiate authentication request.
            OrganizationAuthenticator orgAuthenticator = new OrganizationAuthenticator();
            OrganizationAuthenticator spyOrgAuthenticator = Mockito.spy(orgAuthenticator);
            doReturn(orgOAuth2AuthorizeURL).when(spyOrgAuthenticator).prepareLoginPage(mockServletRequest,
                    mockAuthenticationContext);

            spyOrgAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                    mockAuthenticationContext);

            // Verify the SAML redirection HTML page is written to the response.
            verify(mockedPrintWriter).print(anyString());
        }
    }

    private void mockBasicAuthenticationContext(String tenantDomain, String serviceProviderName) {

        when(mockAuthenticationContext.getTenantDomain()).thenReturn(tenantDomain);
        when(mockAuthenticationContext.getServiceProviderName()).thenReturn(serviceProviderName);
    }

    private void mockOrgApplicationManager() throws OrganizationManagementException {

        when(authenticatorDataHolder.getOrgApplicationManager().resolveSharedApplication(anyString(),
                anyString(), anyString())).thenReturn(mockServiceProvider);
    }

    private void mockOrganizationManager() throws OrganizationManagementException {

        when(authenticatorDataHolder.getOrganizationManager()
                .getOrganizationIdByName(anyString())).thenReturn(orgId);
        when(authenticatorDataHolder.getOrganizationManager()
                .getOrganization(anyString(), anyBoolean(), anyBoolean())).thenReturn(mockOrganization);
        when(authenticatorDataHolder.getOrganizationManager().resolveTenantDomain(anyString()))
                .thenReturn(orgId);
        when(authenticatorDataHolder.getOrganizationManager().resolveOrganizationId(anyString()))
                .thenReturn(saasAppOwnedOrgId);
        when(authenticatorDataHolder.getOrganizationManager().getOrganizationNameById(anyString()))
                .thenReturn(org);
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
