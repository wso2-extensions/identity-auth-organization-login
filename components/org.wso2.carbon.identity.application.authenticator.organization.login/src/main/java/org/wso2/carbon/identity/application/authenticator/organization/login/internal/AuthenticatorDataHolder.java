/*
 * Copyright (c) 2022-2023, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.carbon.identity.application.authenticator.organization.login.internal;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * This class acts as a data holder to the organization login authenticator service.
 */
public class AuthenticatorDataHolder {

    private static final AuthenticatorDataHolder instance = new AuthenticatorDataHolder();

    private RealmService realmService;

    private OAuthAdminServiceImpl oAuthAdminService;

    private OrganizationManager organizationManager;

    private OrgApplicationManager orgApplicationManager;

    private ApplicationManagementService applicationManagementService;
    private ClaimMetadataManagementService claimMetadataManagementService;
    private OrganizationConfigManager organizationConfigManager;
    private OrganizationDiscoveryManager organizationDiscoveryManager;

    private boolean useSamlSsoResponseHtmlPage = false;
    private String samlSsoResponseHtmlPage = StringUtils.EMPTY;

    public static AuthenticatorDataHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public OAuthAdminServiceImpl getOAuthAdminService() {

        return oAuthAdminService;
    }

    public void setOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        this.oAuthAdminService = oAuthAdminService;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    public OrgApplicationManager getOrgApplicationManager() {

        return orgApplicationManager;
    }

    public void setOrgApplicationManager(OrgApplicationManager orgApplicationManager) {

        this.orgApplicationManager = orgApplicationManager;
    }

    public ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {

        return claimMetadataManagementService;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        this.claimMetadataManagementService = claimMetadataManagementService;
    }

    public OrganizationConfigManager getOrganizationConfigManager() {

        return organizationConfigManager;
    }

    public void setOrganizationConfigManager(OrganizationConfigManager organizationConfigManager) {

        this.organizationConfigManager = organizationConfigManager;
    }

    public OrganizationDiscoveryManager getOrganizationDiscoveryManager() {

        return organizationDiscoveryManager;
    }

    public void setOrganizationDiscoveryManager(OrganizationDiscoveryManager organizationDiscoveryManager) {

        this.organizationDiscoveryManager = organizationDiscoveryManager;
    }

    /**
     * Check whether the SAML SSO response HTML page is available.
     *
     * @return True if the SAML SSO response HTML page is available.
     */
    public boolean isSamlSsoResponseHtmlPageAvailable() {

        return useSamlSsoResponseHtmlPage;
    }

    /**
     * Set whether the SAML SSO response HTML page is available.
     *
     * @param useSamlSsoResponseHtmlPage True if the SAML SSO response HTML page is available.
     */
    public void setUseSamlSsoResponseHtmlPage(boolean useSamlSsoResponseHtmlPage) {

        this.useSamlSsoResponseHtmlPage = useSamlSsoResponseHtmlPage;
    }

    /**
     * Get the SAML SSO response HTML page.
     *
     * @return SAML SSO response HTML page.
     */
    public String getSamlSsoResponseHtmlPage() {

        return samlSsoResponseHtmlPage;
    }

    /**
     * Set the SAML SSO response HTML page.
     *
     * @param samlSsoResponseHtmlPage SAML SSO response HTML page.
     */
    public void setSamlSsoResponseHtmlPage(String samlSsoResponseHtmlPage) {

        this.samlSsoResponseHtmlPage = samlSsoResponseHtmlPage;
    }
}
