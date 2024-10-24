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

package org.wso2.carbon.identity.application.authenticator.organization.login.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.organization.login.OrganizationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This class contains the service component of the organization login authenticator.
 */
@Component(
        name = "identity.organization.authenticator.component",
        immediate = true
)
public class AuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticatorServiceComponent.class);

    @SuppressFBWarnings(
            value = "PATH_TRAVERSAL_IN",
            justification = "Passed file location is provided from the server side and not from user input."
    )
    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            OrganizationAuthenticator organizationAuthenticator = new OrganizationAuthenticator();
            ctxt.getBundleContext()
                    .registerService(ApplicationAuthenticator.class.getName(), organizationAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("Organization Authenticator bundle is activated");
            }

            Path redirectHtmlPath = Paths.get(CarbonUtils.getCarbonHome(), "repository", "resources",
                    "identity", "pages", "samlsso_response.html");
            if (Files.exists(redirectHtmlPath)) {
                AuthenticatorDataHolder.getInstance().setUseSamlSsoResponseHtmlPage(true);
                AuthenticatorDataHolder.getInstance().setSamlSsoResponseHtmlPage(
                        new String(Files.readAllBytes(redirectHtmlPath), StandardCharsets.UTF_8));
                if (log.isDebugEnabled()) {
                    log.debug(" SAML SSO response HTML page is found at : " + redirectHtmlPath);
                }
            }
        } catch (Exception e) {
            log.error(" Error while activating Organization Authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Organization Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        AuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset the Realm Service.");
        }
        AuthenticatorDataHolder.getInstance().setRealmService(null);
    }

    @Reference(name = "identity.oauth.component",
            service = OAuthAdminServiceImpl.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOAuthAdminService")
    protected void setOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth Management Service is set in the OpenID Connect Authenticator");
        }
        AuthenticatorDataHolder.getInstance().setOAuthAdminService(oAuthAdminService);
    }

    protected void unsetOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth Management Service is unset in the OpenID Connect Authenticator");
        }
        AuthenticatorDataHolder.getInstance().setOAuthAdminService(null);
    }

    @Reference(name = "identity.application.management.component",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        AuthenticatorDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        AuthenticatorDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Organization Manager is set in the Authenticator");
        }
        AuthenticatorDataHolder.getInstance()
                .setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Organization Manager is unset in the Authenticator");
        }
        AuthenticatorDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(name = "identity.organization.application.management.component",
            service = OrgApplicationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrgApplicationManager")
    protected void setOrgApplicationManager(OrgApplicationManager orgApplicationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Organization Application Manager is set in the Authenticator");
        }
        AuthenticatorDataHolder.getInstance().setOrgApplicationManager(orgApplicationManager);
    }

    protected void unsetOrgApplicationManager(OrgApplicationManager orgApplicationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Organization Application Manager is unset in the Authenticator");
        }
        AuthenticatorDataHolder.getInstance().setOrgApplicationManager(null);
    }

    @Reference(
            name = "claim.metadata.management.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetaDataManagementService"
    )
    protected void setClaimMetaDataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        AuthenticatorDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
        log.debug("Setting the claim metadata management service.");

    }

    protected void unsetClaimMetaDataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        AuthenticatorDataHolder.getInstance().setClaimMetadataManagementService(null);
        log.debug("Unset the claim metadata management service.");
    }

    @Reference(name = "identity.organization.config.management.component",
            service = OrganizationConfigManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationConfigManager")
    protected void setOrganizationConfigManager(OrganizationConfigManager organizationConfigManager) {

        AuthenticatorDataHolder.getInstance().setOrganizationConfigManager(organizationConfigManager);
    }

    protected void unsetOrganizationConfigManager(OrganizationConfigManager organizationConfigManager) {

        AuthenticatorDataHolder.getInstance().setOrganizationConfigManager(null);
    }

    @Reference(name = "identity.organization.discovery.management.component",
            service = OrganizationDiscoveryManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationDiscoveryManager")
    protected void setOrganizationDiscoveryManager(OrganizationDiscoveryManager organizationDiscoveryManager) {

        AuthenticatorDataHolder.getInstance().setOrganizationDiscoveryManager(organizationDiscoveryManager);
    }

    protected void unsetOrganizationDiscoveryManager(OrganizationDiscoveryManager organizationDiscoveryManager) {

        AuthenticatorDataHolder.getInstance().setOrganizationDiscoveryManager(null);
    }
}
