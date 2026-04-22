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

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.internal;

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
import org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandler;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and de-registration of
 * SharedUserIdentifierHandler.
 */
@Component(
        name = "identity.application.handler.shared.user.identifier.component",
        immediate = true
)
public class SharedUserIdentifierAuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(SharedUserIdentifierAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            SharedUserIdentifierHandler sharedUserIdentifierHandler = new SharedUserIdentifierHandler();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    sharedUserIdentifierHandler, null);
            LOG.debug("SharedUserIdentifierHandler bundle is activated");
        } catch (Throwable e) {
            LOG.error("SharedUserIdentifierHandler bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        LOG.debug("SharedUserIdentifierHandler bundle is deactivated");
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        LOG.debug("Setting the Realm Service");
        SharedUserIdentifierAuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        LOG.debug("Unsetting the Realm Service");
        SharedUserIdentifierAuthenticatorDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "organization.user.sharing.service",
            service = OrganizationUserSharingService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserSharingService"
    )
    protected void setOrganizationUserSharingService(
            OrganizationUserSharingService organizationUserSharingService) {

        LOG.debug("Setting the organization user sharing service.");
        SharedUserIdentifierAuthenticatorDataHolder.getInstance()
                .setOrganizationUserSharingService(organizationUserSharingService);
    }

    protected void unsetOrganizationUserSharingService(
            OrganizationUserSharingService organizationUserSharingService) {

        LOG.debug("Unsetting the organization user sharing service.");
        SharedUserIdentifierAuthenticatorDataHolder.getInstance().setOrganizationUserSharingService(null);
    }

    @Reference(
            name = "organization.manager",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        LOG.debug("Setting the organization manager service.");
        SharedUserIdentifierAuthenticatorDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        LOG.debug("Unsetting the organization manager service.");
        SharedUserIdentifierAuthenticatorDataHolder.getInstance().setOrganizationManager(null);
    }
}
