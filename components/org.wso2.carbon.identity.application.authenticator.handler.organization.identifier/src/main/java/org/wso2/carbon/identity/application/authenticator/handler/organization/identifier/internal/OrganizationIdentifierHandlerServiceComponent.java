/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.internal;

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
import org.wso2.carbon.identity.application.authentication.framework.handler.orgdiscovery.OrganizationDiscoveryHandler;
import org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.OrganizationIdentifierHandler;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;

/**
 * This class acts as a service component for the Organization Identifier Handler.
 */
@Component(
        name = "identity.organization.identifier.handler",
        immediate = true
)
public class OrganizationIdentifierHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(OrganizationIdentifierHandlerServiceComponent.class.getName());

    @Activate
    protected void activate(ComponentContext ctx) {

        ctx.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                new OrganizationIdentifierHandler(), null);
        log.debug("Organization Identifier Handler is activated.");
    }

    @Deactivate
    protected void deactivate(ComponentContext ctx) {

        log.debug("Organization Identifier Handler is deactivated.");
    }

    /**
     * This method is used to set the Organization Discovery Handler.
     *
     * @param organizationDiscoveryHandler OrganizationDiscoveryHandler instance.
     */
    @Reference(
            name = "organization.discoverer.handler",
            service = OrganizationDiscoveryHandler.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationDiscovererHandler"
    )
    protected void setOrganizationDiscovererHandler(OrganizationDiscoveryHandler organizationDiscoveryHandler) {

        OrganizationIdentifierHandlerDataHolder.getInstance()
                .setOrganizationDiscoveryHandler(organizationDiscoveryHandler);
        log.debug("Organization discovery handler is set in organization identifier handler component.");
    }

    /**
     * This method is used to unset the Organization Discovery Handler.
     *
     * @param organizationDiscoveryHandler OrganizationDiscoveryHandler instance.
     */
    protected void unsetOrganizationDiscovererHandler(OrganizationDiscoveryHandler organizationDiscoveryHandler) {

        OrganizationIdentifierHandlerDataHolder.getInstance().setOrganizationDiscoveryHandler(null);
        log.debug("Organization discovery handler is unset in organization identifier handler component.");
    }

    @Reference(name = "identity.organization.config.management.component",
            service = OrganizationConfigManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationConfigManager")
    protected void setOrganizationConfigManager(OrganizationConfigManager organizationConfigManager) {

        OrganizationIdentifierHandlerDataHolder.getInstance().setOrganizationConfigManager(organizationConfigManager);
    }

    protected void unsetOrganizationConfigManager(OrganizationConfigManager organizationConfigManager) {

        OrganizationIdentifierHandlerDataHolder.getInstance().setOrganizationConfigManager(null);
    }

    @Reference(name = "identity.organization.discovery.management.component",
            service = OrganizationDiscoveryManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationDiscoveryManager")
    protected void setOrganizationDiscoveryManager(OrganizationDiscoveryManager organizationDiscoveryManager) {

        OrganizationIdentifierHandlerDataHolder.getInstance()
                .setOrganizationDiscoveryManager(organizationDiscoveryManager);
    }

    protected void unsetOrganizationDiscoveryManager(OrganizationDiscoveryManager organizationDiscoveryManager) {

        OrganizationIdentifierHandlerDataHolder.getInstance().setOrganizationDiscoveryManager(null);
    }
}
