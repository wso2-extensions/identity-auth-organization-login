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

package org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.internal;

import org.wso2.carbon.identity.application.authentication.framework.handler.orgdiscovery.OrganizationDiscoveryHandler;
import org.wso2.carbon.identity.organization.config.service.OrganizationConfigManager;
import org.wso2.carbon.identity.organization.discovery.service.OrganizationDiscoveryManager;

/**
 * Data holder for Organization Identifier Handler.
 */
public class OrganizationIdentifierHandlerDataHolder {

    private static final OrganizationIdentifierHandlerDataHolder instance =
            new OrganizationIdentifierHandlerDataHolder();

    private OrganizationDiscoveryHandler organizationDiscoveryHandler;
    private OrganizationConfigManager organizationConfigManager;
    private OrganizationDiscoveryManager organizationDiscoveryManager;

    private OrganizationIdentifierHandlerDataHolder() {

    }

    /**
     * Get the singleton instance of OrganizationIdentifierHandlerDataHolder.
     *
     * @return OrganizationIdentifierHandlerDataHolder instance.
     */
    public static OrganizationIdentifierHandlerDataHolder getInstance() {

        return instance;
    }

    /**
     * Get the Organization Discovery Handler.
     *
     * @return OrganizationDiscoveryHandler instance.
     */
    public OrganizationDiscoveryHandler getOrganizationDiscoveryHandler() {

        return organizationDiscoveryHandler;
    }

    /**
     * Set the Organization Discovery Handler.
     *
     * @param organizationDiscoveryHandler OrganizationDiscoveryHandler instance.
     */
    public void setOrganizationDiscoveryHandler(OrganizationDiscoveryHandler organizationDiscoveryHandler) {

        this.organizationDiscoveryHandler = organizationDiscoveryHandler;
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
}
