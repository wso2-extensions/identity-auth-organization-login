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

package org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant;

/**
 * This class contains constants related to Organization Identifier Handler.
 */
public class OrganizationIdentifierHandlerConstants {

    private OrganizationIdentifierHandlerConstants() {

    }

    public static final String AUTHENTICATOR_NAME = "OrganizationIdentifierHandler";
    public static final String AUTHENTICATOR_ORGANIZATION_IDENTIFIER = "authenticator.organization.identifier";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Organization SSO";
    public static final String CONTEXT_IDENTIFIER = "sessionDataKey";

    public static final String EQUAL_SIGN = "=";
    public static final String AMPERSAND_SIGN = "&";

    public static final String SP_ID_PARAMETER = "spId";
    public static final String AUTHENTICATOR_PARAMETER = "authenticator";

    public static final String REQUEST_ORG_PAGE_URL = "authenticationendpoint/org_name.do";
    public static final String REQUEST_ORG_HANDLE_PAGE_URL = "authenticationendpoint/org_handle.do";
    public static final String REQUEST_ORG_DISCOVERY_PAGE_URL = "authenticationendpoint/org_discovery.do";
    public static final String REQUEST_ORG_PAGE_URL_CONFIG = "RequestOrganizationPage";

    public static final String ORG_NAME_PARAMETER = "org";
    public static final String ORG_HANDLE_PARAMETER = "orgHandle";
    public static final String ORG_DISCOVERY_PARAMETER = "orgDiscovery";
    public static final String PROMPT_PARAMETER = "prompt";
    public static final String ORGANIZATION_NAME_PROMPT_PARAMETER = "orgName";

    public static final String DISPLAY_ORG_ID = "Organization Id";
    public static final String DISPLAY_ORG_NAME = "Organization Name";
    public static final String DISPLAY_ORG_HANDLE = "Organization Handle";
    public static final String DISPLAY_LOGIN_HINT = "Login Hint";
    public static final String DISPLAY_ORG_DISCOVERY_TYPE = "Organization Discovery Type";

    public static final String I18N_ORG_ID = "organization.id.param";
    public static final String I18N_ORG_NAME = "organization.name.param";
    public static final String I18N_ORG_HANDLE = "organization.handle.param";
    public static final String I18N_LOGIN_HINT = "login.hint.param";
    public static final String I18N_ORG_DISCOVERY_TYPE = "organization.discovery.type.param";

    public static final String AUTHENTICATOR_MESSAGE = "authenticatorMessage";
}
