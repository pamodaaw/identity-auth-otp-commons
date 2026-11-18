/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.otp.core.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import javax.servlet.http.HttpServletRequest;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MULTI_OPTION_URI_PARAM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY;

/**
 * Utility functions for the authenticator.
 */
public class AuthenticatorUtils {

    private static final Log LOG = LogFactory.getLog(AuthenticatorUtils.class);
    private static final String COMPONENT_ID = "auth-otp-core-authenticator-utils";
    private static final String MULTI_OPTION_URI = "multiOptionURI";
    private static final String AUTHENTICATORS_PARAM_NAME = "authenticators=";
    /*
     The option list carried in the multi option URI is percent encoded, but the decoded form is tolerated as well,
     so that the comparison does not depend on how many times the URI has been decoded.
     */
    private static final Pattern AUTHENTICATOR_SEPARATOR = Pattern.compile("%3B|;", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTHENTICATOR_IDP_SEPARATOR = Pattern.compile("%3A|:", Pattern.CASE_INSENSITIVE);

    /**
     * Get the multi option URI query param.
     *
     * @param request HttpServletRequest.
     * @return Query parameter for the multi option URI.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    public static String getMultiOptionURIQueryString(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter(MULTI_OPTION_URI);
            multiOptionURI = multiOptionURI != null ? MULTI_OPTION_URI_PARAM +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    /**
     * Get the multi option URI query param, when the options it carries are the options of the step that is being
     * executed.
     *
     * The multi option URI is a snapshot of the option page of the step it was generated for, which the browser
     * carries forward from page to page. An authentication script can change the options of a step after that page
     * is rendered, for example by executing a step with a narrowed down option list from within {@code onFail}. The
     * URI then offers options that the current step no longer has, and picking one of them fails the login with an
     * invalid authenticator error. The URI is dropped in that case, so that a stale option page is never offered.
     *
     * @param request HttpServletRequest.
     * @param context AuthenticationContext.
     * @return Query parameter for the multi option URI, or an empty string when it is not for the current step.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    public static String getMultiOptionURIQueryString(HttpServletRequest request, AuthenticationContext context) {

        if (request == null) {
            return "";
        }
        String multiOptionURI = request.getParameter(MULTI_OPTION_URI);
        if (multiOptionURI == null) {
            return "";
        }
        if (StringUtils.isNotBlank(multiOptionURI) && !isMultiOptionURIOfCurrentStep(multiOptionURI, context)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Dropping the multi option URI, since the options it carries are not the options of the " +
                        "current step. The authentication script may have changed the options of the step after the " +
                        "option page was rendered.");
            }
            return "";
        }
        return MULTI_OPTION_URI_PARAM + Encode.forUriComponent(multiOptionURI);
    }

    /**
     * Check whether the options carried in the multi option URI are the options of the step that is being executed.
     *
     * When either side cannot be read, the URI is kept as it is, so that the behaviour is unchanged wherever the
     * comparison cannot be made.
     *
     * @param multiOptionURI Multi option URI taken from the request.
     * @param context        AuthenticationContext.
     * @return True if the URI is for the current step, or if it cannot be compared with the current step.
     */
    private static boolean isMultiOptionURIOfCurrentStep(String multiOptionURI, AuthenticationContext context) {

        Set<String> optionsInURI = getAuthenticatorNamesInMultiOptionURI(multiOptionURI);
        if (optionsInURI.isEmpty()) {
            return true;
        }
        Set<String> optionsInStep = getAuthenticatorNamesOfCurrentStep(context);
        if (optionsInStep.isEmpty()) {
            return true;
        }
        return optionsInURI.equals(optionsInStep);
    }

    /**
     * Read the authenticator names from the option list carried in the multi option URI.
     *
     * An entry of the list is the name of the authenticator, followed by the identity providers it is configured
     * with, as built by {@code FrameworkUtils.getAuthenticatorIdPMappingString()}.
     *
     * @param multiOptionURI Multi option URI taken from the request.
     * @return Lower cased authenticator names, empty when the URI carries no option list.
     */
    private static Set<String> getAuthenticatorNamesInMultiOptionURI(String multiOptionURI) {

        int startIndex = multiOptionURI.indexOf(AUTHENTICATORS_PARAM_NAME);
        if (startIndex == -1) {
            return Collections.emptySet();
        }
        String options = multiOptionURI.substring(startIndex + AUTHENTICATORS_PARAM_NAME.length());
        int endIndex = options.indexOf('&');
        if (endIndex != -1) {
            options = options.substring(0, endIndex);
        }
        Set<String> authenticatorNames = new HashSet<>();
        for (String option : AUTHENTICATOR_SEPARATOR.split(options)) {
            String authenticatorName = AUTHENTICATOR_IDP_SEPARATOR.split(option, 2)[0];
            if (StringUtils.isNotBlank(authenticatorName)) {
                authenticatorNames.add(authenticatorName.trim().toLowerCase(Locale.ENGLISH));
            }
        }
        return authenticatorNames;
    }

    /**
     * Read the authenticator names of the step that is being executed.
     *
     * @param context AuthenticationContext.
     * @return Lower cased authenticator names, empty when the step cannot be resolved.
     */
    private static Set<String> getAuthenticatorNamesOfCurrentStep(AuthenticationContext context) {

        if (context == null || context.getSequenceConfig() == null
                || context.getSequenceConfig().getStepMap() == null) {
            return Collections.emptySet();
        }
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep());
        if (stepConfig == null || stepConfig.getAuthenticatorList() == null) {
            return Collections.emptySet();
        }
        Set<String> authenticatorNames = new HashSet<>();
        for (AuthenticatorConfig authenticatorConfig : stepConfig.getAuthenticatorList()) {
            if (authenticatorConfig != null && StringUtils.isNotBlank(authenticatorConfig.getName())) {
                authenticatorNames.add(authenticatorConfig.getName().trim().toLowerCase(Locale.ENGLISH));
            }
        }
        return authenticatorNames;
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws
            AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = AuthenticatorDataHolder
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    FAILED_LOGIN_ATTEMPTS_PROPERTY,
                                    ACCOUNT_UNLOCK_TIME_PROPERTY
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration for tenant : " +  tenantDomain, e);
        }
        return connectorConfigs;
    }

    /**
     * Get the parameter value from the runtime parameters if available.
     *
     * @param runtimeParams Runtime parameters.
     * @param paramName     Parameter name.
     * @return Optional parameter value.
     */
    public static Optional<String> getStringRuntimeParamByName(Map<String, String> runtimeParams,
                                                               String paramName) {

        if (MapUtils.isEmpty(runtimeParams)) {
            return Optional.empty();
        }

        String value = runtimeParams.get(paramName);
        if (StringUtils.isNotBlank(value)) {
            return Optional.of(value);
        }
        return Optional.empty();
    }

    /**
     * Get the boolean parameter value from the runtime parameters if available.
     *
     * @param runtimeParams Runtime parameters.
     * @param paramName     Parameter name.
     * @return Optional boolean parameter value.
     */
    public static Optional<Boolean> getBooleanRuntimeParamByName(Map<String, String> runtimeParams,
                                                                 String paramName) {

        Optional<String> paramValue = getStringRuntimeParamByName(runtimeParams, paramName);
        if (paramValue.isPresent()) {
            String value = paramValue.get();
            return Optional.of(Boolean.parseBoolean(value));
        }
        return Optional.empty();
    }

    /**
     * Get the integer parameter value from the runtime parameters if available.
     *
     * @param runtimeParams Runtime parameters.
     * @param paramName     Parameter name.
     * @return Optional integer parameter value.
     */
    public static OptionalInt getIntRuntimeParamByName(Map<String, String> runtimeParams,
                                                       String paramName) {

        Optional<String> value = getStringRuntimeParamByName(runtimeParams, paramName);
        if (value.isPresent()) {
            try {
                return OptionalInt.of(Integer.parseInt(value.get()));
            } catch (NumberFormatException e) {
                triggerDiagnosticLog(
                        COMPONENT_ID,
                        AuthenticatorConstants.LogConstants.ActionID.GET_OPTIONAL_INTEGER_RUNTIME_PARAMS,
                        "Unable to parse the parameter: " + paramName + " with value: "
                                + value + " to an integer. Returning empty optional.",
                        DiagnosticLog.ResultStatus.FAILED,
                        DiagnosticLog.LogDetailLevel.APPLICATION
                );
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse the parameter: " + paramName + " with value: "
                            + value.get() + " to an integer.", e);
                }
            }
        }
        return OptionalInt.empty();
    }

    /**
     * Trigger a diagnostic log event if diagnostic logging is enabled.
     *
     * @param componentId    The diagnostic log component ID.
     * @param actionId       The action ID associated with the log event.
     * @param message        The result message to include in the log.
     * @param status         The result status of the operation.
     * @param logDetailLevel The detail level of the log entry.
     */
    public static void triggerDiagnosticLog(String componentId, String actionId, String message,
                                            DiagnosticLog.ResultStatus status,
                                            DiagnosticLog.LogDetailLevel logDetailLevel) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(
                    new DiagnosticLog.DiagnosticLogBuilder(componentId, actionId)
                            .resultMessage(message)
                            .logDetailLevel(logDetailLevel)
                            .resultStatus(status)
            );
        }
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context   AuthenticationContext.
     * @return True if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    public static boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }
}
