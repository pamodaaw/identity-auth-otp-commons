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

package org.wso2.carbon.identity.auth.otp.core.util;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import javax.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

/**
 * Unit tests for AuthenticatorUtils.
 */
public class AuthenticatorUtilsTest {

    private static final String PARAM_NAME = "testParam";
    private static final String MULTI_OPTION_URI = "multiOptionURI";
    private static final String MULTI_OPTION_URI_PARAM = "&multiOptionURI=";
    private static final String SMS_OTP = "sms-otp-authenticator";
    private static final String EMAIL_OTP = "email-otp-authenticator";
    private static final String TOTP = "totp";
    private static final String PAGE_URL = "https://localhost:9443/authenticationendpoint/login.do?sessionDataKey=k";

    private MockedStatic<LoggerUtils> loggerUtilsMock;

    @BeforeMethod
    public void setUp() {

        loggerUtilsMock = mockStatic(LoggerUtils.class);
        // Disable diagnostic logging by default; individual tests override this where needed.
        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
    }

    @AfterMethod
    public void tearDown() {

        if (loggerUtilsMock != null) {
            loggerUtilsMock.close();
        }
    }

    @DataProvider(name = "getStringRuntimeParamByNameData")
    public Object[][] getStringRuntimeParamByNameData() {

        Map<String, String> presentParam = new HashMap<>();
        presentParam.put(PARAM_NAME, "hello");

        Map<String, String> otherParam = new HashMap<>();
        otherParam.put("otherParam", "value");

        Map<String, String> blankValue = new HashMap<>();
        blankValue.put(PARAM_NAME, "");

        Map<String, String> nullValue = new HashMap<>();
        nullValue.put(PARAM_NAME, null);

        return new Object[][] {
                {"Returns the value when the param exists in the map",
                        presentParam, true, "hello"},
                {"Returns empty when the param key is absent from the map",
                        otherParam, false, null},
                {"Returns empty when the runtime params map is null",
                        null, false, null},
                {"Returns empty when the runtime params map is empty",
                        Collections.emptyMap(), false, null},
                {"Returns empty when the param value is a blank string",
                        blankValue, false, null},
                {"Returns empty when the param value stored in the map is null",
                        nullValue, false, null},
        };
    }

    @Test(dataProvider = "getStringRuntimeParamByNameData",
            description = "getStringRuntimeParamByName returns expected Optional for various inputs")
    public void testGetStringRuntimeParamByName(String scenario, Map<String, String> params,
                                                boolean expectPresent, String expectedValue) {

        Optional<String> result = AuthenticatorUtils.getStringRuntimeParamByName(params, PARAM_NAME);
        Assert.assertEquals(result.isPresent(), expectPresent, scenario);
        if (expectPresent) {
            Assert.assertEquals(result.get(), expectedValue, scenario);
        }
    }

    @DataProvider(name = "getBooleanRuntimeParamByNameData")
    public Object[][] getBooleanRuntimeParamByNameData() {

        Map<String, String> trueParam = new HashMap<>();
        trueParam.put(PARAM_NAME, "true");

        Map<String, String> falseParam = new HashMap<>();
        falseParam.put(PARAM_NAME, "false");

        Map<String, String> upperCaseTrueParam = new HashMap<>();
        upperCaseTrueParam.put(PARAM_NAME, "TRUE");

        Map<String, String> nonBooleanParam = new HashMap<>();
        nonBooleanParam.put(PARAM_NAME, "yes");

        Map<String, String> otherParam = new HashMap<>();
        otherParam.put("otherParam", "true");

        return new Object[][] {
                {"Returns Optional.of(true) when the param value is 'true'",
                        trueParam, true, Boolean.TRUE},
                {"Returns Optional.of(false) when the param value is 'false'",
                        falseParam, true, Boolean.FALSE},
                {"Returns Optional.of(true) for 'TRUE' (case-insensitive)",
                        upperCaseTrueParam, true, Boolean.TRUE},
                {"Returns Optional.of(false) when the param value is a non-boolean string",
                        nonBooleanParam, true, Boolean.FALSE},
                {"Returns empty when the runtime params map is null",
                        null, false, null},
                {"Returns empty when the runtime params map is empty",
                        Collections.emptyMap(), false, null},
                {"Returns empty when the param key is absent",
                        otherParam, false, null},
        };
    }

    @Test(dataProvider = "getBooleanRuntimeParamByNameData",
            description = "getBooleanRuntimeParamByName returns expected Optional for various inputs")
    public void testGetBooleanRuntimeParamByName(String scenario, Map<String, String> params,
                                                 boolean expectPresent, Boolean expectedValue) {

        Optional<Boolean> result = AuthenticatorUtils.getBooleanRuntimeParamByName(params, PARAM_NAME);
        Assert.assertEquals(result.isPresent(), expectPresent, scenario);
        if (expectPresent) {
            Assert.assertEquals(result.get(), expectedValue, scenario);
        }
    }

    @DataProvider(name = "getIntRuntimeParamByNameData")
    public Object[][] getIntRuntimeParamByNameData() {

        Map<String, String> validIntParam = new HashMap<>();
        validIntParam.put(PARAM_NAME, "42");

        Map<String, String> zeroParam = new HashMap<>();
        zeroParam.put(PARAM_NAME, "0");

        Map<String, String> negativeParam = new HashMap<>();
        negativeParam.put(PARAM_NAME, "-5");

        Map<String, String> nonNumericParam = new HashMap<>();
        nonNumericParam.put(PARAM_NAME, "notAnInt");

        Map<String, String> decimalParam = new HashMap<>();
        decimalParam.put(PARAM_NAME, "3.14");

        Map<String, String> nullValueParam = new HashMap<>();
        nullValueParam.put(PARAM_NAME, null);

        Map<String, String> otherParam = new HashMap<>();
        otherParam.put("otherParam", "10");

        return new Object[][] {
                {"Returns the parsed integer when the param value is a valid integer string",
                        validIntParam, true, 42},
                {"Returns the parsed integer for a zero value",
                        zeroParam, true, 0},
                {"Returns the parsed integer for a negative value",
                        negativeParam, true, -5},
                {"Returns empty for a non-numeric value",
                        nonNumericParam, false, 0},
                {"Returns empty for a decimal string value",
                        decimalParam, false, 0},
                {"Returns empty when the runtime params map is null",
                        null, false, 0},
                {"Returns empty when the runtime params map is empty",
                        Collections.emptyMap(), false, 0},
                {"Returns empty when the param key is absent from the map",
                        otherParam, false, 0},
                {"Returns empty when the param value stored in the map is null",
                        nullValueParam, false, 0},
        };
    }

    @Test(dataProvider = "getIntRuntimeParamByNameData",
            description = "getIntRuntimeParamByName returns expected OptionalInt for various inputs")
    public void testGetIntRuntimeParamByName(String scenario, Map<String, String> params,
                                             boolean expectPresent, int expectedValue) {

        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        Assert.assertEquals(result.isPresent(), expectPresent, scenario);
        if (expectPresent) {
            Assert.assertEquals(result.getAsInt(), expectedValue, scenario);
        }
    }

    @Test(description = "Triggers a diagnostic log event for non-numeric values when diagnostic logging is enabled")
    public void testGetIntRuntimeParamByNameNonNumericTriggersDiagnosticLogWhenEnabled() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "bad_value");
        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        Assert.assertFalse(result.isPresent());
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(1));
    }

    @Test(description = "Does NOT trigger a diagnostic log event for non-numeric values when diagnostic logging is disabled")
    public void testGetIntRuntimeParamByNameNonNumericNoDiagnosticLogWhenDisabled() {

        // isDiagnosticLogsEnabled already returns false from setUp().
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "bad_value");
        AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), never());
    }

    @DataProvider(name = "triggerDiagnosticLogData")
    public Object[][] triggerDiagnosticLogData() {

        return new Object[][] {
                {"triggerDiagnosticLogEvent is called when diagnostic logging is enabled",
                        true, DiagnosticLog.ResultStatus.SUCCESS, 1},
                {"triggerDiagnosticLogEvent is NOT called when diagnostic logging is disabled",
                        false, DiagnosticLog.ResultStatus.FAILED, 0},
        };
    }

    @Test(dataProvider = "triggerDiagnosticLogData",
            description = "triggerDiagnosticLog conditionally calls triggerDiagnosticLogEvent based on logging status")
    public void testTriggerDiagnosticLog(String scenario, boolean loggingEnabled,
                                         DiagnosticLog.ResultStatus status, int expectedInvocations) {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(loggingEnabled);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        AuthenticatorUtils.triggerDiagnosticLog(
                "componentId",
                "actionId",
                "test message",
                status,
                DiagnosticLog.LogDetailLevel.APPLICATION);
        loggerUtilsMock.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(expectedInvocations));
    }

    @Test(description = "triggerDiagnosticLog does not throw for any ResultStatus value")
    public void testTriggerDiagnosticLogAllResultStatusesNoException() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        for (DiagnosticLog.ResultStatus status : DiagnosticLog.ResultStatus.values()) {
            AuthenticatorUtils.triggerDiagnosticLog("c", "a", "msg", status,
                    DiagnosticLog.LogDetailLevel.APPLICATION);
        }
    }

    @Test(description = "triggerDiagnosticLog does not throw for any LogDetailLevel value")
    public void testTriggerDiagnosticLogAllLogDetailLevelsNoException() {

        loggerUtilsMock.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtilsMock.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any())).thenAnswer(inv -> null);
        for (DiagnosticLog.LogDetailLevel level : DiagnosticLog.LogDetailLevel.values()) {
            AuthenticatorUtils.triggerDiagnosticLog("c", "a", "msg",
                    DiagnosticLog.ResultStatus.SUCCESS, level);
        }
    }

    /**
     * Build an authentication context whose current step carries the given authenticators.
     *
     * @param authenticatorNames Authenticator names of the current step, null to leave the step map empty.
     * @return AuthenticationContext.
     */
    private AuthenticationContext contextWithCurrentStepOptions(String... authenticatorNames) {

        AuthenticationContext context = new AuthenticationContext();
        SequenceConfig sequenceConfig = new SequenceConfig();
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        context.setCurrentStep(2);
        if (authenticatorNames != null) {
            List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
            for (String name : authenticatorNames) {
                AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
                authenticatorConfig.setName(name);
                authenticatorList.add(authenticatorConfig);
            }
            StepConfig stepConfig = new StepConfig();
            stepConfig.setOrder(2);
            stepConfig.setAuthenticatorList(authenticatorList);
            stepMap.put(2, stepConfig);
        }
        sequenceConfig.setStepMap(stepMap);
        context.setSequenceConfig(sequenceConfig);
        return context;
    }

    @DataProvider(name = "multiOptionURIData")
    public Object[][] multiOptionURIData() {

        String threeOptions = PAGE_URL + "&authenticators=" + SMS_OTP + "%3ALOCAL%3B" + TOTP + "%3ALOCAL%3B"
                + EMAIL_OTP + "%3ALOCAL&sp=app";
        String threeOptionsLast = PAGE_URL + "&authenticators=" + SMS_OTP + "%3ALOCAL%3B" + TOTP + "%3ALOCAL%3B"
                + EMAIL_OTP + "%3ALOCAL";
        String decodedSeparators = PAGE_URL + "&authenticators=" + SMS_OTP + ":LOCAL;" + TOTP + ":LOCAL&sp=app";
        String noOptionList = PAGE_URL + "&sp=app";
        String federated = PAGE_URL + "&authenticators=GoogleOIDCAuthenticator%3AGoogle%3B" + TOTP + "%3ALOCAL";

        return new Object[][] {
                {"Keeps the URI when its options are the options of the current step",
                        threeOptions, new String[] {SMS_OTP, TOTP, EMAIL_OTP}, true},
                {"Drops the URI when the script narrowed the current step to a single option",
                        threeOptions, new String[] {EMAIL_OTP}, false},
                {"Drops the URI when the current step dropped one of the options",
                        threeOptions, new String[] {SMS_OTP, TOTP}, false},
                {"Drops the URI when the current step has an option the URI does not carry",
                        threeOptions, new String[] {SMS_OTP, TOTP, EMAIL_OTP, "backup-code-authenticator"}, false},
                {"Keeps the URI when the options match ignoring case and order",
                        threeOptions, new String[] {"TOTP", EMAIL_OTP.toUpperCase(), SMS_OTP}, true},
                {"Keeps the URI when the option list is the last query param",
                        threeOptionsLast, new String[] {SMS_OTP, TOTP, EMAIL_OTP}, true},
                {"Keeps the URI when the option list separators are not percent encoded",
                        decodedSeparators, new String[] {SMS_OTP, TOTP}, true},
                {"Drops the URI with unencoded separators when the options do not match",
                        decodedSeparators, new String[] {EMAIL_OTP}, false},
                {"Keeps the URI when it carries no option list",
                        noOptionList, new String[] {EMAIL_OTP}, true},
                {"Keeps the URI when a federated option matches by authenticator name",
                        federated, new String[] {"GoogleOIDCAuthenticator", TOTP}, true},
                {"Keeps the URI when the current step cannot be resolved",
                        threeOptions, null, true},
        };
    }

    @Test(dataProvider = "multiOptionURIData",
            description = "getMultiOptionURIQueryString keeps the URI only when it is for the current step")
    public void testGetMultiOptionURIQueryStringForCurrentStep(String scenario, String multiOptionURI,
                                                               String[] stepOptions, boolean expectKept) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(MULTI_OPTION_URI)).thenReturn(multiOptionURI);
        AuthenticationContext context = contextWithCurrentStepOptions(stepOptions);

        String result = AuthenticatorUtils.getMultiOptionURIQueryString(request, context);

        if (expectKept) {
            Assert.assertTrue(result.startsWith(MULTI_OPTION_URI_PARAM), scenario);
            Assert.assertTrue(result.length() > MULTI_OPTION_URI_PARAM.length(), scenario);
        } else {
            Assert.assertEquals(result, "", scenario);
        }
    }

    @Test(description = "getMultiOptionURIQueryString returns empty when the request carries no multi option URI")
    public void testGetMultiOptionURIQueryStringWithoutParam() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(MULTI_OPTION_URI)).thenReturn(null);

        Assert.assertEquals(AuthenticatorUtils.getMultiOptionURIQueryString(request,
                contextWithCurrentStepOptions(EMAIL_OTP)), "");
    }

    @Test(description = "getMultiOptionURIQueryString returns empty when the request is null")
    public void testGetMultiOptionURIQueryStringWithNullRequest() {

        Assert.assertEquals(AuthenticatorUtils.getMultiOptionURIQueryString(null,
                contextWithCurrentStepOptions(EMAIL_OTP)), "");
    }

    @Test(description = "getMultiOptionURIQueryString keeps an empty multi option URI as it was handled before")
    public void testGetMultiOptionURIQueryStringWithBlankURI() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(MULTI_OPTION_URI)).thenReturn("");

        Assert.assertEquals(AuthenticatorUtils.getMultiOptionURIQueryString(request,
                contextWithCurrentStepOptions(EMAIL_OTP)), MULTI_OPTION_URI_PARAM);
    }

    @Test(description = "getMultiOptionURIQueryString keeps the URI when no context is given")
    public void testGetMultiOptionURIQueryStringWithNullContext() {

        String multiOptionURI = PAGE_URL + "&authenticators=" + SMS_OTP + "%3ALOCAL%3B" + TOTP + "%3ALOCAL";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(MULTI_OPTION_URI)).thenReturn(multiOptionURI);

        Assert.assertTrue(AuthenticatorUtils.getMultiOptionURIQueryString(request, null)
                .startsWith(MULTI_OPTION_URI_PARAM));
    }

    @Test(description = "The request only overload keeps the multi option URI as it was handled before")
    public void testGetMultiOptionURIQueryStringRequestOnlyOverloadIsUnchanged() {

        String multiOptionURI = PAGE_URL + "&authenticators=" + SMS_OTP + "%3ALOCAL%3B" + TOTP + "%3ALOCAL";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(MULTI_OPTION_URI)).thenReturn(multiOptionURI);

        Assert.assertTrue(AuthenticatorUtils.getMultiOptionURIQueryString(request)
                .startsWith(MULTI_OPTION_URI_PARAM));
        Assert.assertEquals(AuthenticatorUtils.getMultiOptionURIQueryString(request),
                AuthenticatorUtils.getMultiOptionURIQueryString(request,
                        contextWithCurrentStepOptions(SMS_OTP, TOTP)));
    }
}
