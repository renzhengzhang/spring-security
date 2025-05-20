/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.web;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.util.StringUtils;

/**
 * The default {@link BearerTokenResolver} implementation based on RFC 6750.
 *
 * <p>
 * 从请求 Header 或者 Parameters 中解析 Bearer Token
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750
 * Section 2: Authenticated Requests</a>
 */
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

	private static final String ACCESS_TOKEN_PARAMETER_NAME = "access_token";

	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private boolean allowFormEncodedBodyParameter = false;

	private boolean allowUriQueryParameter = false;

	private String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

	@Override
	public String resolve(final HttpServletRequest request) {
		// 从请求头中获取 Bearer Token
		final String authorizationHeaderToken = resolveFromAuthorizationHeader(request);
		// 从请求参数中获取 Bearer Token
		final String parameterToken = isParameterTokenSupportedForRequest(request)
				? resolveFromRequestParameters(request) : null;

		// 优先使用从请求头中获取获取的 Token
		if (authorizationHeaderToken != null) {
			if (parameterToken != null) {
				final BearerTokenError error = BearerTokenErrors
					.invalidRequest("Found multiple bearer tokens in the request");
				throw new OAuth2AuthenticationException(error);
			}
			return authorizationHeaderToken;
		}

		// 没有合法的 Authorization Header
		// 如果从请求参数中存在 access_token，并且允许使用，则使用从请求参数中获取的 Token
		if (parameterToken != null && isParameterTokenEnabledForRequest(request)) {
			return parameterToken;
		}
		return null;
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported.
	 * Defaults to {@code false}.
	 * @param allowFormEncodedBodyParameter if the form-encoded body parameter is
	 * supported
	 */
	public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
		this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults
	 * to {@code false}.
	 *
	 * The spec recommends against using this mechanism for sending bearer tokens, and
	 * even goes as far as stating that it was only included for completeness.
	 * @param allowUriQueryParameter if the URI query parameter is supported
	 */
	public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
		this.allowUriQueryParameter = allowUriQueryParameter;
	}

	/**
	 * Set this value to configure what header is checked when resolving a Bearer Token.
	 * This value is defaulted to {@link HttpHeaders#AUTHORIZATION}.
	 *
	 * This allows other headers to be used as the Bearer Token source such as
	 * {@link HttpHeaders#PROXY_AUTHORIZATION}
	 * @param bearerTokenHeaderName the header to check when retrieving the Bearer Token.
	 * @since 5.4
	 */
	public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
		this.bearerTokenHeaderName = bearerTokenHeaderName;
	}

	/**
	 * 使用正则表达式匹配 Request Header 中的 Bearer Token（header 名称为 Authorization）
	 */
	private String resolveFromAuthorizationHeader(HttpServletRequest request) {
		// 获取请求头中的 Authorization
		String authorization = request.getHeader(this.bearerTokenHeaderName);

		// 非 bearer 开头的 Header 内容忽略
		if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
			return null;
		}

		// 使用正则表达式捕获组获取其中的 Token
		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
			throw new OAuth2AuthenticationException(error);
		}
		return matcher.group("token");
	}

	/**
	 * 从 Request Parameters 中获取 Bearer Token（参数名为 access_token）
	 */
	private static String resolveFromRequestParameters(HttpServletRequest request) {
		String[] values = request.getParameterValues(ACCESS_TOKEN_PARAMETER_NAME);
		if (values == null || values.length == 0) {
			return null;
		}
		if (values.length == 1) {
			return values[0];
		}
		BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
		throw new OAuth2AuthenticationException(error);
	}

	/**
     * 判断是否支持使用 access_token 参数
     */
	private boolean isParameterTokenSupportedForRequest(final HttpServletRequest request) {
		return isFormEncodedRequest(request) || isGetRequest(request);
	}

	/**
	 * 判断是否为 GET 请求
	 */
	private static boolean isGetRequest(HttpServletRequest request) {
		return HttpMethod.GET.name().equals(request.getMethod());
	}

	/**
     * 判断是否为 POST 表单请求
	 */
	private static boolean isFormEncodedRequest(HttpServletRequest request) {
		return MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType());
	}

	/**
     * 判断是否包含 access_token 参数
     */
	private static boolean hasAccessTokenInQueryString(HttpServletRequest request) {
		return (request.getQueryString() != null) && request.getQueryString().contains(ACCESS_TOKEN_PARAMETER_NAME);
	}

	/**
	 * 判断是否允许使用 access_token 参数
	 */
	private boolean isParameterTokenEnabledForRequest(HttpServletRequest request) {
		// 以下这两种情况允许使用 access_token 参数
		// 1. allowFormEncodedBodyParameter 为 true、表单请求、非 GET 请求；
		// 2. allowUriQueryParameter 为 true、GET 请求
		return ((this.allowFormEncodedBodyParameter && isFormEncodedRequest(request) && !isGetRequest(request)
				&& !hasAccessTokenInQueryString(request)) || (this.allowUriQueryParameter && isGetRequest(request)));
	}

}
