/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationEntryPoint} that sends a generic {@link HttpStatus} as a
 * response. Useful for JavaScript clients which cannot use Basic authentication since the
 * browser intercepts the response.
 *
 * <p>
 * 身份认证失败时，返回一个固定的 HttpStatus
 * <p>
 * 用于 JavaScript 客户端，无法使用 BASIC 认证，因为浏览器拦截响应。
 * <p>
 * 在浏览器环境中，使用基本身份验证（Basic Authentication）时，浏览器会自动处理 HTTP 响应中的 WWW-Authenticate 头部。
 * 具体来说，当服务器返回状态码 401（未授权）并带有 WWW-Authenticate 头部时，浏览器会自动弹出一个对话框，要求用户输入用户名和密码。
 * 这种行为是浏览器内置的，并且无法通过 JavaScript 客户端进行控制或拦截。
 * <p>
 * 可以参见<a href="https://juejin.cn/post/7447881845860368420">这篇博客</a>。
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class HttpStatusEntryPoint implements AuthenticationEntryPoint {

	private final HttpStatus httpStatus;

	/**
	 * Creates a new instance.
	 * @param httpStatus the HttpStatus to set
	 */
	public HttpStatusEntryPoint(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		this.httpStatus = httpStatus;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) {
		response.setStatus(this.httpStatus.value());
	}

}
