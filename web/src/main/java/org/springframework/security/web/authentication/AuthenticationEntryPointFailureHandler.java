/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * Adapts a {@link AuthenticationEntryPoint} into a {@link AuthenticationFailureHandler}
 *
 * <p>
 * AbstractAuthenticationProcessingFilter 身份认证失败之后，依据是否需要抛出异常，来判断是否交由 AuthenticationEntryPoint 处理
 * </p>
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public class AuthenticationEntryPointFailureHandler implements AuthenticationFailureHandler {

	// 默认需要重新抛出异常
	private boolean rethrowAuthenticationServiceException = true;

	private final AuthenticationEntryPoint authenticationEntryPoint;

	public AuthenticationEntryPointFailureHandler(AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		// 不需要需重新抛出异常，交由 AuthenticationEntryPoint 处理
		if (!this.rethrowAuthenticationServiceException) {
			this.authenticationEntryPoint.commence(request, response, exception);
			return;
		}

		// 非 AuthenticationServiceException、InternalAuthenticationServiceException 异常
		// 这里不抛出异常，交由 AuthenticationEntryPoint 处理
		if (!AuthenticationServiceException.class.isAssignableFrom(exception.getClass())) {
			this.authenticationEntryPoint.commence(request, response, exception);
			return;
		}

		// 若需要重新抛出异常，AuthenticationServiceException、InternalAuthenticationServiceException 异常，需要抛出
		throw exception;
	}

	/**
	 * Set whether to rethrow {@link AuthenticationServiceException}s (defaults to true)
	 * @param rethrowAuthenticationServiceException whether to rethrow
	 * {@link AuthenticationServiceException}s
	 * @since 5.8
	 */
	public void setRethrowAuthenticationServiceException(boolean rethrowAuthenticationServiceException) {
		this.rethrowAuthenticationServiceException = rethrowAuthenticationServiceException;
	}

}
