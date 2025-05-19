/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.authentication.rememberme;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;

/**
 * {@link RememberMeServices} implementation based on Barry Jaspan's
 * <a href="http://jaspan.com/improved_persistent_login_cookie_best_practice">Improved
 * Persistent Login Cookie Best Practice</a>.
 *
 * There is a slight modification to the described approach, in that the username is not
 * stored as part of the cookie but obtained from the persistent store via an
 * implementation of {@link PersistentTokenRepository}. The latter should place a unique
 * constraint on the series identifier, so that it is impossible for the same identifier
 * to be allocated to two different users.
 *
 * <p>
 * User management such as changing passwords, removing users and setting user status
 * should be combined with maintenance of the user's persistent tokens.
 * </p>
 *
 * <p>
 * Note that while this class will use the date a token was created to check whether a
 * presented cookie is older than the configured <tt>tokenValiditySeconds</tt> property
 * and deny authentication in this case, it will not delete these tokens from storage. A
 * suitable batch process should be run periodically to remove expired tokens from the
 * database.
 * </p>
 *
 * <p>
 * 此类通过在 {@link AbstractAuthenticationProcessingFilter} 等过滤器身份认证成功时，持久化一个 {@link PersistentRememberMeToken}
 * 并将其放入 Cookie 中。执行 RememberMe 自动登录时，通过比较 Cookie 中的 Token 和 持久化的 Token，
 * 若一致则调用 {@link UserDetailsService} 获取 UserDetails 进行认证。
 * <p>
 * 用户管理，如更改密码、删除用户和设置用户状态时，需要联动持久化的 Token。
 * <p>
 * 注意，虽然使用创建 Token 的日期来检查是否已过期，但不会从存储中删除这些 Token。需要定期运行批处理以从数据库中删除已过期 Token。
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices {

	private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();

	private SecureRandom random;

	public static final int DEFAULT_SERIES_LENGTH = 16;

	public static final int DEFAULT_TOKEN_LENGTH = 16;

	private int seriesLength = DEFAULT_SERIES_LENGTH;

	private int tokenLength = DEFAULT_TOKEN_LENGTH;

	public PersistentTokenBasedRememberMeServices(String key, UserDetailsService userDetailsService,
			PersistentTokenRepository tokenRepository) {
		super(key, userDetailsService);
		this.random = new SecureRandom();
		this.tokenRepository = tokenRepository;
	}

	/**
	 * Locates the presented cookie data in the token repository, using the series id. If
	 * the data compares successfully with that in the persistent store, a new token is
	 * generated and stored with the same series. The corresponding cookie value is set on
	 * the response.
	 * @param cookieTokens the series and token values
	 * @throws RememberMeAuthenticationException if there is no stored token corresponding
	 * to the submitted cookie, or if the token in the persistent store has expired.
	 * @throws InvalidCookieException if the cookie doesn't have two tokens as expected.
	 * @throws CookieTheftException if a presented series value is found, but the stored
	 * token is different from the one presented.
	 */
	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) {

		// Cookie 中有且只能有两个 Series 和 Token 俩个数据
		if (cookieTokens.length != 2) {
			throw new InvalidCookieException("Cookie token did not contain " + 2 + " tokens, but contained '"
					+ Arrays.asList(cookieTokens) + "'");
		}

		// 验证 Cookie 中的 Series 和 Token 是否与持久化 Token 匹配
		String presentedSeries = cookieTokens[0];
		String presentedToken = cookieTokens[1];
		PersistentRememberMeToken token = this.tokenRepository.getTokenForSeries(presentedSeries);

		// 根据 Series 找不到持久化的 Token，则抛出 RememberMeAuthenticationException 异常
		if (token == null) {
			// No series match, so we can't authenticate using this cookie
			throw new RememberMeAuthenticationException("No persistent token found for series id: " + presentedSeries);
		}

		// 找到了 Token 但不匹配，说明遇到了 Cookie 窃取攻击，需要清除所有已持久化的 Token
		// We have a match for this user/series combination
		if (!presentedToken.equals(token.getTokenValue())) {
			// Token doesn't match series value. Delete all logins for this user and throw
			// an exception to warn them.
			this.tokenRepository.removeUserTokens(token.getUsername());
			throw new CookieTheftException(this.messages.getMessage(
					"PersistentTokenBasedRememberMeServices.cookieStolen",
					"Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
		}

		// 如果 Token 匹配但是过期了，抛出 RememberMeAuthenticationException 异常
		if (token.getDate().getTime() + getTokenValiditySeconds() * 1000L < System.currentTimeMillis()) {
			throw new RememberMeAuthenticationException("Remember-me login has expired");
		}
		// Token also matches, so login is valid. Update the token value, keeping the
		// *same* series number.
		this.logger.debug(LogMessage.format("Refreshing persistent login token for user '%s', series '%s'",
				token.getUsername(), token.getSeries()));

		// Token 验证成功，需要更新 Token 以及创建时间，并更新 Cookie
		PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(), token.getSeries(),
				generateTokenData(), new Date());
		try {
			this.tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(), newToken.getDate());
			addCookie(newToken, request, response);
		}
		catch (Exception ex) {
			this.logger.error("Failed to update token: ", ex);
			throw new RememberMeAuthenticationException("Autologin failed due to data access problem");
		}

		// 验证成功，返回 UserDetails
		return getUserDetailsService().loadUserByUsername(token.getUsername());
	}

	/**
	 * Creates a new persistent login token with a new series number, stores the data in
	 * the persistent token repository and adds the corresponding cookie to the response.
	 *
	 * <p>
	 * 只有需要 RememberMe 时，才会执行此方法
	 * <p>
	 * 身份认证成功时调用此方法，生成 PersistentRememberMeToken 并持久化
	 */
	@Override
	protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication) {
		String username = successfulAuthentication.getName();
		this.logger.debug(LogMessage.format("Creating new persistent login for user %s", username));
		// 随机生成 Series、Token（均使用 Base64 编码），创建 PersistentRememberMeToken
		PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(username, generateSeriesData(),
				generateTokenData(), new Date());
		try {
			// 使用 PersistentTokenRepository 持久化保存 Token
			this.tokenRepository.createNewToken(persistentToken);
			// Cookie 过期时间默认俩周，过期时间在父类 AbstractRememberMeServices 中设置
			addCookie(persistentToken, request, response);
		}
		catch (Exception ex) {
			this.logger.error("Failed to save persistent token ", ex);
		}
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		// 父类 AbstractRememberMeServices 在执行登出时，会清理 RememberMe Cookie
		super.logout(request, response, authentication);
		// 删除持久化的 Token
		if (authentication != null) {
			this.tokenRepository.removeUserTokens(authentication.getName());
		}
	}

	// 随机生成 Series 作为 PersistentRememberMeToken 主键
	protected String generateSeriesData() {
		// 默认 16 字节
		byte[] newSeries = new byte[this.seriesLength];
		// 生成默认 16 字节长度的随机数
		this.random.nextBytes(newSeries);
		// 将随机数转换为 Base64 字符串
		return new String(Base64.getEncoder().encode(newSeries));
	}

	// 随机生成 Token
	protected String generateTokenData() {
		byte[] newToken = new byte[this.tokenLength];
		this.random.nextBytes(newToken);
		return new String(Base64.getEncoder().encode(newToken));
	}

	private void addCookie(PersistentRememberMeToken token, HttpServletRequest request, HttpServletResponse response) {
		setCookie(new String[] { token.getSeries(), token.getTokenValue() }, getTokenValiditySeconds(), request,
				response);
	}

	public void setSeriesLength(int seriesLength) {
		this.seriesLength = seriesLength;
	}

	public void setTokenLength(int tokenLength) {
		this.tokenLength = tokenLength;
	}

	@Override
	public void setTokenValiditySeconds(int tokenValiditySeconds) {
		Assert.isTrue(tokenValiditySeconds > 0, "tokenValiditySeconds must be positive for this implementation");
		super.setTokenValiditySeconds(tokenValiditySeconds);
	}

}
