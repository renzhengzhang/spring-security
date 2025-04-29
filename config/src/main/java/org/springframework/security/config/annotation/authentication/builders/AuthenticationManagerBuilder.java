/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.builders;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsAwareConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.util.Assert;

/**
 * {@link SecurityBuilder} used to create an {@link AuthenticationManager}. Allows for
 * easily building in memory authentication, LDAP authentication, JDBC based
 * authentication, adding {@link UserDetailsService}, and adding
 * {@link AuthenticationProvider}'s.
 *
 * <p>
 * 支持基于 parent AuthenticationManager 和 {@link AuthenticationProvider} 来构建 {@link ProviderManager}
 * <p>
 * 提供 {@link AuthenticationManagerBuilder#inMemoryAuthentication()} 来使用 {@link InMemoryUserDetailsManager}
 * 作为 {@link ProviderManagerBuilder} 中 {@link DaoAuthenticationProvider} 的 {@link UserDetailsService}
 * <p>
 * 提供 {@link AuthenticationManagerBuilder#jdbcAuthentication()} 来使用 {@link JdbcUserDetailsManager}
 * 作为 {@link ProviderManagerBuilder} 中 {@link DaoAuthenticationProvider} 的 {@link UserDetailsService}
 * <p>
 * 提供 {@link AuthenticationManagerBuilder#userDetailsService(UserDetailsService)} 来使用传入的 UserDetailsService
 * 作为 {@link ProviderManagerBuilder} 中 {@link DaoAuthenticationProvider} 的 {@link UserDetailsService}
 *
 * @author Rob Winch
 * @since 3.2
 */
public class AuthenticationManagerBuilder
		extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder>
		implements ProviderManagerBuilder<AuthenticationManagerBuilder> {

	private final Log logger = LogFactory.getLog(getClass());

	private AuthenticationManager parentAuthenticationManager;

	private List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private UserDetailsService defaultUserDetailsService;

	private Boolean eraseCredentials;

	private AuthenticationEventPublisher eventPublisher;

	/**
	 * Creates a new instance
	 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
	 */
	public AuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor, true);
	}

	/**
	 * Allows providing a parent {@link AuthenticationManager} that will be tried if this
	 * {@link AuthenticationManager} was unable to attempt to authenticate the provided
	 * {@link Authentication}.
	 * @param authenticationManager the {@link AuthenticationManager} that should be used
	 * if the current {@link AuthenticationManager} was unable to attempt to authenticate
	 * the provided {@link Authentication}.
	 * @return the {@link AuthenticationManagerBuilder} for further adding types of
	 * authentication
	 */
	public AuthenticationManagerBuilder parentAuthenticationManager(AuthenticationManager authenticationManager) {
		// 配置 parent AuthenticationManager，≈ eraseCredentials 与 parent 保持一致
		if (authenticationManager instanceof ProviderManager) {
			eraseCredentials(((ProviderManager) authenticationManager).isEraseCredentialsAfterAuthentication());
		}
		this.parentAuthenticationManager = authenticationManager;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationEventPublisher}
	 * @param eventPublisher the {@link AuthenticationEventPublisher} to use
	 * @return the {@link AuthenticationManagerBuilder} for further customizations
	 */
	public AuthenticationManagerBuilder authenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
		// 配置 AuthenticationEventPublisher
		Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
		return this;
	}

	/**
	 * @param eraseCredentials true if {@link AuthenticationManager} should clear the
	 * credentials from the {@link Authentication} object after authenticating
	 * @return the {@link AuthenticationManagerBuilder} for further customizations
	 */
	public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
		// 配置是否需要清空 Authentication 中的 Credentials
		this.eraseCredentials = eraseCredentials;
		return this;
	}

	/**
	 * Add in memory authentication to the {@link AuthenticationManagerBuilder} and return
	 * a {@link InMemoryUserDetailsManagerConfigurer} to allow customization of the in
	 * memory authentication.
	 *
	 * <p>
	 * This method also ensure that a {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default.
	 * </p>
	 * @return a {@link InMemoryUserDetailsManagerConfigurer} to allow customization of
	 * the in memory authentication
	 * @throws Exception if an error occurs when adding the in memory authentication
	 */
	public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
			throws Exception {
		// 1. 使用 InMemoryUserDetailsManager 作为 ProviderManagerBuilder 中 DaoAuthenticationProvider 的 UserDetailsService，
		//    支持在 UserDetailsManager 初始化一些用户
		// 2. 配置 InMemoryUserDetailsManagerConfigurer，并将其添加至 configurers 中
		return apply(new InMemoryUserDetailsManagerConfigurer<>());
	}

	/**
	 * Add JDBC authentication to the {@link AuthenticationManagerBuilder} and return a
	 * {@link JdbcUserDetailsManagerConfigurer} to allow customization of the JDBC
	 * authentication.
	 *
	 * <p>
	 * When using with a persistent data store, it is best to add users external of
	 * configuration using something like <a href="https://flywaydb.org/">Flyway</a> or
	 * <a href="https://www.liquibase.org/">Liquibase</a> to create the schema and adding
	 * users to ensure these steps are only done once and that the optimal SQL is used.
	 * </p>
	 *
	 * <p>
	 * This method also ensure that a {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default. See the <a href=
	 * "https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#user-schema"
	 * >User Schema</a> section of the reference for the default schema.
	 * </p>
	 * @return a {@link JdbcUserDetailsManagerConfigurer} to allow customization of the
	 * JDBC authentication
	 * @throws Exception if an error occurs when adding the JDBC authentication
	 */
	public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() throws Exception {
		// 1. 使用 JdbcUserDetailsManager 作为 ProviderManagerBuilder 中 DaoAuthenticationProvider 的 UserDetailsService
		// 2. 配置 JdbcUserDetailsManagerConfigurer，并将其添加至 configurers 中
		return apply(new JdbcUserDetailsManagerConfigurer<>());
	}

	/**
	 * Add authentication based upon the custom {@link UserDetailsService} that is passed
	 * in. It then returns a {@link DaoAuthenticationConfigurer} to allow customization of
	 * the authentication.
	 *
	 * <p>
	 * This method also ensure that the {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default.
	 * </p>
	 * @return a {@link DaoAuthenticationConfigurer} to allow customization of the DAO
	 * authentication
	 * @throws Exception if an error occurs when adding the {@link UserDetailsService}
	 * based authentication
	 */
	public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
			T userDetailsService) throws Exception {
		// 1. 使用 userDetailsService 作为 ProviderManagerBuilder 中 DaoAuthenticationProvider 的 UserDetailsService
		// 2. 配置 DaoAuthenticationConfigurer，并将其添加至 configurers 中
		this.defaultUserDetailsService = userDetailsService;
		return apply(new DaoAuthenticationConfigurer<>(userDetailsService));
	}

	/**
	 * Add LDAP authentication to the {@link AuthenticationManagerBuilder} and return a
	 * {@link LdapAuthenticationProviderConfigurer} to allow customization of the LDAP
	 * authentication.
	 *
	 * <p>
	 * This method <b>does NOT</b> ensure that a {@link UserDetailsService} is available
	 * for the {@link #getDefaultUserDetailsService()} method.
	 * @return a {@link LdapAuthenticationProviderConfigurer} to allow customization of
	 * the LDAP authentication
	 * @throws Exception if an error occurs when adding the LDAP authentication
	 */
	public LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthentication() throws Exception {
		return apply(new LdapAuthenticationProviderConfigurer<>());
	}

	/**
	 * Add authentication based upon the custom {@link AuthenticationProvider} that is
	 * passed in. Since the {@link AuthenticationProvider} implementation is unknown, all
	 * customizations must be done externally and the {@link AuthenticationManagerBuilder}
	 * is returned immediately.
	 *
	 * <p>
	 * This method <b>does NOT</b> ensure that the {@link UserDetailsService} is available
	 * for the {@link #getDefaultUserDetailsService()} method.
	 *
	 * Note that an {@link Exception} might be thrown if an error occurs when adding the
	 * {@link AuthenticationProvider}.
	 * @return a {@link AuthenticationManagerBuilder} to allow further authentication to
	 * be provided to the {@link AuthenticationManagerBuilder}
	 */
	@Override
	public AuthenticationManagerBuilder authenticationProvider(AuthenticationProvider authenticationProvider) {
		// 添加 AuthenticationProvider
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	@Override
	protected ProviderManager performBuild() throws Exception {
		// 要么配置 parent AuthenticationManager，要么配置 authenticationProviders
		if (!isConfigured()) {
			this.logger.debug("No authenticationProviders and no parentAuthenticationManager defined. Returning null.");
			return null;
		}

		// 基于 parent AuthenticationManager 和 authenticationProviders 构建 ProviderManager
		ProviderManager providerManager = new ProviderManager(this.authenticationProviders,
				this.parentAuthenticationManager);

		// 配置 ProviderManager 的 eraseCredentials 和 eventPublisher
		if (this.eraseCredentials != null) {
			providerManager.setEraseCredentialsAfterAuthentication(this.eraseCredentials);
		}
		if (this.eventPublisher != null) {
			providerManager.setAuthenticationEventPublisher(this.eventPublisher);
		}

		// 进行后处理
		providerManager = postProcess(providerManager);
		return providerManager;
	}

	/**
	 * Determines if the {@link AuthenticationManagerBuilder} is configured to build a non
	 * null {@link AuthenticationManager}. This means that either a non-null parent is
	 * specified or at least one {@link AuthenticationProvider} has been specified.
	 *
	 * <p>
	 * When using {@link SecurityConfigurer} instances, the
	 * {@link AuthenticationManagerBuilder} will not be configured until the
	 * {@link SecurityConfigurer#configure(SecurityBuilder)} methods. This means a
	 * {@link SecurityConfigurer} that is last could check this method and provide a
	 * default configuration in the {@link SecurityConfigurer#configure(SecurityBuilder)}
	 * method.
	 * @return true, if {@link AuthenticationManagerBuilder} is configured, otherwise
	 * false
	 */
	public boolean isConfigured() {
		return !this.authenticationProviders.isEmpty() || this.parentAuthenticationManager != null;
	}

	/**
	 * Gets the default {@link UserDetailsService} for the
	 * {@link AuthenticationManagerBuilder}. The result may be null in some circumstances.
	 * @return the default {@link UserDetailsService} for the
	 * {@link AuthenticationManagerBuilder}
	 */
	public UserDetailsService getDefaultUserDetailsService() {
		return this.defaultUserDetailsService;
	}

	/**
	 * Captures the {@link UserDetailsService} from any {@link UserDetailsAwareConfigurer}
	 * .
	 * @param configurer the {@link UserDetailsAwareConfigurer} to capture the
	 * {@link UserDetailsService} from.
	 * @return the {@link UserDetailsAwareConfigurer} for further customizations
	 * @throws Exception if an error occurs
	 */
	private <C extends UserDetailsAwareConfigurer<AuthenticationManagerBuilder, ? extends UserDetailsService>> C apply(
			C configurer) throws Exception {
		// 从 UserDetailsAwareConfigurer 中获取 UserDetailsService，将 UserDetailsService 设置到 defaultUserDetailsService
		this.defaultUserDetailsService = configurer.getUserDetailsService();
		// 配置 UserDetailsAwareConfigurer，并将其添加至 configurers 中
		return super.apply(configurer);
	}

}
