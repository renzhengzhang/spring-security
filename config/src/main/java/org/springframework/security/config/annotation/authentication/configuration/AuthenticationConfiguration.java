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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.AbstractDaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * Exports the authentication {@link Configuration}
 *
 * <p>
 * 向 {@link ApplicationContext} 中注册 {@link DefaultPasswordEncoderAuthenticationManagerBuilder}
 * 作为 AuthenticationManagerBuilder。这个 AuthenticationManagerBuilder 可以被其各类 SecurityConfigurer 从 {@link ApplicationContext} 中
 * 获取 UserDetailsService、PasswordEncoder、DaoAuthenticationProvider、AuthenticationProvider 来配置 AuthenticationManagerBuilder
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@Configuration(proxyBeanMethods = false)
@Import(ObjectPostProcessorConfiguration.class)
public class AuthenticationConfiguration {

	// 表示使用 ApplicationContext 中的 AuthenticationManagerBuilder 构建 AuthenticationManager
	private AtomicBoolean buildingAuthenticationManager = new AtomicBoolean();

	private ApplicationContext applicationContext;

	private AuthenticationManager authenticationManager;

	private boolean authenticationManagerInitialized;

	private List<GlobalAuthenticationConfigurerAdapter> globalAuthConfigurers = Collections.emptyList();

	private ObjectPostProcessor<Object> objectPostProcessor;

	/**
	 * 向 ApplicationContext 中注册 {@link DefaultPasswordEncoderAuthenticationManagerBuilder} 作为 AuthenticationManagerBuilder。
	 * 这个 AuthenticationManagerBuilder 可以被其各类 SecurityConfigurer 从 {@link ApplicationContext} 中
	 * 获取 UserDetailsService、PasswordEncoder、DaoAuthenticationProvider、AuthenticationProvider 来配置 AuthenticationManagerBuilder
	 */
	@Bean
	public AuthenticationManagerBuilder authenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
			ApplicationContext context) {
		LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
		AuthenticationEventPublisher authenticationEventPublisher = getAuthenticationEventPublisher(context);
		DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				objectPostProcessor, defaultPasswordEncoder);
		if (authenticationEventPublisher != null) {
			result.authenticationEventPublisher(authenticationEventPublisher);
		}
		return result;
	}

	@Bean
	public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(
			ApplicationContext context) {
		return new EnableGlobalAuthenticationAutowiredConfigurer(context);
	}


	/**
	 * 如果 {@link AuthenticationManagerBuilder} 中还没有配置 authenticationProviders 以及 parentAuthenticationManager，
	 * 则 {@link InitializeUserDetailsBeanManagerConfigurer} 会从 {@link ApplicationContext} 中
	 * 取 {@link AuthenticationProvider} 放入 {@link AuthenticationManagerBuilder}
	 */
	@Bean
	public static InitializeUserDetailsBeanManagerConfigurer initializeUserDetailsBeanManagerConfigurer(
			ApplicationContext context) {
		return new InitializeUserDetailsBeanManagerConfigurer(context);
	}

	/**
	 * 如果 {@link AuthenticationManagerBuilder} 中还没有配置 authenticationProviders 以及 parentAuthenticationManager，
	 * 则 {@link InitializeUserDetailsBeanManagerConfigurer} 会从 {@link ApplicationContext} 中取 {@link UserDetailsService}、
	 * {@link PasswordEncoder} 自动配置 {@link DaoAuthenticationProvider} 到 {@link AuthenticationManagerBuilder}
	 */
	@Bean
	public static InitializeAuthenticationProviderBeanManagerConfigurer initializeAuthenticationProviderBeanManagerConfigurer(
			ApplicationContext context) {
		return new InitializeAuthenticationProviderBeanManagerConfigurer(context);
	}


	/**
	 * 返回从 ApplicationContext 中获取 UserDetailsService、PasswordEncoder、DaoAuthenticationProvider、AuthenticationProvider
	 * 和 AuthenticationManager 来构建的 ProviderManager，HttpSecurityConfiguration#httpSecurity()
	 * 会调用此方法，来作为 parent AuthenticationManager
	 */
	public AuthenticationManager getAuthenticationManager() throws Exception {
		if (this.authenticationManagerInitialized) {
			return this.authenticationManager;
		}

		// 使用 ApplicationContext 中的 AuthenticationManagerBuilder 构建 AuthenticationManager
		// AuthenticationConfiguration.authenticationManagerBuilder() 会向 ApplicationContext 注册 AuthenticationManagerBuilder
		AuthenticationManagerBuilder authBuilder = this.applicationContext.getBean(AuthenticationManagerBuilder.class);

		// buildingAuthenticationManager 保证后面的逻辑只会调用一遍
		if (this.buildingAuthenticationManager.getAndSet(true)) {
			return new AuthenticationManagerDelegator(authBuilder);
		}

		// 将 globalAuthConfigurers 中的各个 SecurityConfigurer 加入到 AuthenticationManagerBuilder 中，并进行构建
		// 1. InitializeUserDetailsBeanManagerConfigurer
		//    支持从 ApplicationContext 获取 UserDetailsService、PasswordEncoder，初始化 DaoAuthenticationProvider
		// 2. InitializeAuthenticationProviderBeanManagerConfigurer
		//    支持从 ApplicationContext 获取 AuthenticationProvider，来配置 AuthenticationManager
		for (GlobalAuthenticationConfigurerAdapter config : this.globalAuthConfigurers) {
			authBuilder.apply(config);
		}
		this.authenticationManager = authBuilder.build();


		// AuthenticationManagerBuilder 没有构建出来，则从 ApplicationContext 中获取
		// AuthenticationManagerBuilder 没有配置 parent AuthenticationManager 和 authenticationProviders 是构建不出 AuthenticationManager 的
		if (this.authenticationManager == null) {
			this.authenticationManager = getAuthenticationManagerBean();
		}
		this.authenticationManagerInitialized = true;

		return this.authenticationManager;
	}

	@Autowired(required = false)
	public void setGlobalAuthenticationConfigurers(List<GlobalAuthenticationConfigurerAdapter> configurers) {
		configurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		this.globalAuthConfigurers = configurers;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	/**
	 * 从 ApplicationContext 中获取 AuthenticationEventPublisher <br>
	 * 如果不存在则创建一个，则实例化一个 DefaultAuthenticationEventPublisher
	 */
	private AuthenticationEventPublisher getAuthenticationEventPublisher(ApplicationContext context) {
		if (context.getBeanNamesForType(AuthenticationEventPublisher.class).length > 0) {
			return context.getBean(AuthenticationEventPublisher.class);
		}
		return this.objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
	}

	@SuppressWarnings("unchecked")
	private <T> T lazyBean(Class<T> interfaceName) {
		LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
		String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.applicationContext,
				interfaceName);
		if (beanNamesForType.length == 0) {
			return null;
		}
		String beanName = getBeanName(interfaceName, beanNamesForType);
		lazyTargetSource.setTargetBeanName(beanName);
		lazyTargetSource.setBeanFactory(this.applicationContext);
		ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
		proxyFactory = this.objectPostProcessor.postProcess(proxyFactory);
		proxyFactory.setTargetSource(lazyTargetSource);
		return (T) proxyFactory.getObject();
	}

	private <T> String getBeanName(Class<T> interfaceName, String[] beanNamesForType) {
		if (beanNamesForType.length == 1) {
			return beanNamesForType[0];
		}
		List<String> primaryBeanNames = getPrimaryBeanNames(beanNamesForType);
		Assert.isTrue(primaryBeanNames.size() != 0, () -> "Found " + beanNamesForType.length + " beans for type "
				+ interfaceName + ", but none marked as primary");
		Assert.isTrue(primaryBeanNames.size() == 1,
				() -> "Found " + primaryBeanNames.size() + " beans for type " + interfaceName + " marked as primary");
		return primaryBeanNames.get(0);
	}

	private List<String> getPrimaryBeanNames(String[] beanNamesForType) {
		List<String> list = new ArrayList<>();
		if (!(this.applicationContext instanceof ConfigurableApplicationContext)) {
			return Collections.emptyList();
		}
		for (String beanName : beanNamesForType) {
			if (((ConfigurableApplicationContext) this.applicationContext).getBeanFactory()
				.getBeanDefinition(beanName)
				.isPrimary()) {
				list.add(beanName);
			}
		}
		return list;
	}

	private AuthenticationManager getAuthenticationManagerBean() {
		return lazyBean(AuthenticationManager.class);
	}

	private static <T> T getBeanOrNull(ApplicationContext applicationContext, Class<T> type) {
		try {
			return applicationContext.getBean(type);
		}
		catch (NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	private static class EnableGlobalAuthenticationAutowiredConfigurer extends GlobalAuthenticationConfigurerAdapter {

		private final ApplicationContext context;

		private static final Log logger = LogFactory.getLog(EnableGlobalAuthenticationAutowiredConfigurer.class);

		EnableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
			this.context = context;
		}

		@Override
		public void init(AuthenticationManagerBuilder auth) {
			Map<String, Object> beansWithAnnotation = this.context
				.getBeansWithAnnotation(EnableGlobalAuthentication.class);
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Eagerly initializing %s", beansWithAnnotation));
			}
		}

	}

	/**
	 * Prevents infinite recursion in the event that initializing the
	 * AuthenticationManager.
	 *
	 * @author Rob Winch
	 * @since 4.1.1
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {

		private AuthenticationManagerBuilder delegateBuilder;

		private AuthenticationManager delegate;

		private final Object delegateMonitor = new Object();

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			this.delegateBuilder = delegateBuilder;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (this.delegate != null) {
				return this.delegate.authenticate(authentication);
			}
			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					this.delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}
			return this.delegate.authenticate(authentication);
		}

		@Override
		public String toString() {
			return "AuthenticationManagerDelegator [delegate=" + this.delegate + "]";
		}

	}


	/**
	 * 为 {@link AbstractDaoAuthenticationConfigurer} 提供快速配置的 {@link PasswordEncoder} 的能力
	 */
	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {

		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
				PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
				throws Exception {
			return super.inMemoryAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() throws Exception {
			return super.jdbcAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
				T userDetailsService) throws Exception {
			return super.userDetailsService(userDetailsService).passwordEncoder(this.defaultPasswordEncoder);
		}

	}

	/**
	 * 从 ApplicationContext 中懒加载 PasswordEncoder。<br>
	 * 如果 ApplicationContext 中没有，则使用 PasswordEncoderFactories.createDelegatingPasswordEncoder() 创建一个
	 */
	static class LazyPasswordEncoder implements PasswordEncoder {

		private ApplicationContext applicationContext;

		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		private PasswordEncoder getPasswordEncoder() {
			if (this.passwordEncoder != null) {
				return this.passwordEncoder;
			}
			PasswordEncoder passwordEncoder = getBeanOrNull(this.applicationContext, PasswordEncoder.class);
			if (passwordEncoder == null) {
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}

	}

}
