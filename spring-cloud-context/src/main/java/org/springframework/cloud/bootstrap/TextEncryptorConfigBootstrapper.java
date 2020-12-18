/*
 * Copyright 2012-2020 the original author or authors.
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

package org.springframework.cloud.bootstrap;

import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.BootstrapContext;
import org.springframework.boot.BootstrapRegistry;
import org.springframework.boot.Bootstrapper;
import org.springframework.boot.context.properties.bind.BindHandler;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.autoconfigure.EncryptionBootstrapAutoConfiguration;
import org.springframework.cloud.bootstrap.TextEncryptorConfigurationPropertiesBindHandlerAdvisor.TextEncryptorBindHandler;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.bootstrap.encrypt.RsaProperties;
import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * Bootstrapper.
 *
 * @author Marcin Grzejszczak
 * @since 3.0.0
 */
public class TextEncryptorConfigBootstrapper implements Bootstrapper {

	@Override
	public void intitialize(BootstrapRegistry registry) {
		if (!ClassUtils.isPresent("org.springframework.security.crypto.encrypt.TextEncryptor", null)) {
			return;
		}

		registry.registerIfAbsent(KeyProperties.class, context -> context.get(Binder.class)
				.bind("encrypt", KeyProperties.class).orElseGet(KeyProperties::new));
		registry.registerIfAbsent(RsaProperties.class, context -> context.get(Binder.class)
				.bind("encrypt.rsa", RsaProperties.class).orElseGet(RsaProperties::new));
		registry.registerIfAbsent(TextEncryptor.class, context -> {
			KeyProperties keyProperties = context.get(KeyProperties.class);
			if (keysConfigured(keyProperties)) {
				if (ClassUtils.isPresent("org.springframework.security.rsa.crypto.RsaSecretEncryptor", null)) {
					RsaProperties rsaProperties = context.get(RsaProperties.class);
					return EncryptionBootstrapAutoConfiguration.rsaTextEncryptor(keyProperties, rsaProperties);
				}
				return new EncryptorFactory(keyProperties.getSalt()).create(keyProperties.getKey());
			}
			// no keys configured
			return new FailsafeTextEncryptor();
		});
		registry.registerIfAbsent(BindHandler.class, context -> {
			TextEncryptor textEncryptor = context.get(TextEncryptor.class);
			if (textEncryptor != null) {
				KeyProperties keyProperties = context.get(KeyProperties.class);
				return new TextEncryptorBindHandler(textEncryptor, keyProperties);
			}
			return null;
		});

		// promote beans to context
		registry.addCloseListener(event -> {
			if (isLegacyBootstrap(event.getApplicationContext().getEnvironment())) {
				return;
			}
			BootstrapContext bootstrapContext = event.getBootstrapContext();
			KeyProperties keyProperties = bootstrapContext.get(KeyProperties.class);
			ConfigurableListableBeanFactory beanFactory = event.getApplicationContext().getBeanFactory();
			if (keyProperties != null) {
				beanFactory.registerSingleton("keyProperties", keyProperties);
			}
			RsaProperties rsaProperties = bootstrapContext.get(RsaProperties.class);
			if (rsaProperties != null) {
				beanFactory.registerSingleton("rsaProperties", rsaProperties);
			}
			TextEncryptor textEncryptor = bootstrapContext.get(TextEncryptor.class);
			if (textEncryptor != null) {
				beanFactory.registerSingleton("textEncryptor", textEncryptor);
			}
		});
	}

	private boolean keysConfigured(KeyProperties properties) {
		if (hasProperty(properties.getKeyStore().getLocation())) {
			if (hasProperty(properties.getKeyStore().getPassword())) {
				return true;
			}
			return false;
		}
		else if (hasProperty(properties.getKey())) {
			return true;
		}
		return false;
	}

	private boolean hasProperty(Object value) {
		if (value instanceof String) {
			return StringUtils.hasText((String) value);
		}
		return value != null;
	}

	private boolean isLegacyBootstrap(Environment environment) {
		boolean isLegacy = environment.getProperty("spring.config.use-legacy-processing", Boolean.class, false);
		boolean isBootstrapEnabled = environment.getProperty("spring.cloud.bootstrap.enabled", Boolean.class, false);
		return isLegacy || isBootstrapEnabled;
	}

	/**
	 * TextEncryptor that just fails, so that users don't get a false sense of security
	 * adding ciphers to config files and not getting them decrypted.
	 *
	 * @author Dave Syer
	 *
	 */
	protected static class FailsafeTextEncryptor implements TextEncryptor {

		@Override
		public String encrypt(String text) {
			throw new UnsupportedOperationException(
					"No encryption for FailsafeTextEncryptor. Did you configure the keystore correctly?");
		}

		@Override
		public String decrypt(String encryptedText) {
			throw new UnsupportedOperationException(
					"No decryption for FailsafeTextEncryptor. Did you configure the keystore correctly?");
		}

	}

}
