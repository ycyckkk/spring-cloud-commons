/*
 * Copyright 2013-2020 the original author or authors.
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

package org.springframework.cloud.bootstrap.encrypt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.cloud.bootstrap.TextEncryptorConfigBootstrapper;
import org.springframework.cloud.bootstrap.TextEncryptorConfigBootstrapper.FailsafeTextEncryptor;
import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.core.Ordered;
import org.springframework.core.env.CompositePropertySource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.PropertySources;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.util.ClassUtils;

import static org.springframework.cloud.bootstrap.TextEncryptorConfigBootstrapper.keysConfigured;
import static org.springframework.cloud.util.PropertyUtils.bootstrapEnabled;
import static org.springframework.cloud.util.PropertyUtils.useLegacyProcessing;

/**
 * Decrypt properties from the environment and insert them with high priority so they
 * override the encrypted values.
 *
 * @author Dave Syer
 * @author Tim Ysewyn
 */
public class DecryptEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

	/**
	 * Name of the decrypted property source.
	 */
	public static final String DECRYPTED_PROPERTY_SOURCE_NAME = "decrypted";

	/**
	 * Prefix indicating an encrypted value.
	 */
	public static final String ENCRYPTED_PROPERTY_PREFIX = "{cipher}";

	private static final Pattern COLLECTION_PROPERTY = Pattern.compile("(\\S+)?\\[(\\d+)\\](\\.\\S+)?");

	private static Log logger = LogFactory.getLog(DecryptEnvironmentPostProcessor.class);

	private int order = Ordered.LOWEST_PRECEDENCE;

	private boolean failOnError = true;

	/**
	 * Strategy to determine how to handle exceptions during decryption.
	 * @param failOnError the flag value (default true)
	 */
	public void setFailOnError(boolean failOnError) {
		this.failOnError = failOnError;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		if (bootstrapEnabled(environment) || useLegacyProcessing(environment)) {
			return;
		}

		MutablePropertySources propertySources = environment.getPropertySources();

		environment.getPropertySources().remove(DECRYPTED_PROPERTY_SOURCE_NAME);

		TextEncryptor encryptor = getTextEncryptor(environment);

		Map<String, Object> map = decrypt(encryptor, propertySources);
		if (!map.isEmpty()) {
			// We have some decrypted properties
			propertySources.addFirst(new SystemEnvironmentPropertySource(DECRYPTED_PROPERTY_SOURCE_NAME, map));
		}

	}

	protected TextEncryptor getTextEncryptor(ConfigurableEnvironment environment) {
		Binder binder = Binder.get(environment);
		KeyProperties keyProperties = binder.bind(KeyProperties.PREFIX, KeyProperties.class)
				.orElseGet(KeyProperties::new);
		if (keysConfigured(keyProperties)) {

			if (ClassUtils.isPresent("org.springframework.security.rsa.crypto.RsaSecretEncryptor", null)) {
				RsaProperties rsaProperties = binder.bind(RsaProperties.PREFIX, RsaProperties.class)
						.orElseGet(RsaProperties::new);
				return TextEncryptorConfigBootstrapper.rsaTextEncryptor(keyProperties, rsaProperties);
			}
			return new EncryptorFactory(keyProperties.getSalt()).create(keyProperties.getKey());
		}
		// no keys configured
		return new FailsafeTextEncryptor();
	}

	public Map<String, Object> decrypt(TextEncryptor encryptor, PropertySources propertySources) {
		Map<String, Object> properties = merge(propertySources);
		decrypt(encryptor, properties);
		return properties;
	}

	private Map<String, Object> merge(PropertySources propertySources) {
		Map<String, Object> properties = new LinkedHashMap<>();
		List<PropertySource<?>> sources = new ArrayList<>();
		for (PropertySource<?> source : propertySources) {
			sources.add(0, source);
		}
		for (PropertySource<?> source : sources) {
			merge(source, properties);
		}
		return properties;
	}

	private void merge(PropertySource<?> source, Map<String, Object> properties) {
		if (source instanceof CompositePropertySource) {

			List<PropertySource<?>> sources = new ArrayList<>(((CompositePropertySource) source).getPropertySources());
			Collections.reverse(sources);

			for (PropertySource<?> nested : sources) {
				merge(nested, properties);
			}

		}
		else if (source instanceof EnumerablePropertySource) {
			Map<String, Object> otherCollectionProperties = new LinkedHashMap<>();
			boolean sourceHasDecryptedCollection = false;

			EnumerablePropertySource<?> enumerable = (EnumerablePropertySource<?>) source;
			for (String key : enumerable.getPropertyNames()) {
				Object property = source.getProperty(key);
				if (property != null) {
					String value = property.toString();
					if (value.startsWith(ENCRYPTED_PROPERTY_PREFIX)) {
						properties.put(key, value);
						if (COLLECTION_PROPERTY.matcher(key).matches()) {
							sourceHasDecryptedCollection = true;
						}
					}
					else if (COLLECTION_PROPERTY.matcher(key).matches()) {
						// put non-encrypted properties so merging of index properties
						// happens correctly
						otherCollectionProperties.put(key, value);
					}
					else {
						// override previously encrypted with non-encrypted property
						properties.remove(key);
					}
				}
			}
			// copy all indexed properties even if not encrypted
			if (sourceHasDecryptedCollection && !otherCollectionProperties.isEmpty()) {
				properties.putAll(otherCollectionProperties);
			}

		}
	}

	private void decrypt(TextEncryptor encryptor, Map<String, Object> properties) {
		properties.replaceAll((key, value) -> {
			String valueString = value.toString();
			if (!valueString.startsWith(ENCRYPTED_PROPERTY_PREFIX)) {
				return value;
			}
			return decrypt(encryptor, key, valueString);
		});
	}

	private String decrypt(TextEncryptor encryptor, String key, String original) {
		String value = original.substring(ENCRYPTED_PROPERTY_PREFIX.length());
		try {
			value = encryptor.decrypt(value);
			if (logger.isDebugEnabled()) {
				logger.debug("Decrypted: key=" + key);
			}
			return value;
		}
		catch (Exception e) {
			String message = "Cannot decrypt: key=" + key;
			if (logger.isDebugEnabled()) {
				logger.warn(message, e);
			}
			else {
				logger.warn(message);
			}
			if (this.failOnError) {
				throw new IllegalStateException(message, e);
			}
			return "";
		}
	}

}
