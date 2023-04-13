/*
 * Copyright (c) 2016 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.evolveum.polygon.scim;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;


/**
 *
 * @author Macik
 *
 * Implementation of the connId connector class for the scim standard.
 *
 */
@ConnectorClass(displayNameKey = "ScimConnector.connector.display", configurationClass = ScimConnectorConfiguration.class)
public class ScimConnector implements Connector, CreateOp, DeleteOp, SchemaOp, SearchOp<Filter>, TestOp, UpdateOp,
		UpdateAttributeValuesOp {

	private static final String SCHEMAS_ENDPOINT = "Schemas/";
	private static final String USERS_ENDPOINT = "Users";
	private static final String GROUPS_ENDPOINT = "Groups";
	private static final String DEFAULT_UID = "default";
	private static final String DELETE_OP = "remove";
	private static final String ADD_OP = "add";
	private static final String UPDATE_OP = "replace";
	private static final char QUERY_CHAR = '?';
	private static final char QUERY_DELIMITER = '&';
	private static final Log LOGGER = Log.getLog(ScimConnector.class);

	private ScimConnectorConfiguration configuration;
	private Schema schema = null;
	private String providerName = "";
	private HandlingStrategy strategy;

	@Override
	public Schema schema() {

		LOGGER.info("Building schema definition");

		if (schema == null) {
			final SchemaBuilder schemaBuilder = new SchemaBuilder(ScimConnector.class);
			final ParserSchemaScim schemaParser = strategy.querySchemas(providerName, SCHEMAS_ENDPOINT, USERS_ENDPOINT, GROUPS_ENDPOINT, configuration);

			if (schemaParser != null) {
				buildSchemas(schemaBuilder, schemaParser);
			} else {

				ObjectClassInfo userSchemaInfo = UserSchemaBuilder.getUserSchema();
				ObjectClassInfo groupSchemaInfo = GroupDataBuilder.getGroupSchema();
				schemaBuilder.defineObjectClass(userSchemaInfo);
				schemaBuilder.defineObjectClass(groupSchemaInfo);
			}

			this.schema = schemaBuilder.build();
			return schema;
		}

		return this.schema;
	}

	/**
	 * Implementation of the connId delete method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied.
	 * 
	 **/
	@Override
	public void delete(final ObjectClass object, final Uid uid, final OperationOptions options) {
		LOGGER.info("Resource object delete");
		if (uid.getUidValue() == null && uid.getUidValue().isEmpty()) {
			LOGGER.error("Uid not provided or empty: {0} ", uid.getUidValue());
			throw new InvalidAttributeValueException("Uid value not provided or empty");
		}

		if (object == null) {
			LOGGER.error("Object value not provided for delete of {0} ", uid);
			throw new InvalidAttributeValueException("Object value not provided");
		}

		final String endpointName = object.getObjectClassValue();

		if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

			strategy.delete(uid, USERS_ENDPOINT, configuration);

		} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

			strategy.delete(uid, GROUPS_ENDPOINT, configuration);
		} else {

			strategy.delete(uid, endpointName, configuration);
		}

	}

	/**
	 * Implementation of the connId create method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied.
	 */
	@Override
	public Uid create(final ObjectClass object, final Set<Attribute> attribute, final OperationOptions options) {
		LOGGER.info("Resource object create");

		Set<Attribute> injectedAttributeSet = new HashSet<>();

		if (attribute == null || attribute.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty", attribute);
			throw new ConnectorException("Set of Attributes value is null or empty");
		}

		Uid uid = new Uid(DEFAULT_UID);
		final GenericDataBuilder jsonDataBuilder = new GenericDataBuilder(ADD_OP, scimVersionInt());
		final String endpointName = object.getObjectClassValue();

		if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {
			injectedAttributeSet = strategy.addAttributesToInject(injectedAttributeSet);

			uid = strategy.create(USERS_ENDPOINT, jsonDataBuilder, attribute, injectedAttributeSet, configuration);

		} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {
			injectedAttributeSet = strategy.addAttributesToInject(injectedAttributeSet);

			uid = strategy.create(GROUPS_ENDPOINT, jsonDataBuilder, attribute, injectedAttributeSet, configuration);

		} else {
			injectedAttributeSet = strategy.addAttributesToInject(injectedAttributeSet);

			uid = strategy.create(endpointName, jsonDataBuilder, attribute, injectedAttributeSet, configuration);
		}

		return uid;
	}

	@Override
	public void dispose() {
		LOGGER.info("Configuration cleanup");
		configuration = null;
	}

	@Override
	public Configuration getConfiguration() {
		LOGGER.info("Fetch configuration");
		return this.configuration;
	}

	@Override
	public void init(final Configuration configuration) {
		String loginUrl;
		LOGGER.info("Initiation");
		this.configuration = (ScimConnectorConfiguration) configuration;
		this.configuration.validate();

		if (this.configuration.getLoginURL() != null && !this.configuration.getLoginURL().isEmpty()) {
			loginUrl = this.configuration.getLoginURL();
		} else {
			loginUrl = this.configuration.getBaseUrl();
		}

		if (this.configuration.getProvider() != null && !this.configuration.getProvider().isEmpty()) {
			providerName = this.configuration.getProvider().trim().toLowerCase();
			strategy = new StrategyFetcher().fetchStrategy(providerName);
		} else {
			strategy = new StrategyFetcher().fetchStrategy(loginUrl);
			providerName = strategy.getStrategyName();
		}

		if (providerName.equalsIgnoreCase("standard")) {
			final String[] loginUrlParts = loginUrl.split("\\.");

			if (loginUrlParts.length >= 2) {
				providerName = loginUrlParts[1];
			} else {
				providerName = "";
			}
		}
		LOGGER.info("The provider name is {0}", providerName);
	}

	/**
	 * Implementation of the connId update method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied. This method is used
	 * to update singular and non-complex attributes, e.g. name.familyName.
	 * 
	 * @return the Uid of the updated object.
	 **/

	@Override
	public Uid update(final ObjectClass object, final Uid id, final Set<Attribute> attributes, final OperationOptions options) {
		LOGGER.info("Resource object update");
		if (attributes == null || attributes.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty: {0}", attributes);
			throw new ConnectorException("Set of Attributes value is null or empty");
		}

		Uid uid = new Uid(DEFAULT_UID);
		final GenericDataBuilder genericDataBuilder = new GenericDataBuilder(UPDATE_OP, scimVersionInt());

		final String endpointName = object.getObjectClassValue();

		if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

			uid = strategy.update(id, USERS_ENDPOINT, genericDataBuilder, attributes, configuration);

		} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

			uid = strategy.update(id, GROUPS_ENDPOINT, genericDataBuilder, attributes, configuration);
		} else {
			uid = strategy.update(id, endpointName, genericDataBuilder, attributes, configuration);

		}

		return uid;
	}

	@Override
	public void test() {

		LOGGER.info("Test");

		if (configuration != null) {
			final ServiceAccessManager accessManager = new ServiceAccessManager(configuration, strategy);

			final String baseUri = accessManager.getBaseUri();
		
			if (baseUri !=null && !baseUri.isEmpty()) {
				LOGGER.info("Test was successful");
			} else {

				LOGGER.error("Error with establishing connection while testing. No authorization data were provided.");
			}

		} else {

			LOGGER.error(
					"Error with establishing connection while testing. No instance of the configuration class or CRUD+L communication class was created");
		}

	}

	@Override
	public FilterTranslator<Filter> createFilterTranslator(final ObjectClass arg0, final OperationOptions arg1) {
		return new FilterTranslator<>() {
			@Override
			public List<Filter> translate(final Filter filter) {
				return CollectionUtil.newList(filter);
			}
		};
	}

	/**
	 * Implementation of the connId executeQuery method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied. This method is used
	 * to execute any query define via the Filter "query" parameter.
	 * 
	 * @throws IllegalArgumentException
	 *             if the provided object class is not supported.
	 * @throws ConnectorException
	 *             if the handler attribute is null.
	 */
	@Override
	public void executeQuery(final ObjectClass objectClass, final Filter query, final ResultsHandler handler, final OperationOptions options) {
		LOGGER.info("Connector object execute query");
		LOGGER.info("Object class value {0}", objectClass.getDisplayNameKey());
		StringBuilder queryUriSnippet = new StringBuilder();
		final String endpointName = objectClass.getObjectClassValue();

		if (options != null) {
			queryUriSnippet = processOptions(options);
		}

		LOGGER.info("The operation options: {0}", options);
		LOGGER.info("The filter which is being processed: {0}", query);

		if (handler == null) {

			LOGGER.error("Result handler for query is null");
			throw new ConnectorException("Result handler for query can not be null");
		}

		if (ObjectClass.ACCOUNT.getObjectClassValue().equals(endpointName)) {

			strategy.query(query, queryUriSnippet, USERS_ENDPOINT, handler, configuration);

		} else if (ObjectClass.GROUP.getObjectClassValue().equals(endpointName)) {

			strategy.query(query, queryUriSnippet, GROUPS_ENDPOINT, handler, configuration);

		} else {

			strategy.query(query, queryUriSnippet, endpointName, handler, configuration);
		}

	}

	/**
	 * Calls the "schemaObjectBuilder" class "buildSchema" methods for all the
	 * individual schema resource objects.
	 * 
	 * @param schemaBuilder
	 *            The "SchemaBuilder" object which will be populated with the
	 *            data representing the schemas of resource objects.
	 * @param schemaParser
	 *            The "schemaParser" object which contains the map
	 *            representation of the service schema data.
	 * @return The instance of "SchemaBuilder" populated with the data
	 *         representing the schemas of resource objects.
	 */
	private SchemaBuilder buildSchemas(final SchemaBuilder schemaBuilder, final ParserSchemaScim schemaParser) {
		LOGGER.info("Building schemas from provided data");

		final SchemaObjectBuilderGeneric schemaObjectBuilder = new SchemaObjectBuilderGeneric();
		int iterator = 0;
		Map<String, String> hlAttribute;
		final List<Map<String, Map<String, Object>>> attributeMapList = schemaParser.getAttributeMapList(strategy);

		for (final Map<String, Map<String, Object>> attributeMap : attributeMapList) {
			hlAttribute = schemaParser.getHlAttributeMapList().get(iterator);

			for (final String key : hlAttribute.keySet()) {
				if ("endpoint".equals(key)) {
					final String schemaName = hlAttribute.get(key);
					final ObjectClassInfo objectClassInfo = schemaObjectBuilder.buildSchema(attributeMap, schemaName,
							strategy);
					schemaBuilder.defineObjectClass(objectClassInfo);
				}
			}
			iterator++;
		}

		return schemaBuilder;
	}

	/**
	 * Evaluates if the options attribute contains information for pagination
	 * configuration of query.
	 * 
	 * @param options
	 *            Provided parameter which carries the data for pagination
	 *            configuration.
	 * 
	 * @return a "StringBuilder" instance containing the query snippet with
	 *         pagination information of or is no pagination information is
	 *         provided an empty snippet.
	 */
	private StringBuilder processOptions(final OperationOptions options) {
		final StringBuilder queryBuilder = new StringBuilder();

		final Integer pageSize = options.getPageSize();
		final Integer PagedResultsOffset = options.getPagedResultsOffset();

		if (pageSize != null && PagedResultsOffset != null) {
			queryBuilder.append(QUERY_CHAR).append("startIndex=").append(PagedResultsOffset).append(QUERY_DELIMITER)
					.append("count=").append(pageSize);

			return queryBuilder;
		}
		return queryBuilder;
	}

	/**
	 * Implementation of the connId addAttributeValues method. The method
	 * evaluates if generic methods can be applied to the query. If not the
	 * methods implemented for core schema processing are applied. This method
	 * is used to update multivalued and complex attributes, e.g.
	 * members.default.value .
	 * 
	 * @return the Uid of the updated object.
	 **/
	@Override
	public Uid addAttributeValues(final ObjectClass object, final Uid id, final Set<Attribute> attributes, final OperationOptions options) {

		LOGGER.info("Resource object update for addition of values");
		if (attributes == null || attributes.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty: {}", attributes);
			throw new ConnectorException("Set of Attributes value is null or empty");
		}

		Uid uid = new Uid(DEFAULT_UID);
		final GenericDataBuilder genericDataBuilder = new GenericDataBuilder(UPDATE_OP, scimVersionInt());

		final String endpointName = object.getObjectClassValue();

		if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

			uid = strategy.update(id, USERS_ENDPOINT, genericDataBuilder, attributes, configuration);

		} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

			uid = strategy.update(id, GROUPS_ENDPOINT, genericDataBuilder, attributes, configuration);
		} else {
			uid = strategy.update(id, endpointName, genericDataBuilder, attributes, configuration);
		}

		return uid;

	}

	/**
	 * Implementation of the connId removeAttributeValues method. The method
	 * evaluates if generic methods can be applied to the query. If not the
	 * methods implemented for core schema processing are applied. This method
	 * is used to update multivalued and complex attributes, e.g.
	 * members.default.value . The updates are used for removal of attribute
	 * values of multivalued and complex attributes.
	 * 
	 * @return the Uid of the updated object.
	 **/
	@Override
	public Uid removeAttributeValues(final ObjectClass object, final Uid id, final Set<Attribute> attributes, final OperationOptions options) {

		LOGGER.info("Resource object update for removal of attribute values");
		if (attributes == null || attributes.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty: {0}", attributes);
			throw new ConnectorException("Set of Attributes value is null or empty");
		}
		Uid uid = new Uid(DEFAULT_UID);
		final GenericDataBuilder genericDataBuilder = new GenericDataBuilder(DELETE_OP, scimVersionInt());

		final String endpointName = object.getObjectClassValue();

		if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

			uid = strategy.update(id, USERS_ENDPOINT, genericDataBuilder, attributes, configuration);

		} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

			uid = strategy.update(id, GROUPS_ENDPOINT, genericDataBuilder, attributes, configuration);

		} else {

			uid = strategy.update(id, endpointName, genericDataBuilder, attributes, configuration);
		}

		return uid;

	}

	private int scimVersionInt() {
		final String version = configuration.getVersion();

		if (StringUtil.isNotBlank(version) && version.trim().toLowerCase().contains("v2")) {
			return 2;
		} else {
			return 1;
		}
	}

}
