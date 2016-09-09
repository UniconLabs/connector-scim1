package com.evolveum.polygon.scim;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.client.methods.HttpPost;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
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
import org.json.JSONObject;

@ConnectorClass(displayNameKey = "ScimConnector.connector.display", configurationClass = ScimConnectorConfiguration.class)

public class ScimConnector implements Connector, CreateOp, DeleteOp, SchemaOp, SearchOp<Filter>, TestOp, UpdateOp,
		UpdateAttributeValuesOp {

	private ScimConnectorConfiguration configuration;
	private CrudManagerScim crudManager;
	private Boolean genericsCanBeApplied = false;

	private static final String SCHEMAS = "Schemas/";
	private static final String USERS = "Users";
	private static final String GROUPS = "Groups";
	private static final String DEFAULT = "default";
	private static final String DELETE = "delete";
	private Schema schema = null;
	private String providerName = "";

	// TODO check if plausible
	private HandlingStrategy strategy;

	private static final char QUERYCHAR = '?';
	private static final char QUERYDELIMITER = '&';

	private static final Log LOGGER = Log.getLog(ScimConnector.class);

	@Override
	public Schema schema() {

		LOGGER.info("Building schema definition");

		if (schema == null) {
			// test log delete
			SchemaBuilder schemaBuilder = new SchemaBuilder(ScimConnector.class);
			ParserSchemaScim schemaParser = strategy.qeuerySchemas(providerName, SCHEMAS, configuration);

			if (schemaParser != null) {

				long startTime = System.currentTimeMillis();
				buildSchemas(schemaBuilder, schemaParser);
				long endTime = System.currentTimeMillis();

				long time = (endTime - startTime);

				LOGGER.error("The buildSchemas methods Time: {0} milliseconds", time);

			} else {

				ObjectClassInfo userSchemaInfo = UserDataBuilder.getUserSchema();
				ObjectClassInfo groupSchemaInfo = GroupDataBuilder.getGroupSchema();
				schemaBuilder.defineObjectClass(userSchemaInfo);
				schemaBuilder.defineObjectClass(groupSchemaInfo);
			}
			return schemaBuilder.build();
		}
		return this.schema;
	}

	/**
	 * Implementation of the connId delete method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied.
	 * 
	 * @throws IllegalArgumentException
	 *             if the object value is not provided.
	 **/
	@Override
	public void delete(ObjectClass object, Uid uid, OperationOptions options) {
		LOGGER.info("Resource object delete");
		if (uid.getUidValue() == null && uid.getUidValue().isEmpty()) {
			LOGGER.error("Uid not provided or empty: {0} ", uid.getUidValue());
			throw new IllegalArgumentException("Uid value not provided or empty");
		}

		if (object == null) {
			LOGGER.error("Object value not provided {0} ", object);
			throw new IllegalArgumentException("Object value not provided");
		}

		if (genericsCanBeApplied) {
			String endpointName = object.getObjectClassValue();

			if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

				strategy.delete(uid, USERS, configuration);

			} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

				strategy.delete(uid, GROUPS, configuration);
			} else {

				strategy.delete(uid, endpointName, configuration);
			}

		} else {

			if (ObjectClass.ACCOUNT.equals(object)) {
				strategy.delete(uid, USERS, configuration);
			} else if (ObjectClass.GROUP.equals(object)) {
				strategy.delete(uid, GROUPS, configuration);
			} else {
				LOGGER.error("Provided object value is not valid: {0}", object);
				throw new IllegalArgumentException("Object value not valid");
			}
		}
	}

	/**
	 * Implementation of the connId create method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied.
	 * 
	 * @throws IllegalArgumentException
	 *             if the value of set is not provided.
	 */
	@Override
	public Uid create(ObjectClass object, Set<Attribute> attribute, OperationOptions options) {
		LOGGER.info("Resource object create");

		Set<Attribute> injectetAttributeSet = new HashSet<Attribute>();

		if (attribute == null || attribute.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty", attribute);
			throw new IllegalArgumentException("Set of Attributes value is null or empty");
		}

		if (genericsCanBeApplied) {
			Uid uid = new Uid(DEFAULT);
			GenericDataBuilder jsonDataBuilder = new GenericDataBuilder("");
			String endpointName = object.getObjectClassValue();

			if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {
				strategy.addAttributeToInject(injectetAttributeSet);

				uid = strategy.create(USERS, jsonDataBuilder, attribute, injectetAttributeSet, configuration);

			} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {
				strategy.addAttributeToInject(injectetAttributeSet);

				uid = strategy.create(GROUPS, jsonDataBuilder, attribute, injectetAttributeSet, configuration);

			} else {
				strategy.addAttributeToInject(injectetAttributeSet);

				uid = strategy.create(endpointName, jsonDataBuilder, attribute, injectetAttributeSet, configuration);
			}

			return uid;
		} else {

			if (ObjectClass.ACCOUNT.equals(object)) {
				ObjectTranslator userBuild = new UserDataBuilder("");

				strategy.addAttributeToInject(injectetAttributeSet);

				Uid uid = strategy.create(USERS, userBuild, attribute, injectetAttributeSet, configuration);

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}

				return uid;

			} else if (ObjectClass.GROUP.equals(object)) {

				GroupDataBuilder groupBuild = new GroupDataBuilder("");

				StrategyFetcher fetch = new StrategyFetcher();
				HandlingStrategy strategy = fetch.fetchStrategy(providerName);
				strategy.addAttributeToInject(injectetAttributeSet);

				Uid uid = strategy.create(GROUPS, groupBuild, attribute, injectetAttributeSet, configuration);

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;
			} else {

				LOGGER.error("Provided object value is not valid: {0}", object);
				throw new IllegalArgumentException("Object value not valid");
			}
		}
	}

	@Override
	public void dispose() {
		LOGGER.info("Configuration cleanup");
		configuration = null;
		crudManager = null;
	}

	@Override
	public Configuration getConfiguration() {
		LOGGER.info("Fetch configuration");
		return this.configuration;
	}

	@Override
	public void init(Configuration configuration) {
		String[] loginUrlParts;
		LOGGER.info("Initiation");
		this.configuration = (ScimConnectorConfiguration) configuration;
		this.configuration.validate();
		this.crudManager = new CrudManagerScim();

		// For workaround purposes
		// TODO

		if (this.configuration.getLoginURL() != null && !this.configuration.getLoginURL().isEmpty()) {

			loginUrlParts = this.configuration.getLoginURL().split("\\."); // e.g.

		} else {

			loginUrlParts = this.configuration.getBaseUrl().split("\\."); // e.g.
		}
		// https://login.salesforce.com
		if (loginUrlParts.length >= 2) {
			providerName = loginUrlParts[1];
		}
		//

		// TODO check if this is plausible
		StrategyFetcher fetcher = new StrategyFetcher();
		strategy = fetcher.fetchStrategy(providerName);

		// TODO obsolete
		LOGGER.info("The provider name is {0}", providerName);
		ParserSchemaScim schemaParser = strategy.qeuerySchemas(providerName, SCHEMAS, this.configuration);

		if (schemaParser != null) {

			genericsCanBeApplied = true;
		} else {

			LOGGER.warn(
					"No schema found for processing, the connector will switch to the core SCIM v1. schema definition");
		}

	}

	/**
	 * Implementation of the connId update method. The method evaluates if
	 * generic methods can be applied to the query. If not the methods
	 * implemented for core schema processing are applied. This method is used
	 * to update singular and non complex attributes, e.g. name.familyname.
	 * 
	 * @throws IllegalArgumentException
	 *             if the provided set of attributes is null or empty.
	 * @return the Uid of the updated object.
	 **/
	@Override
	public Uid update(ObjectClass object, Uid id, Set<Attribute> attributes, OperationOptions options) {
		LOGGER.info("Resource object update");
		if (attributes == null || attributes.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty: {0}", attributes);
			throw new IllegalArgumentException("Set of Attributes value is null or empty");
		}
		if (genericsCanBeApplied) {
			Uid uid = new Uid(DEFAULT);
			GenericDataBuilder genericDataBuilder = new GenericDataBuilder("");

			String endpointName = object.getObjectClassValue();

			if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

				uid = strategy.update(id, USERS, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);

			} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

				uid = strategy.update(id, GROUPS, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);
			} else {
				uid = strategy.update(id, endpointName, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);

			}

			return uid;
		} else {
			if (ObjectClass.ACCOUNT.equals(object)) {
				UserDataBuilder userJson = new UserDataBuilder("");
				JSONObject userJsonObject = new JSONObject();

				userJsonObject = userJson.translateSetToJson(attributes, null);

				Uid uid = strategy.update(id, USERS, userJsonObject, configuration);

				LOGGER.info("Json response: {0}", userJsonObject.toString(1));

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;

			} else if (ObjectClass.GROUP.equals(object)) {

				GroupDataBuilder groupJson = new GroupDataBuilder("");
				JSONObject groupJsonObject = new JSONObject();

				groupJsonObject = groupJson.translateSetToJson(attributes, null);

				Uid uid = strategy.update(id, GROUPS, groupJsonObject, configuration);

				LOGGER.info("Json response: {0}", groupJsonObject.toString(1));

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;
			} else {
				LOGGER.error("Provided object value is not valid: {0}", object);
				throw new IllegalArgumentException("Object value not valid");
			}
		}
	}

	@Override
	public void test() {

		LOGGER.info("Test");

		if (crudManager != null && configuration != null) {
			Map<String, Object> autoriazationData = crudManager.logIntoService(configuration);

			if (autoriazationData != null && !autoriazationData.isEmpty()) {

				if (autoriazationData.containsKey("loginInstance")) {

					HttpPost instance = (HttpPost) autoriazationData.get("loginInstance");

					LOGGER.info("Test was succesfull");
					crudManager.logOut(instance);
				} else {

					LOGGER.error(
							"Error with establishing connection while testing. The login instance was not created.");
				}

			} else {

				LOGGER.error("Error with establishing connection while testing. No authorization data were provided.");
			}

		} else {

			LOGGER.error(
					"Error with establishing connection while testing. No instance of the configuration class or CRUD+L communication class was created");
		}

	}

	@Override
	public FilterTranslator<Filter> createFilterTranslator(ObjectClass arg0, OperationOptions arg1) {
		return new FilterTranslator<Filter>() {
			@Override
			public List<Filter> translate(Filter filter) {
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
	public void executeQuery(ObjectClass objectClass, Filter query, ResultsHandler handler, OperationOptions options) {
		LOGGER.info("Connector object execute query");
		LOGGER.info("Object class value {0}", objectClass.getDisplayNameKey());
		StringBuilder queryUriSnippet = new StringBuilder("");
		String endpointName = objectClass.getObjectClassValue();

		if (options != null) {
			queryUriSnippet = processOptions(options);
		}

		LOGGER.info("The operation options: {0}", options);
		LOGGER.info("The filter which is beaing processed: {0}", query);

		if (handler == null) {

			LOGGER.error("Result handler for queuery is null");
			throw new ConnectorException("Result handler for queuery can not be null");
		}

		String flag = querryChecker(query, endpointName);

		if (flag.isEmpty()) {

			if (genericsCanBeApplied) {

				if (ObjectClass.ACCOUNT.getObjectClassValue().equals(endpointName)) {
					if (query == null) {

						strategy.qeuery(queryUriSnippet.toString(), USERS, handler, configuration);

					} else if (query instanceof EqualsFilter && qIsUid(USERS, query, handler)) {

					} else {

						qIsFilter(USERS, query, handler, queryUriSnippet);
					}
				} else if (ObjectClass.GROUP.getObjectClassValue().equals(endpointName)) {
					if (query == null) {
						strategy.qeuery(queryUriSnippet.toString(), GROUPS, handler, configuration);

					} else if (query instanceof EqualsFilter && qIsUid(GROUPS, query, handler)) {

					} else {
						qIsFilter(GROUPS, query, handler, queryUriSnippet);
					}
				} else {

					if (query == null) {

						strategy.qeuery(queryUriSnippet.toString(), endpointName, handler, configuration);
					} else if (query instanceof EqualsFilter && qIsUid(endpointName, query, handler)) {

					} else {
						qIsFilter(endpointName, query, handler, queryUriSnippet);
					}
				}
			} else {

				if (ObjectClass.ACCOUNT.equals(objectClass)) {

					if (query == null) {
						strategy.qeuery(queryUriSnippet.toString(), USERS, handler, configuration);
					} else if (query instanceof EqualsFilter && qIsUid(USERS, query, handler)) {

					} else {
						qIsFilter(USERS, query, handler, queryUriSnippet);
					}
				} else if (ObjectClass.GROUP.equals(objectClass)) {
					if (query == null) {
						strategy.qeuery(queryUriSnippet.toString(), GROUPS, handler, configuration);
					} else if (query instanceof EqualsFilter && qIsUid(GROUPS, query, handler)) {

					} else {

						qIsFilter(GROUPS, query, handler, queryUriSnippet);
					}
				} else {
					LOGGER.error("The provided objectClass is not supported: {0}", objectClass.getDisplayNameKey());
					throw new IllegalArgumentException("ObjectClass is not supported");
				}
			}
		} else {

			if (ObjectClass.GROUP.equals(objectClass)) {
				Uid quieriedObject = new Uid(flag);

				strategy.queryMembershipData(quieriedObject, USERS, handler, GROUPS, configuration);
			}
		}

	}

	/**
	 * Evaluates if the provided filter query is supported or in need of special
	 * handling.
	 * 
	 * @param filter
	 *            the provided filter query.
	 * @return the boolean value of true is query is supported.
	 * @throws IllegalArgumentException
	 *             if the provided filter is no supported.
	 **/
	public String querryChecker(Filter filter, String endpointName) {

		String flag = strategy.checkFilter(filter, endpointName);
		return flag;
	}

	/**
	 * Used to evaluate if the queried attribute in the provided filter query is
	 * an instance of Uid. if yes, the method used to process such query is
	 * called.
	 * 
	 * @param endPoint
	 *            The name of the endpoint which should be queried.
	 * @param query
	 *            The provided filter query.
	 * @param resultHandler
	 *            The provided result handler used to handle the query result.
	 * @return true if filter attribute value is an instance of uid and executes
	 *         an successful query to the service provider. Else returns false.
	 */
	private boolean qIsUid(String endPoint, Filter query, ResultsHandler resultHandler) {
		Attribute filterAttr = ((EqualsFilter) query).getAttribute();

		if (filterAttr instanceof Uid) {
			strategy.qeuery((Uid) filterAttr, endPoint, resultHandler, configuration);
			return true;
		} else
			return false;
	}

	/**
	 * Called when the query is evaluated as an filter not containing an uid
	 * type attribute.
	 * 
	 * @param endPoint
	 *            The name of the endpoint which should be queried.
	 * @param query
	 *            The provided filter query.
	 * @param resultHandler
	 *            The provided result handler used to handle the query result.
	 * @param schemaMap
	 *            A map representation of the schema provided from the service
	 *            provider.
	 * @param queryUriSnippet
	 *            A part of the query uri which will build a larger query.
	 */
	private void qIsFilter(String endPoint, Filter query, ResultsHandler resultHandler, StringBuilder queryUriSnippet) {

		char prefixChar;
		StringBuilder filterSnippet = new StringBuilder();
		if (queryUriSnippet.toString().isEmpty()) {
			prefixChar = QUERYCHAR;

		} else {

			prefixChar = QUERYDELIMITER;
		}

		filterSnippet = query.accept(new FilterHandler(), providerName);

		queryUriSnippet.append(prefixChar).append("filter=").append(filterSnippet.toString());
		strategy.qeuery(queryUriSnippet.toString(), endPoint, resultHandler, configuration);
	}

	/**
	 * Calls the "schemaObjectbuilder" class "buildSchema" methods for all the
	 * individual schema resource objects.
	 * 
	 * @param schemaBuilder
	 *            The "SchemaBuilder" object which will be populated with the
	 *            data representing the schemas of resource objects.
	 * @return an the instance of "SchemaBuilder" populated with the data
	 *         representing the schemas of resource objects.
	 */
	private SchemaBuilder buildSchemas(SchemaBuilder schemaBuilder, ParserSchemaScim schemaParser) {
		LOGGER.info("Building schemas from provided data");

		SchemaObjectBuilderGeneric schemaObjectBuilder = new SchemaObjectBuilderGeneric();
		int iterator = 0;
		Map<String, String> hlAtrribute = new HashMap<String, String>();
		List<Map<String, Map<String, Object>>> attributeMapList = schemaParser.getAttributeMapList(strategy);

		for (Map<String, Map<String, Object>> attributeMap : attributeMapList) {
			hlAtrribute = schemaParser.gethlAttributeMapList().get(iterator);

			for (String key : hlAtrribute.keySet()) {
				if ("endpoint".equals(key)) {
					String schemaName = hlAtrribute.get(key);
					ObjectClassInfo oclassInfo = schemaObjectBuilder.buildSchema(attributeMap, schemaName,
							providerName);
					schemaBuilder.defineObjectClass(oclassInfo);
				}
			}
			iterator++;
		}

		return schemaBuilder;
	}

	/**
	 * Evaluates if the options attribute contains information for pagination
	 * configuration for the query.
	 * 
	 * @return a "StringBuilder" instance containing the query snippet with
	 *         pagination information of or is no pagination information is
	 *         provided an empty snippet.
	 */
	private StringBuilder processOptions(OperationOptions options) {
		StringBuilder queryBuilder = new StringBuilder();

		Integer pageSize = options.getPageSize();
		Integer PagedResultsOffset = options.getPagedResultsOffset();
		if (pageSize != null && PagedResultsOffset != null) {
			queryBuilder.append(QUERYCHAR).append("startIndex=").append(PagedResultsOffset).append(QUERYDELIMITER)
					.append("count=").append(pageSize);

			return queryBuilder;
		}
		return queryBuilder.append("");
	}

	/**
	 * Implementation of the connId addAttributeValues method. The method
	 * evaluates if generic methods can be applied to the query. If not the
	 * methods implemented for core schema processing are applied. This method
	 * is used to update multivalued and complex attributes, e.g.
	 * members.default.value .
	 * 
	 * @throws IllegalArgumentException
	 *             if the provided set of attributes is null or empty.
	 * @return the Uid of the updated object.
	 **/
	@Override
	public Uid addAttributeValues(ObjectClass object, Uid id, Set<Attribute> attributes, OperationOptions options) {

		LOGGER.info("Resource object update for addition of values");
		if (attributes == null || attributes.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty: {}", attributes);
			throw new IllegalArgumentException("Set of Attributes value is null or empty");
		}
		if (genericsCanBeApplied) {
			Uid uid = new Uid(DEFAULT);
			GenericDataBuilder genericDataBuilder = new GenericDataBuilder("");

			String endpointName = object.getObjectClassValue();

			if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

				uid = strategy.update(id, USERS, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);

			} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

				uid = strategy.update(id, GROUPS, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);
			} else {
				uid = strategy.update(id, endpointName, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);
			}

			return uid;
		} else {
			if (ObjectClass.ACCOUNT.equals(object)) {
				UserDataBuilder userJson = new UserDataBuilder("");
				JSONObject userJsonObject = new JSONObject();

				userJsonObject = userJson.translateSetToJson(attributes, null);

				Uid uid = strategy.update(id, USERS, userJsonObject, configuration);

				LOGGER.info("Json response: {0}", userJsonObject.toString(1));

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;

			} else if (ObjectClass.GROUP.equals(object)) {

				GroupDataBuilder groupJson = new GroupDataBuilder("");
				JSONObject groupJsonObject = new JSONObject();

				groupJsonObject = groupJson.translateSetToJson(attributes, null);

				Uid uid = strategy.update(id, GROUPS, groupJsonObject, configuration);

				LOGGER.info("Json response: {0}", groupJsonObject.toString(1));

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;
			} else {
				LOGGER.error("Provided object value is not valid: {0}", object);
				throw new IllegalArgumentException("Object value not valid");
			}
		}

	}

	/**
	 * Implementation of the connId removeAttributeValues method. The method
	 * evaluates if generic methods can be applied to the query. If not the
	 * methods implemented for core schema processing are applied. This method
	 * is used to update multivalued and complex attributes, e.g.
	 * members.default.value . The updates are used for removal of attribute
	 * values of multivalued and complex attributes.
	 * 
	 * @throws IllegalArgumentException
	 *             if the provided set of attributes is null or empty.
	 * @return the Uid of the updated object.
	 **/
	@Override
	public Uid removeAttributeValues(ObjectClass object, Uid id, Set<Attribute> attributes, OperationOptions options) {

		LOGGER.info("Resource object update for removal of attribute values");
		if (attributes == null || attributes.isEmpty()) {
			LOGGER.error("Set of Attributes can not be null or empty: {0}", attributes);
			throw new IllegalArgumentException("Set of Attributes value is null or empty");
		}
		if (genericsCanBeApplied) {
			Uid uid = new Uid(DEFAULT);
			GenericDataBuilder genericDataBuilder = new GenericDataBuilder(DELETE);

			String endpointName = object.getObjectClassValue();

			if (endpointName.equals(ObjectClass.ACCOUNT.getObjectClassValue())) {

				uid = strategy.update(id, USERS, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);

			} else if (endpointName.equals(ObjectClass.GROUP.getObjectClassValue())) {

				uid = strategy.update(id, GROUPS, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);

			} else {

				uid = strategy.update(id, endpointName, genericDataBuilder.translateSetToJson(attributes, null),
						configuration);
			}

			return uid;
		} else {
			if (ObjectClass.ACCOUNT.equals(object)) {
				UserDataBuilder userJson = new UserDataBuilder(DELETE);
				JSONObject userJsonObject = new JSONObject();

				userJsonObject = userJson.translateSetToJson(attributes, null);

				Uid uid = strategy.update(id, USERS, userJsonObject, configuration);

				LOGGER.info("Json response: {0}", userJsonObject.toString(1));

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;

			} else if (ObjectClass.GROUP.equals(object)) {

				GroupDataBuilder groupJson = new GroupDataBuilder(DELETE);
				JSONObject groupJsonObject = new JSONObject();

				groupJsonObject = groupJson.translateSetToJson(attributes, null);

				Uid uid = strategy.update(id, GROUPS, groupJsonObject, configuration);

				LOGGER.info("Json response: {0}", groupJsonObject.toString(1));

				if (uid == null) {
					LOGGER.error("No uid returned by the create method: {0} ", uid);
					throw new IllegalArgumentException("No uid returned by the create method");
				}
				return uid;
			} else {
				LOGGER.error("Provided object value is not valid: {0}", object);
				throw new IllegalArgumentException("Object value not valid");
			}
		}

	}

}
