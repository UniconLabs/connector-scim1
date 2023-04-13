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


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException;
import org.identityconnectors.framework.common.exceptions.OperationTimeoutException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AttributeFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


/**
 * @author Macik
 * 
 *         An implementation of all strategy methods used for processing of
 *         data.
 * 
 */

public class StandardScimHandlingStrategy implements HandlingStrategy {

	private static final Log LOGGER = Log.getLog(StandardScimHandlingStrategy.class);
	private static final String CANONICAL_VALUES = "canonicalValues";
	private static final String REFERENCE_TYPES = "referenceTypes";
	private static final String RESOURCES = "Resources";
	private static final String USER_V2_SCHEMA_ID = "urn:ietf:params:scim:schemas:core:2.0:User";
	private static final String GROUP_V2_SCHEMA_ID = "urn:ietf:params:scim:schemas:core:2.0:Group";
	private static final String USER_V1_SCHEMA_ID = "urn:scim:schemas:core:1.0:User";
	private static final String GROUP_V1_SCHEMA_ID = "urn:scim:schemas:core:1.0:User";
	private static final String START_INDEX = "startIndex";
	private static final String TOTAL_RESULTS = "totalResults";
	private static final String ITEMS_PER_PAGE = "itemsPerPage";
	private static final String FORBIDDEN_SEPARATOR = ":";
	private static final String SEPARATOR = "-";
	private static final char QUERY_CHAR = '?';
	private static final char QUERY_DELIMITER = '&';

	@Override
	public Uid create(final String resourceEndPoint, final ObjectTranslator objectTranslator, final Set<Attribute> attributes,
			Set<Attribute> injectedAttributeSet, final ScimConnectorConfiguration conf) {

		final ServiceAccessManager accessManager = new ServiceAccessManager(conf, this);

		final Header authHeader = accessManager.getAuthHeader();
		final String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {

			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		injectedAttributeSet = attributeInjection(injectedAttributeSet, accessManager.getLoginJson());

		final JSONObject jsonObject = objectTranslator.translateSetToJson(attributes, injectedAttributeSet, resourceEndPoint);

		final HttpClient httpClient = initHttpClient(conf);

		final String uri = scimBaseUri + SLASH + resourceEndPoint + SLASH;
		LOGGER.info("Query url: {0}", uri);
		try {

			// LOGGER.info("Json object to be send: {0}",
			// jsonObject.toString(1));

			final HttpPost httpPost = buildHttpPost(uri, authHeader, jsonObject);
			String responseString;
			try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpPost)) {

				final HttpEntity entity = response.getEntity();

				if (entity != null) {
					responseString = EntityUtils.toString(entity);
				} else {
					responseString = "";
				}

				final int statusCode = response.getStatusLine().getStatusCode();
				LOGGER.info("Status code: {0}", statusCode);

				if (statusCode == 201) {
					LOGGER.info("Creation of resource was successful");

					if (!responseString.isEmpty()) {
						final JSONObject json = new JSONObject(responseString);

						final Uid uid = new Uid(json.getString(ID));

						 LOGGER.info("Json response: {0}", json.toString(1));
						return uid;
					} else {
						return null;
					}
				} else {
					handleInvalidStatus(" while resource creation, please check if credentials are valid. ",
							responseString, "creating a new object", statusCode);
				}

			} catch (ClientProtocolException e) {
				LOGGER.error(
						"An protocol exception has occurred while in the process of creating a new resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An protocol exception has occurred while in the process of creating a new resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
						e);
				throw new ConnectionFailedException(
						"An protocol exception has occurred while in the process of creating a new resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
						e);

			} catch (IOException e) {

				if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

					throw new OperationTimeoutException(
							"The connection timed out. Occurrence in the process of creating a new resource object", e);
				} else {

					LOGGER.error(
							"An error has occurred while processing the http response. Occurrence in the process of creating a new resource object: {0}",
							e.getLocalizedMessage());
					LOGGER.info(
							"An error has occurred while processing the http response. Occurrence in the process of creating a new resource object: {0}",
							e);

					throw new ConnectorIOException(
							"An error has occurred while processing the http response. Occurrence in the process of creating a new resource object",
							e);
				}
			}

		} catch (JSONException e) {

			LOGGER.error(
					"An exception has occurred while processing an json object. Occurrence in the process of creating a new resource object: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An exception has occurred while processing an json object. Occurrence in the process of creating a new resource object: {0}",
					e);

			throw new ConnectorException(
					"An exception has occurred while processing an json object. Occurrence in the process of creating a new resource object",
					e);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("Unsupported encoding: {0}. Occurrence in the process of creating a new resource object ",
					e.getLocalizedMessage());
			LOGGER.info("Unsupported encoding: {0}. Occurrence in the process of creating a new resource object ", e);

			throw new ConnectorException(
					"Unsupported encoding, Occurrence in the process of creating a new resource object ", e);
		}
		return null;
	}

	@Override
	public void query(final Filter query, final StringBuilder queryUriSnippet, String resourceEndPoint,
			final ResultsHandler resultHandler, final ScimConnectorConfiguration conf) {

		LOGGER.info("Processing query");

		Boolean isCAVGroupQuery = false; // query is a ContainsAllValues
											// filter query for the group
											// endpoint?
		boolean valueIsUid = false;
		final ServiceAccessManager accessManager = new ServiceAccessManager(conf, this);

		final Header authHeader = accessManager.getAuthHeader();
		final String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {
			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		String q;

		final String[] baseUrlParts = scimBaseUri.split("\\.");
		final String providerName = baseUrlParts[1];

		if (query != null) {

			if (query instanceof EqualsFilter) {
				final Attribute filterAttr = ((EqualsFilter) query).getAttribute();

				if (filterAttr instanceof Uid) {

					valueIsUid = true;

					isCAVGroupQuery = checkFilter(query, resourceEndPoint);

					if (!isCAVGroupQuery) {
						q = ((Uid) filterAttr).getUidValue();
					} else {
						q = ((Uid) filterAttr).getUidValue();
						resourceEndPoint = "Users";
					}
				} else {

					isCAVGroupQuery = checkFilter(query, resourceEndPoint);

					if (!isCAVGroupQuery) {
						LOGGER.info("Attribute not instance of UID");
						q = qIsFilter(query, queryUriSnippet, providerName, resourceEndPoint);
					} else {
						q = (String) filterAttr.getValue().get(0);
						resourceEndPoint = "Users";
					}

				}

			} else {

				isCAVGroupQuery = checkFilter(query, resourceEndPoint);

				if (!isCAVGroupQuery) {
					q = qIsFilter(query, queryUriSnippet, providerName, resourceEndPoint);
				} else {

					Attribute filterAttr = ((AttributeFilter) query).getAttribute();
					q = (String) filterAttr.getValue().get(0);
					resourceEndPoint = "Users";
				}
			}

		} else {
			LOGGER.info("No filter was defined, query will return all the resource values");
			q = queryUriSnippet.toString();

		}

		final HttpClient httpClient = initHttpClient(conf);
		final String uri = scimBaseUri + SLASH + resourceEndPoint + SLASH + q;
		LOGGER.info("Query url: {0}", uri);

		final HttpGet httpGet = buildHttpGet(uri, authHeader);
		String responseString;

		try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpGet)) {
			int statusCode = response.getStatusLine().getStatusCode();
			final HttpEntity entity = response.getEntity();

			if (entity != null) {
				responseString = EntityUtils.toString(entity);
			} else {
				responseString = "";
			}

			LOGGER.info("Status code: {0}", statusCode);
			if (statusCode == 200) {

				if (!responseString.isEmpty()) {
					try {
						final JSONObject jsonObject = new JSONObject(responseString);

						 LOGGER.info("Json object returned from service provider: {0}", jsonObject.toString(1));
						try {

							if (valueIsUid) {

								final ConnectorObject connectorObject = buildConnectorObject(jsonObject, resourceEndPoint);
								resultHandler.handle(connectorObject);

							} else {

								if (isCAVGroupQuery) {

									handleCAVGroupQuery(jsonObject, GROUPS, resultHandler, scimBaseUri, authHeader,
											conf);

								} else if (jsonObject.has(RESOURCES)) {
									final int amountOfResources = jsonObject.getJSONArray(RESOURCES).length();
									int totalResults = 0;
									int startIndex = 0;
									int itemsPerPage = 0;

									if (jsonObject.has(START_INDEX) && jsonObject.has(TOTAL_RESULTS)
											&& jsonObject.has(ITEMS_PER_PAGE)) {
										totalResults = (int) jsonObject.get(TOTAL_RESULTS);
										startIndex = (int) jsonObject.get(START_INDEX);
										itemsPerPage = (int) jsonObject.get(ITEMS_PER_PAGE);
									}

									for (int i = 0; i < amountOfResources; i++) {
										final JSONObject minResourceJson = jsonObject.getJSONArray(RESOURCES).getJSONObject(i);
										if (minResourceJson.has(ID) && minResourceJson.getString(ID) != null) {

											if (minResourceJson.has(USERNAME)) {

												final ConnectorObject connectorObject = buildConnectorObject(minResourceJson,
														resourceEndPoint);

												resultHandler.handle(connectorObject);
											} else if (!USERS.equals(resourceEndPoint)) {

												if (minResourceJson.has(DISPLAYNAME)) {
													final ConnectorObject connectorObject = buildConnectorObject(
															minResourceJson, resourceEndPoint);
													resultHandler.handle(connectorObject);
												}
											} else if (minResourceJson.has(META)) {

												final String resourceUri = minResourceJson.getJSONObject(META)
														.getString("location");

												final HttpGet httpGetR = buildHttpGet(resourceUri, authHeader);
												try (CloseableHttpResponse resourceResponse = (CloseableHttpResponse) httpClient
														.execute(httpGetR)) {

													statusCode = resourceResponse.getStatusLine().getStatusCode();
													responseString = EntityUtils.toString(resourceResponse.getEntity());
													if (statusCode == 200) {

														final JSONObject fullResourceJSON = new JSONObject(responseString);

														// LOGGER.info(
														// "The {0}. resource
														// jsonObject which was
														// returned by the
														// service
														// provider: {1}",
														// i + 1,
														// fullResourceJSON);

														final ConnectorObject connectorObject = buildConnectorObject(
																fullResourceJSON, resourceEndPoint);

														resultHandler.handle(connectorObject);

													} else {

														ErrorHandler.onNoSuccess(responseString, statusCode,
																resourceUri);

													}
												}
											}
										} else {
											LOGGER.error("No uid present in fetched object: {0}", minResourceJson);

											throw new ConnectorException(
													"No uid present in fetched object while processing query result");

										}
									}
									if (resultHandler instanceof SearchResultsHandler) {
										boolean allResultsReturned = false;
										int remainingResult = totalResults - (startIndex - 1) - itemsPerPage;

										if (remainingResult <= 0) {
											remainingResult = 0;
											allResultsReturned = true;

										}

										// LOGGER.info("The number of remaining
										// results: {0}", remainingResult);
										final SearchResult searchResult = new SearchResult(DEFAULT, remainingResult,
												allResultsReturned);
										((SearchResultsHandler) resultHandler).handleResult(searchResult);
									}

								} else {

									LOGGER.error("Resource object not present in provider response to the query");

									throw new ConnectorException(
											"No uid present in fetched object while processing query result");

								}
							}

						} catch (Exception e) {
							LOGGER.error(
									"Builder error. Error while building connId object. The exception message: {0}",
									e.getLocalizedMessage());
							LOGGER.info("Builder error. Error while building connId object. The exception message: {0}",
									e);
							throw new ConnectorException("Builder error. Error while building connId object.", e);
						}

					} catch (JSONException jsonException) {
						if (q == null) {
							q = "the full resource representation";
						}
						LOGGER.error(
								"An exception has occurred while setting the variable \"jsonObject\". Occurrence while processing the http response to the query request for: {1}, exception message: {0}",
								jsonException.getLocalizedMessage(), q);
						LOGGER.info(
								"An exception has occurred while setting the variable \"jsonObject\". Occurrence while processing the http response to the query request for: {1}, exception message: {0}",
								jsonException, q);
						throw new ConnectorException(
								"An exception has occurred while setting the variable \"jsonObject\".", jsonException);
					}

				} else {

					LOGGER.warn("Service provider response is empty, response returned on query: {0}", q);
				}
			} else if (statusCode == 401) {

				handleInvalidStatus("while querying for resources. ", responseString, "retrieving an object",
						statusCode);

			} else if (valueIsUid) {

				LOGGER.info("About to throw an exception, the resource: {0} was not found.", q);

				ErrorHandler.onNoSuccess(responseString, statusCode, uri);

				final String errorBuilder = "The resource with the uid: " + q +
						" was not found.";

				throw new UnknownUidException(errorBuilder);
			} else if (statusCode == 404) {

				final String error = ErrorHandler.onNoSuccess(responseString, statusCode, uri);
				LOGGER.warn("Resource not found: {0}", error);
			} else {
				ErrorHandler.onNoSuccess(responseString, statusCode, uri);
			}

		} catch (IOException e) {

			if (q == null) {
				q = "the full resource representation";
			}

			final StringBuilder errorBuilder = new StringBuilder(
					"An error occurred while processing the query http response for ");
			errorBuilder.append(q);
			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

				errorBuilder.insert(0, "The connection timed out while closing the http connection. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error occurred while processing the query http response. Occurrence while processing the http response to the query request for: {1}, exception message: {0}",
						e.getLocalizedMessage(), q);
				LOGGER.info(
						"An error occurred while processing the query http response. Occurrence while processing the http response to the query request for: {1}, exception message: {0}",
						e, q);
				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}
	}

	@Override
	public Uid update(final Uid uid, final String resourceEndPoint, final ObjectTranslator objectTranslator, final Set<Attribute> attributes,
			final ScimConnectorConfiguration conf) {

		final ServiceAccessManager accessManager = new ServiceAccessManager(conf, this);

		final Header authHeader = accessManager.getAuthHeader();
		final String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {
			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		final HttpClient httpClient = initHttpClient(conf);

		final String uri = scimBaseUri + SLASH + resourceEndPoint + SLASH +
				uid.getUidValue();
		LOGGER.info("The uri for the update request: {0}", uri);

		String responseString;
		try {
			LOGGER.info("Query url: {0}", uri);

			final JSONObject jsonObject = objectTranslator.translateSetToJson(attributes, null, resourceEndPoint);
			LOGGER.info("The update json object: {0}", jsonObject);

			final HttpPatch httpPatch = buildHttpPatch(uri, authHeader, jsonObject);

			try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpPatch)) {

				int statusCode = response.getStatusLine().getStatusCode();

				final HttpEntity entity = response.getEntity();

				if (entity != null) {
					responseString = EntityUtils.toString(entity);
				} else {
					responseString = "";
				}
				if (statusCode == 200  || statusCode == 201) {
					LOGGER.info("Update of resource was successful");

					if (!responseString.isEmpty()) {
						final JSONObject json = new JSONObject(responseString);
						 LOGGER.ok("Json response: {0}", json.toString());
						return new Uid(json.getString(ID));

					} else {
						LOGGER.warn("Service provider response is empty, no response after the update procedure");
					}
				} else if (statusCode == 204) {

					LOGGER.warn("Status code {0}. Response body left intentionally empty", statusCode);

					return uid;
				} else if (statusCode == 404) {

					ErrorHandler.onNoSuccess(responseString, statusCode, uri);

					final String errorBuilder = "The resource with the uid: " + uid +
							" was not found.";

					throw new UnknownUidException(errorBuilder);

				} else if (statusCode == 500 && GROUPS.equals(resourceEndPoint)) {

					final Uid id = groupUpdateProcedure(statusCode, jsonObject, uri, authHeader, conf);

					if (id != null) {

						return id;
					} else {
						ErrorHandler.onNoSuccess(responseString, statusCode, "updating object");
					}
				} else {
					handleInvalidStatus("while updating resource. ", responseString, "updating object", statusCode);
				}
			}

		} catch (UnsupportedEncodingException e) {

			LOGGER.error("Unsupported encoding: {0}. Occurrence in the process of updating a resource object ",
					e.getMessage());
			LOGGER.info("Unsupported encoding: {0}. Occurrence in the process of updating a resource object ", e);

			throw new ConnectorException(
					"Unsupported encoding, Occurrence in the process of updating a resource object ", e);

		} catch (JSONException e) {

			LOGGER.error(
					"An exception has occurred while processing a json object. Occurrence in the process of updating a resource object: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An exception has occurred while processing a json object. Occurrence in the process of updating a resource object: {0}",
					e);

			throw new ConnectorException(
					"An exception has occurred while processing a json object,Occurrence in the process of updating a resource object",
					e);

		} catch (ClientProtocolException e) {
			LOGGER.error(
					"An protocol exception has occurred while in the process of updating a resource object. Possible mismatch in the interpretation of the HTTP specification: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An protocol exception has occurred while in the process of updating a resource object. Possible mismatch in the interpretation of the HTTP specification: {0}",
					e);
			throw new ConnectionFailedException(
					"An protocol exception has occurred while in the process of updating a resource object, Possible mismatch in the interpretation of the HTTP specification.",
					e);

		} catch (IOException e) {

			final StringBuilder errorBuilder = new StringBuilder(
					"An error has occurred while processing the http response. Occurrence in the process of updating a resource object wit the Uid: ");

			errorBuilder.append(uid);

			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {
				errorBuilder.insert(0, "The connection timed out. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error has occurred while processing the http response. Occurrence in the process of updating a resource object: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An error has occurred while processing the http response. Occurrence in the process of updating a resource object: {0}",
						e);

				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}

		return null;
	}

	@Override
	public void delete(final Uid uid, final String resourceEndPoint, final ScimConnectorConfiguration conf) {

		final ServiceAccessManager accessManager = new ServiceAccessManager(conf, this);

		final Header authHeader = accessManager.getAuthHeader();
		final String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {
			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		final HttpClient httpClient = initHttpClient(conf);

		final String uri = scimBaseUri + SLASH + resourceEndPoint + SLASH +
				uid.getUidValue();

		LOGGER.info("The uri for the delete request: {0}", uri);
		final HttpDelete httpDelete = buildHttpDelete(uri, authHeader);

		try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpDelete)) {
			final int statusCode = response.getStatusLine().getStatusCode();

			if (statusCode == 204 || statusCode == 200) {
				LOGGER.info("Deletion of resource was successful");
			} else {

				String responseString;
				final HttpEntity entity = response.getEntity();

				if (entity != null) {
					responseString = EntityUtils.toString(entity);
				} else {
					responseString = "";
				}

				handleInvalidStatus("while deleting resource. ", responseString, "deleting object", statusCode);
			}

		} catch (ClientProtocolException e) {
			LOGGER.error(
					"An protocol exception has occurred while in the process of deleting a resource object. Possible mismatch in the interpretation of the HTTP specification: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An protocol exception has occurred while in the process of deleting a resource object. Possible mismatch in the interpretation of the HTTP specification: {0}",
					e);
			throw new ConnectionFailedException(
					"An protocol exception has occurred while in the process of deleting a resource object. Possible mismatch in the interpretation of the HTTP specification.",
					e);

		} catch (IOException e) {

			final StringBuilder errorBuilder = new StringBuilder(
					"An error has occurred while processing the http response. Occurrence in the process of deleting a resource object with the Uid:  ");

			errorBuilder.append(uid);

			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

				errorBuilder.insert(0, "Connection timed out. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error has occurred while processing the http response. Occurrence in the process of deleting a resource object: : {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An error has occurred while processing the http response. Occurrence in the process of deleting a resource object: : {0}",
						e);

				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}
	}

	@Override
	public ParserSchemaScim querySchemas(final String providerName, final String schemaEndPoint,
			final String usersEndpoint, final String groupsEndpoint, final ScimConnectorConfiguration conf) {

		final ServiceAccessManager accessManager = new ServiceAccessManager(conf, this);
		final Header authHeader = accessManager.getAuthHeader();
		final String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {
			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		final HttpClient schemaHttpClient = initHttpClient(conf);
		final List<String> schemaUrls = List.of(
				scimBaseUri + SLASH + schemaEndPoint,
				scimBaseUri + SLASH + schemaEndPoint + usersEndpoint,
				scimBaseUri + SLASH + schemaEndPoint + groupsEndpoint);

		List<String> excludedAttrs = new ArrayList<>();
		String responseString = "";
		int statusCode = 0;
		JSONObject responseObject = new JSONObject();
		JSONArray responseArray = new JSONArray();

		for (final String url : schemaUrls) {
			final HttpGet schemaHttpGet = buildHttpGet(url, authHeader);
			LOGGER.info("Query url: {0}", url);

			try (final CloseableHttpResponse response = (CloseableHttpResponse) schemaHttpClient.execute(schemaHttpGet)) {
				final HttpEntity entity = response.getEntity();

				if (entity != null) {
					responseString = EntityUtils.toString(entity);
				} else {
					responseString = "";
				}

				statusCode = response.getStatusLine().getStatusCode();
				LOGGER.info("Schema query status code: {0} ", statusCode);

				if (statusCode == 200 && responseString !=null && !responseString.isEmpty()) {
					final JSONObject jsonObject = injectMissingSchemaAttributes(url, new JSONObject(responseString));

					excludedAttrs = excludeFromAssembly(excludedAttrs);
					for (final String attribute : excludedAttrs) {
						LOGGER.ok("The attribute \"{0}\" will be omitted from the connId object build.", attribute);
					}

					if (url.equals(schemaUrls.get(0))) {
						responseObject = jsonObject;
						break; //skip Users and Groups if plain /Schemas/ succeeds

					} else {
						responseArray.put(jsonObject);
						responseObject.put(RESOURCES, responseArray);
					}

				} else {
					LOGGER.ok("Invalid status code {0} or empty response for query {1}.", statusCode, url);
				}

			} catch (ClientProtocolException ce) {
				LOGGER.error("An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification: {0}", ce.getLocalizedMessage());
				LOGGER.info("An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification: {0}", ce);
				throw new ConnectorException("An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification", ce);

			} catch (IOException ioe) {
				final StringBuilder errorBuilder = new StringBuilder("An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object");

				if ((ioe instanceof SocketTimeoutException || ioe instanceof NoRouteToHostException)) {
					errorBuilder.insert(0, "The connection timed out. ");
					throw new OperationTimeoutException(errorBuilder.toString(), ioe);
				} else {
					LOGGER.error("An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object: {0}", ioe.getLocalizedMessage());
					LOGGER.info("An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object: {0}", ioe);
					throw new ConnectorIOException(errorBuilder.toString(), ioe);
				}

			} catch (Exception e) {
				LOGGER.ok("Error while querying for schema attempting different url endpoints. [" + statusCode + "],[" + responseString + "]", e);
			}
		}

		if (statusCode != 200) {
			try {
				handleInvalidStatus("while querying for schema. ", responseString, "schema", statusCode);
			} catch (IOException ioe) {
				LOGGER.error("Error processing invalid status code. ", ioe);
			}
		} else if (responseObject == JSONObject.NULL) {
			LOGGER.warn("No definition for provided schemas was found! The connector will switch to default generic scim schema configuration!");
			return null;

		} else {
			return processSchemaResponse(responseObject);
		}

		LOGGER.ok("Error or empty result during schema processing! The connector will switch to default generic scim schema configuration!");
		return null;
	}

	@Override
	public JSONObject injectMissingSchemaAttributes(final String resourceName, final JSONObject jsonObject) {
		return jsonObject;
	}

	@Override
	public ParserSchemaScim processSchemaResponse(final JSONObject responseObject) {

		// LOGGER.info("The resources json representation: {0}",
		// responseObject.toString(1));
		final ParserSchemaScim scimParser = new ParserSchemaScim();
		for (int i = 0; i < responseObject.getJSONArray(RESOURCES).length(); i++) {
			final JSONObject minResourceJson = responseObject.getJSONArray(RESOURCES).getJSONObject(i);

			if (minResourceJson != null && (minResourceJson.has("endpoint") || minResourceJson.has("id"))) {

				if (!minResourceJson.has("endpoint")) {
					final Object id = minResourceJson.get("id");
					if (id == null || (!id.toString().contains(USER_V2_SCHEMA_ID)
							&& !id.toString().contains(GROUP_V2_SCHEMA_ID)
							&& !id.toString().contains(USER_V1_SCHEMA_ID)
							&& !id.toString().contains(GROUP_V1_SCHEMA_ID))) {

						LOGGER.warn("Error processing returned SCIM schema object. No valid User or Group SCIM v1 or v2 definition found in {0}!", minResourceJson);
					}
				}

				scimParser.parseSchema(minResourceJson, this);

			} else {
				LOGGER.error("No endpoint or SCIM id identifier present in fetched schema object: {0}", minResourceJson);
				throw new ConnectorException("No endpoint or identifier present in fetched schema object while processing schema query result");
			}
		}

		return scimParser;

	}

	@Override
	public Map<String, Map<String, Object>> parseSchemaAttribute(final JSONObject attribute,
			 Map<String, Map<String, Object>> attributeMap, final ParserSchemaScim parser) {

		try {
			String attributeName = null;
			Boolean isComplex = false;
			Boolean isMultiValued = false;
			boolean hasSubAttributes = false;
			String nameFromDictionary = "";
			final Map<String, Object> attributeObjects = new HashMap<>();
			Map<String, Object> subAttributeMap = new HashMap<>();

			final List<String> dictionary = populateDictionary(WorkaroundFlags.PARSERFLAG);
			final List<String> excludedAttributes = defineExcludedAttributes();

			for (final String s : dictionary) {
				nameFromDictionary = s;

				if (attribute.has(nameFromDictionary)) {

					hasSubAttributes = true;
					break;
				}

			}
			if (hasSubAttributes) {

				boolean hasTypeValues = false;
				final JSONArray subAttributes = (JSONArray) attribute.get(nameFromDictionary);
				for (final String subAttributeNameKeys : attribute.keySet()) {
					if (NAME.equals(subAttributeNameKeys)) {
						attributeName = attribute.get(subAttributeNameKeys).toString();

						if (attributeName.contains(FORBIDDEN_SEPARATOR)) {
							attributeName = attributeName.replace(FORBIDDEN_SEPARATOR, SEPARATOR);
						}

						break;
					}
				}

				if (!excludedAttributes.contains(attributeName)) {

					for (final String nameKey : attribute.keySet()) {
						if (MULTIVALUED.equals(nameKey)) {
							isMultiValued = (Boolean) attribute.get(nameKey);
							break;
						}
					}

					for (int i = 0; i < subAttributes.length(); i++) {
						final JSONObject subAttribute = subAttributes.getJSONObject(i);
						subAttributeMap = parser.parseSubAttribute(subAttribute, subAttributeMap);
					}

					for (final String typeKey : subAttributeMap.keySet()) {
						if (TYPE.equals(typeKey)) {
							hasTypeValues = true;
							break;
						}
					}

					if (hasTypeValues) {
						final Map<String, Object> typeObject = (HashMap<String, Object>) subAttributeMap.get(TYPE);

						if (typeObject.containsKey(CANONICAL_VALUES) || typeObject.containsKey(REFERENCE_TYPES)) {
							final JSONArray referenceValues;

							if (typeObject.containsKey(CANONICAL_VALUES)) {
								referenceValues = (JSONArray) typeObject.get(CANONICAL_VALUES);
							} else {
								referenceValues = (JSONArray) typeObject.get(REFERENCE_TYPES);
							}

							for (int position = 0; position < referenceValues.length(); position++) {
								final Map<String, Object> processedParameters = translateReferenceValues(attributeMap,
										referenceValues, subAttributeMap, position, attributeName);

								for (String parameterName : processedParameters.keySet()) {
									if (ISCOMPLEX.equals(parameterName)) {
										isComplex = (Boolean) processedParameters.get(parameterName);

									} else {
										attributeMap = (Map<String, Map<String, Object>>) processedParameters.get(parameterName);
									}
								}
							}
						} else {
							// default set of canonical values.

							final List<String> defaultReferenceTypeValues = new ArrayList<>();
							defaultReferenceTypeValues.add("User");
							defaultReferenceTypeValues.add("Group");

							defaultReferenceTypeValues.add("external");
							defaultReferenceTypeValues.add(URI);

							for (final String subAttributeKeyNames : subAttributeMap.keySet()) {
								if (!TYPE.equals(subAttributeKeyNames)) {
									for (final String defaultTypeReferenceValues : defaultReferenceTypeValues) {
										final StringBuilder complexAttrName = ((StringUtil.isNotBlank(attributeName)) ? new StringBuilder(attributeName) : new StringBuilder());
										complexAttrName.append(DOT).append(defaultTypeReferenceValues);
										attributeMap.put(
												complexAttrName.append(DOT).append(subAttributeKeyNames).toString(),
												(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
										isComplex = true;
									}
								}
							}
						}
					} else {

						if (!isMultiValued) {
							for (final String subAttributeKeyNames : subAttributeMap.keySet()) {
								final StringBuilder complexAttrName = ((StringUtil.isNotBlank(attributeName)) ? new StringBuilder(attributeName) : new StringBuilder());
								attributeMap.put(complexAttrName.append(DOT).append(subAttributeKeyNames).toString(),
										(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
								isComplex = true;
							}
						} else {
							for (final String subAttributeKeyNames : subAttributeMap.keySet()) {
								final StringBuilder complexAttrName = ((StringUtil.isNotBlank(attributeName)) ? new StringBuilder(attributeName) : new StringBuilder());

								final Map<String, Object> subattributeKeyMap = (HashMap<String, Object>) subAttributeMap
										.get(subAttributeKeyNames);

								for (final String attributeProperty : subattributeKeyMap.keySet()) {

									if (MULTIVALUED.equals(attributeProperty)) {
										subattributeKeyMap.put(MULTIVALUED, true);
									}
								}
								attributeMap.put(complexAttrName.append(DOT).append(DEFAULT).append(DOT)
										.append(subAttributeKeyNames).toString(), subattributeKeyMap);
								isComplex = true;
							}
						}
					}
				}
			} else {

				for (final String attributeNameKeys : attribute.keySet()) {
					if (!excludedAttributes.contains(attributeName)) {
						if (NAME.equals(attributeNameKeys)) {
							attributeName = attribute.get(attributeNameKeys).toString();
							if (attributeName.contains(FORBIDDEN_SEPARATOR)) {
								attributeName = attributeName.replace(FORBIDDEN_SEPARATOR, SEPARATOR);
							}
						} else {
							attributeObjects.put(attributeNameKeys, attribute.get(attributeNameKeys));
						}
					} else {
						if (!attributeObjects.isEmpty()) {

							attributeObjects.clear();
						}
					}
				}
			}
			if (!isComplex) {
				if (!attributeObjects.isEmpty()) {
					attributeMap.put(attributeName, attributeObjects);
				}
			}

		} catch (ClassCastException|JSONException e) {
			LOGGER.ok("Error parsing schema attribute {0} with {1}!", attribute.toString(), e);
			throw e;
			//throw new ConnectorException("Error parsing schema attribute {0}!", e);
		}

		return attributeMap;
	}

	@Override
	public List<Map<String, Map<String, Object>>> getAttributeMapList(
			final List<Map<String, Map<String, Object>>> attributeMapList) {
		return attributeMapList;
	}

	@Override
	public Map<String, Object> translateReferenceValues(final Map<String, Map<String, Object>> attributeMap,
			final JSONArray referenceValues, final Map<String, Object> subAttributeMap, final int position, final String attributeName) {

		Boolean isComplex = null;
		final Map<String, Object> processedParameters = new HashMap<>();

		String stringReferenceValue;
		try {
			stringReferenceValue = (String) referenceValues.get(position);
		} catch (ClassCastException ce) {
			stringReferenceValue = ((JSONObject) referenceValues.get(position)).getString("value");
		}

		for (final String subAttributeKeyNames : subAttributeMap.keySet()) {
			if (!TYPE.equals(subAttributeKeyNames)) {

				final StringBuilder complexAttrName = new StringBuilder(attributeName);
				attributeMap.put(complexAttrName.append(DOT).append(stringReferenceValue).append(DOT)
						.append(subAttributeKeyNames).toString(),
						(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
				isComplex = true;

			}
		}
		if (isComplex != null) {
			processedParameters.put(ISCOMPLEX, isComplex);
		}
		processedParameters.put("attributeMap", attributeMap);

		return processedParameters;
	}

	@Override
	public List<String> defineExcludedAttributes() {

		//TODO?
		return new ArrayList<>();
	}

	@Override
	public Set<Attribute> addAttributesToInject(final Set<Attribute> injectetAttributeSet) {
		return injectetAttributeSet;
	}

	@Override
	public Uid groupUpdateProcedure(final Integer statusCode, final JSONObject jsonObject, final String uri, final Header authHeader,
			final ScimConnectorConfiguration conf) {
		return null;
	}

	@Override
	public ConnectorObject buildConnectorObject(final JSONObject resourceJsonObject, final String resourceEndPoint)
			throws ConnectorException {

		List<String> excludedAttributes = new ArrayList<>();
		LOGGER.info("Building the connector object from provided json");

		if (resourceJsonObject == null) {
			LOGGER.error(
					"Empty json object was passed from data provider. Error occurrence while building connector object");
			throw new ConnectorException(
					"Empty json object was passed from data provider. Error occurrence while building connector object");
		}

		final ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
		cob.setUid(resourceJsonObject.getString(ID));
		excludedAttributes.add(ID);

		if (USERS.equals(resourceEndPoint)) {
			cob.setName(resourceJsonObject.getString(USERNAME));
			excludedAttributes.add(USERNAME);

		} else if (GROUPS.equals(resourceEndPoint)) {

			cob.setName(resourceJsonObject.getString(DISPLAYNAME));
			excludedAttributes.add(DISPLAYNAME);
			cob.setObjectClass(ObjectClass.GROUP);

		} else {
			cob.setName(resourceJsonObject.getString(DISPLAYNAME));
			excludedAttributes.add(DISPLAYNAME);
			final ObjectClass objectClass = new ObjectClass(resourceEndPoint);
			cob.setObjectClass(objectClass);

		}

		for (String key : resourceJsonObject.keySet()) {
			final Object attribute = resourceJsonObject.get(key);

			excludedAttributes = excludeFromAssembly(excludedAttributes);

			if (excludedAttributes.contains(key)) {
				//LOGGER.warn("The attribute \"{0}\" was omitted from the connId object build.", key);
				//TODO?
			}

			if (attribute instanceof JSONArray) {

				final JSONArray attributeArray = (JSONArray) attribute;

				final Map<String, Collection<Object>> multivaluedAttributeMap = new HashMap<>();
				Collection<Object> attributeValues = new ArrayList<>();

				for (final Object singleAttribute : attributeArray) {
					StringBuilder objectNameBuilder = new StringBuilder(key);
					String objectKeyName = "";

					if (singleAttribute instanceof JSONObject) {
						for (final String singleSubAttribute : ((JSONObject) singleAttribute).keySet()) {
							if (TYPE.equals(singleSubAttribute)) {
								objectKeyName = objectNameBuilder.append(DOT)
										.append(((JSONObject) singleAttribute).get(singleSubAttribute)).toString();
								objectNameBuilder.delete(0, objectNameBuilder.length());
								break;
							}
						}

						for (final String singleSubAttribute : ((JSONObject) singleAttribute).keySet()) {
							Object sAttributeValue;
							if (((JSONObject) singleAttribute).isNull(singleSubAttribute)) {
								sAttributeValue = null;
							} else {

								sAttributeValue = ((JSONObject) singleAttribute).get(singleSubAttribute);
							}

							if (TYPE.equals(singleSubAttribute)) {
								//TODO?
							} else {

								if (!"".equals(objectKeyName)) {
									objectNameBuilder.append(objectKeyName).append(DOT).append(singleSubAttribute);
								} else {
									objectKeyName = objectNameBuilder.append(DOT).append(DEFAULT).toString();
									objectNameBuilder.append(DOT).append(singleSubAttribute);
								}

								if (attributeValues.isEmpty()) {

									attributeValues.add(sAttributeValue);
									multivaluedAttributeMap.put(objectNameBuilder.toString(), attributeValues);
								} else {
									if (multivaluedAttributeMap.containsKey(objectNameBuilder.toString())) {
										attributeValues = multivaluedAttributeMap.get(objectNameBuilder.toString());
										attributeValues.add(sAttributeValue);
									} else {
										Collection<Object> newAttributeValues = new ArrayList<>();
										newAttributeValues.add(sAttributeValue);
										multivaluedAttributeMap.put(objectNameBuilder.toString(), newAttributeValues);
									}

								}
								objectNameBuilder.delete(0, objectNameBuilder.length());

							}
						}
					} else {
						objectKeyName = objectNameBuilder.append(DOT).append(singleAttribute.toString()).toString();
						cob.addAttribute(objectKeyName, singleAttribute);
					}
				}

				if (!multivaluedAttributeMap.isEmpty()) {
					for (String attributeName : multivaluedAttributeMap.keySet()) {
						cob.addAttribute(attributeName, multivaluedAttributeMap.get(attributeName));
					}

				}

			} else if (attribute instanceof JSONObject) {
				for (final String s : ((JSONObject) attribute).keySet()) {
					Object attributeValue;
					if (key.contains(FORBIDDEN_SEPARATOR)) {
						key = key.replace(FORBIDDEN_SEPARATOR, SEPARATOR);
					}

					if (((JSONObject) attribute).isNull(s)) {

						attributeValue = null;

					} else {

						attributeValue = ((JSONObject) attribute).get(s);

					}

					final StringBuilder objectNameBuilder = new StringBuilder(key);
					cob.addAttribute(objectNameBuilder.append(DOT).append(s).toString(), attributeValue);
				}

			} else {

				if (ACTIVE.equals(key)) {
					cob.addAttribute(OperationalAttributes.ENABLE_NAME, resourceJsonObject.get(key));
				} else {

					if (!resourceJsonObject.isNull(key)) {

						cob.addAttribute(key, resourceJsonObject.get(key));
					} else {
						Object value = null;
						cob.addAttribute(key, value);

					}
				}
			}
		}

		final ConnectorObject finalConnectorObject = cob.build();
		// LOGGER.info("The connector object returned from the processed json:
		// {0}", finalConnectorObject);
		return finalConnectorObject;

	}

	@Override
	public List<String> excludeFromAssembly(final List<String> excludedAttributes) {

		excludedAttributes.add(META);
		excludedAttributes.add("schemas");
		//excludedAttributes.add("urn:scim:schemas:extension:enterprise:1.0"); //TODO check this extension attribute
		return excludedAttributes;
	}

	@Override
	public Set<Attribute> attributeInjection(final Set<Attribute> injectedAttributeSet, JSONObject loginJson) {
		return injectedAttributeSet;
	}

	@Override
	public StringBuilder processContainsAllValuesFilter(final String p, final ContainsAllValuesFilter filter,
			final FilterHandler handler) {
		return handler.processArrayQ(filter, p);
	}

	@Override
	public ObjectClassInfoBuilder schemaBuilder(final String attributeName, final Map<String, Map<String, Object>> attributeMap,
			ObjectClassInfoBuilder builder, final SchemaObjectBuilderGeneric schemaBuilder) {

		AttributeInfoBuilder infoBuilder = new AttributeInfoBuilder(attributeName);
		boolean containsDictionaryValue = false;
		Map<String, Object> caseHandlingMap = new HashMap<>();

		List<String> dictionary = populateDictionary(WorkaroundFlags.BUILDERFLAG);

		if (dictionary.contains(attributeName)) {
			containsDictionaryValue = true;
		}

		if (!containsDictionaryValue) {
			dictionary.clear();
			final Map<String, Object> schemaSubPropertysMap = attributeMap.get(attributeName);

			for (final String subPropertyName : schemaSubPropertysMap.keySet()) {
				containsDictionaryValue = false;
				dictionary = populateDictionary(WorkaroundFlags.PARSERFLAG);

				if (dictionary.contains(subPropertyName)) {
					containsDictionaryValue = true;
				}

				if (containsDictionaryValue) {
					// TODO check positive cases
					infoBuilder = new AttributeInfoBuilder(attributeName);
					final JSONArray jsonArray = new JSONArray();
LOGGER.info("The sub property name: {0}", subPropertyName);
				/*	jsonArray = ((JSONArray) schemaSubPropertiesMap.get(subPropertyName));
					for (int i = 0; i < jsonArray.length(); i++) {
						JSONObject attribute = new JSONObject();
						attribute = jsonArray.getJSONObject(i);
					}*/
					break;
				} else {

					if ("type".equals(subPropertyName)) {

						if ("string".equals(schemaSubPropertysMap.get(subPropertyName).toString())) {

							caseHandlingMap.put("type", "string");

						} else if ("boolean".equals(schemaSubPropertysMap.get(subPropertyName).toString())) {

							caseHandlingMap.put("type", "bool");
							infoBuilder.setType(Boolean.class);
						}
					} else if ("caseExact".equals(subPropertyName)) {

						caseHandlingMap.put("caseExact", schemaSubPropertysMap.get(subPropertyName));
					}

					infoBuilder = schemaBuilder.subPropertiesChecker(infoBuilder, schemaSubPropertysMap,
							subPropertyName);
					infoBuilder = schemaObjectParametersInjection(infoBuilder, attributeName);

				}

			}
			if (!caseHandlingMap.isEmpty()) {
				if (caseHandlingMap.containsKey("type")) {
					if ("string".equals(caseHandlingMap.get("type"))) {
						infoBuilder.setType(String.class);
						if (caseHandlingMap.containsKey("caseExact")) {
							if (!(Boolean) caseHandlingMap.get("caseExact")) {
								infoBuilder.setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE);
							}
						}
					} else if ("boolean".equals(caseHandlingMap.get("type"))) {
						infoBuilder.setType(Boolean.class);
					}

				}

			}

			builder.addAttributeInfo(infoBuilder.build());
		} else {
			builder = schemaObjectInjection(builder, attributeName, infoBuilder);
		}
		return builder;
	}

	@Override
	public ObjectClassInfoBuilder schemaObjectInjection(final ObjectClassInfoBuilder builder, final String attributeName,
			final AttributeInfoBuilder infoBuilder) {

		builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);
		builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

		return builder;
	}

	@Override
	public AttributeInfoBuilder schemaObjectParametersInjection(final AttributeInfoBuilder infoBuilder,
			final String attributeName) {
		return infoBuilder;
	}

	@Override
	public List<String> populateDictionary(final WorkaroundFlags flag) {

		final List<String> dictionary = new ArrayList<>();

		if (WorkaroundFlags.PARSERFLAG.getValue().equals(flag.getValue())) {
			dictionary.add(SUBATTRIBUTES);
		} else if (WorkaroundFlags.BUILDERFLAG.getValue().equals(flag.getValue())) {

			dictionary.add(ACTIVE);
		} else {

			LOGGER.warn("No such flag defined: {0}", flag);
		}
		return dictionary;

	}

	@Override
	public Boolean checkFilter(final Filter filter, final String endpointName) {
		LOGGER.info("Check filter standard");
		return false;
	}

	/**
	 * Called when the query is evaluated as a filter not containing an uid
	 * type attribute.
	 * 
	 * @param query
	 *            The provided filter query.
	 * @param queryUriSnippet
	 *            A part of the query uri which will build a larger query.
	 * @param providerName
	 * 			  The name of the provider.
	 * @param resourceEndPoint
	 *            The name of the endpoint which should be queried (e.g.
	 *            "Users").
	 */

	private String qIsFilter(final Filter query, final StringBuilder queryUriSnippet, final String providerName,
			final String resourceEndPoint) {

		final char prefixChar;
		final StringBuilder filterSnippet;
		if (queryUriSnippet.toString().isEmpty()) {
			prefixChar = QUERY_CHAR;

		} else {

			prefixChar = QUERY_DELIMITER;
		}

//		if (query instanceof AttributeFilter) {
//
//			attributeName = ((AttributeFilter) query).getName();
//
//			if ("__NAME__".equals(attributeName)) {
//
//				if (USERS.equals(resourceEndPoint)) {
//					attributeName = "userName";
//				} else {
//
//					attributeName = "displayName";
//				}
//
//			} else {
//				attributeName = "";
//
//			}
//
//		}


		filterSnippet = query.accept(new FilterHandler(), resourceEndPoint + DOT + providerName);

		queryUriSnippet.append(prefixChar).append("filter=").append(filterSnippet.toString());

		return queryUriSnippet.toString();
	}

	@Override
	public void handleCAVGroupQuery(final JSONObject jsonObject, final String resourceEndPoint, final ResultsHandler handler,
			final String scimBaseUri, final Header authHeader, final ScimConnectorConfiguration conf)
			throws IOException {

		final ConnectorObject connectorObject = buildConnectorObject(jsonObject, resourceEndPoint);

		handler.handle(connectorObject);

	}

	protected HttpPost buildHttpPost(final String uri, final Header authHeader, final JSONObject jsonBody)
			throws UnsupportedEncodingException, JSONException {

		final HttpPost httpPost = new HttpPost(uri);
		httpPost.addHeader(authHeader);
		httpPost.addHeader(PRETTYPRINTHEADER);

		final HttpEntity entity = new ByteArrayEntity(jsonBody.toString().getBytes(StandardCharsets.UTF_8));
		// LOGGER.info("The update JSON object which is being sent: {0}",
		// jsonBody);
		httpPost.setEntity(entity);
		httpPost.setHeader("Content-Type", CONTENTTYPE);

		// StringEntity bodyContent = new StringEntity(jsonBody.toString(1));

		// bodyContent.setContentType(CONTENT_TYPE);
		// httpPost.setEntity(bodyContent);

		return httpPost;
	}

	protected HttpGet buildHttpGet(final String uri, final Header authHeader) {

		final HttpGet httpGet = new HttpGet(uri);
		httpGet.addHeader(authHeader);
		httpGet.addHeader(PRETTYPRINTHEADER);

		return httpGet;
	}

	protected HttpPatch buildHttpPatch(final String uri, final Header authHeader, final JSONObject jsonBody)
			throws UnsupportedEncodingException, JSONException {

		final HttpPatch httpPatch = new HttpPatch(uri);

		httpPatch.addHeader(authHeader);
		httpPatch.addHeader(PRETTYPRINTHEADER);
		final HttpEntity entity = new ByteArrayEntity(jsonBody.toString().getBytes(StandardCharsets.UTF_8));
		// LOGGER.info("The update JSON object which is being sent: {0}",
		// jsonBody);
		httpPatch.setEntity(entity);
		// StringEntity bodyContent = new StringEntity(jsonBody.toString(1));

		// bodyContent.setContentType(CONTENT_TYPE);
		// httpPatch.setEntity(bodyContent);

		httpPatch.setHeader("Content-Type", CONTENTTYPE);

		return httpPatch;
	}

	protected HttpDelete buildHttpDelete(final String uri, final Header authHeader) {

		final HttpDelete httpDelete = new HttpDelete(uri);
		httpDelete.addHeader(authHeader);
		httpDelete.addHeader(PRETTYPRINTHEADER);
		return httpDelete;
	}

	public void handleInvalidStatus(final String errorPitch, final String responseString, final String situation, final int statusCode)
			throws ParseException, IOException {

		final String error = ErrorHandler.onNoSuccess(responseString, statusCode, situation);
		final StringBuilder errorString = new StringBuilder(errorPitch).append(error);

		switch (statusCode) {
			case 400:
				handleBadRequest(error);
				break;
			case 401:
				errorString.insert(0, "Unauthorized ");
				throw new InvalidCredentialException(errorString.toString());
			case 404:
				LOGGER.warn("Resource not found or resource was already deleted");
				break;
			case 409:
				errorString.insert(0, "Conflict ");
				throw new AlreadyExistsException(errorString.toString());
			case 500:
				errorString.insert(0, "Provider server error ");
				throw new ConnectorException(errorString.toString());
			default:
				LOGGER.warn(error);
				break;
		}
	}

	@Override
	public String getStrategyName() {
		return "standard";
	}

	public void handleBadRequest(final String error) {

		throw new ConnectorException(error);
	}

	protected HttpClient initHttpClient(final ScimConnectorConfiguration conf) {
		final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

		if (StringUtil.isNotEmpty(conf.getProxyUrl())) {
			final HttpHost proxy = new HttpHost(conf.getProxyUrl(), conf.getProxyPortNumber());
			final DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
			httpClientBuilder.setRoutePlanner(routePlanner);
		}

		return httpClientBuilder.build();
	}
}
