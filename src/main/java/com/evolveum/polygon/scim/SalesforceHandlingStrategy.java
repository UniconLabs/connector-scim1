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
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException;
import org.identityconnectors.framework.common.exceptions.OperationTimeoutException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.json.JSONArray;
import org.json.JSONObject;


/**
 * 
 * @author Macik
 *
 *         Implementation of the "HandlingStrategy" methods for the Slack
 *         service provider.
 *
 */

public class SalesforceHandlingStrategy extends StandardScimHandlingStrategy implements HandlingStrategy {

	private static final Log LOGGER = Log.getLog(SalesforceHandlingStrategy.class);
	private static final String SCHEMATYPE = "urn:scim:schemas:extension:enterprise:1.0";
	private static final String JSON = "json";

	private static List<String> multivaluedAttributes = new ArrayList<String>();
	private static List<String> writableAttributes = new ArrayList<String>();

	static {

		multivaluedAttributes.add("members.User.value");
		multivaluedAttributes.add("members.Group.value");
		multivaluedAttributes.add("members.default.value");
		multivaluedAttributes.add("members.default.display");

		// writableAttributes.add("name.formatted");
		// writableAttributes.add("entitlements.default.value");
		// writableAttributes.add("emails.work.value");
		// writableAttributes.add("phoneNumbers.work.value");
		// writableAttributes.add("phoneNumbers.fax.value");
		// writableAttributes.add("phoneNumbers.mobile.value");
		// writableAttributes.add("photos.thumbnail.value");
		// writableAttributes.add("roles.value");
		// writableAttributes.add("photos.photo.value");
		// writableAttributes.add("addresses.work.value");
		// writableAttributes.add("groups.default.value");
		// writableAttributes.add("addresses.thumbnail.value");
		// writableAttributes.add("members.default.display");
	}

	@Override
	public Map<String, Object> translateReferenceValues(Map<String, Map<String, Object>> attributeMap,
			JSONArray referenceValues, Map<String, Object> subAttributeMap, int position, String attributeName) {

		JSONObject referenceValue = new JSONObject();
		Boolean isComplex = null;
		Map<String, Object> processedParameters = new HashMap<String, Object>();

		LOGGER.info(
				"Processing trough Salesforce scim schema inconsistencies workaround (canonicalValues,referenceTypes)");
		referenceValue = ((JSONArray) referenceValues).getJSONObject(position);
		for (String subAttributeKeyNames : subAttributeMap.keySet()) {
			if (!TYPE.equals(subAttributeKeyNames)) {
				StringBuilder complexAttrName = new StringBuilder(attributeName);
				attributeMap.put(
						complexAttrName.append(DOT).append(referenceValue.get(VALUE)).append(DOT)
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
	public Uid groupUpdateProcedure(Integer statusCode, JSONObject jsonObject, String uri, Header authHeader,
			ScimConnectorConfiguration conf) {

		Uid id = null;
		HttpClient httpClient = initHttpClient(conf);
		LOGGER.info(
				"Status code from first update query: {0}. Processing trough Salesforce \"group/member update\" workaround. ",
				statusCode);
		HttpGet httpGet = buildHttpGet(uri, authHeader);
		try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpGet);) {
			statusCode = response.getStatusLine().getStatusCode();
			LOGGER.info("status code: {0}", statusCode);
			if (statusCode == 200) {

				String responseString = EntityUtils.toString(response.getEntity());
				if (!responseString.isEmpty()) {

					JSONObject json = new JSONObject(responseString);
					LOGGER.info("Json object returned from service provider: {0}", json);
					for (String attributeName : jsonObject.keySet()) {

						json.put(attributeName, jsonObject.get(attributeName));
					}

					StringEntity bodyContent = new StringEntity(json.toString(1));
					bodyContent.setContentType(CONTENTTYPE);

					HttpPatch httpPatch = new HttpPatch(uri);
					httpPatch.addHeader(authHeader);
					httpPatch.addHeader(PRETTYPRINTHEADER);
					httpPatch.setEntity(bodyContent);

					try (CloseableHttpResponse secondaryResponse = (CloseableHttpResponse) httpClient
							.execute(httpPatch)) {
						responseString = EntityUtils.toString(secondaryResponse.getEntity());
						statusCode = secondaryResponse.getStatusLine().getStatusCode();
						LOGGER.info("status code: {0}", statusCode);
						if (statusCode == 200 || statusCode == 201) {
							LOGGER.info("Update of resource was successful");

							json = new JSONObject(responseString);
							id = new Uid(json.getString(ID));
							LOGGER.ok("Json response: {0}", json.toString(1));
							return id;
						} else {
							ErrorHandler.onNoSuccess(responseString, statusCode, "updating object");
						}
					}
				}
			}

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

			StringBuilder errorBuilder = new StringBuilder("Occurrence in the process of creating a resource object");

			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {
				errorBuilder.insert(0, "The connection timed out. ");
				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error has occurred while processing the http response. Occurrence in the process of updating a resource object: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An error has occurred while processing the http response. Occurrence in the process of creating a resource object: {0}",
						e);

				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}
		return id;
	}

	@Override
	public List<String> excludeFromAssembly(List<String> excludedAttributes) {

		excludedAttributes.add("schemas");
		excludedAttributes.add(META);
		excludedAttributes.add("alias");

		return excludedAttributes;
	}

	@Override
	public Set<Attribute> attributeInjection(Set<Attribute> injectedAttributeSet, JSONObject loginObject) {

		String orgID = null;

		if (loginObject != null) {
			if (loginObject.has(ID)) {
				orgID = loginObject.getString(ID);
				String idParts[] = orgID.split("\\/");
				orgID = idParts[4];
			}
		} else {

			LOGGER.info("No json object returned after login");
		}
		// injection of organization ID into the set of attributes
		if (orgID != null) {
			LOGGER.info("The organization ID is: {0}", orgID);

			injectedAttributeSet.add(AttributeBuilder.build("schema.type", SCHEMATYPE));

			injectedAttributeSet.add(AttributeBuilder.build("schema.organization", orgID));
		} else {
			LOGGER.warn("No organization ID specified in instance URL");
		}
		return injectedAttributeSet;

	}

	@Override
	public StringBuilder processContainsAllValuesFilter(String p, ContainsAllValuesFilter filter,
			FilterHandler handler) {
		// members

		String attributeName = "";

		String[] keyParts = filter.getName().split("\\."); // eq.
		// members.User.value
		if (keyParts.length == 3) {

			String attributeNamePart = keyParts[0];

			if ("members".equals(attributeNamePart)) {

				attributeName = attributeNamePart;
			}

		}

		if (!attributeName.isEmpty()) {
			List<Object> valueList = filter.getAttribute().getValue();
			Collection<Filter> filterList = new ArrayList<Filter>();

			for (Object value : valueList) {
				Filter containsSingleAtribute = (EqualsFilter) FilterBuilder
						.equalTo(AttributeBuilder.build(attributeName, value));
				filterList.add(containsSingleAtribute);
			}

			for (Filter f : filterList) {

				return f.accept(new FilterHandler(), p);
			}
		}
		return null;
	}

	@Override
	public AttributeInfoBuilder schemaObjectParametersInjection(AttributeInfoBuilder infoBuilder,
			String attributeName) {

		if (multivaluedAttributes.contains(attributeName)) {
			infoBuilder.setMultiValued(true);
		} /*
			 * else if (writableAttributes.contains(attributeName)) {
			 * infoBuilder.setUpdateable(true); infoBuilder.setCreateable(true);
			 * infoBuilder.setReadable(true); }
			 */
		return infoBuilder;
	}

	public void handleBadRequest(String error) {

		List<String> uniqueAttributes = new ArrayList<String>();
		uniqueAttributes.add("invalid_grant");

		String[] parts = error.split("\"");
		for (String part : parts) {
			if (uniqueAttributes.contains(part)) {
				StringBuilder errorBuilder = new StringBuilder("Conflict. ").append(error).append(
						". Propably the value you have chosen is already taken, please chose another and try again.");
				throw new InvalidCredentialException(errorBuilder.toString());
			}
		}
		throw new ConnectorException(error);

	}

	@Override
	public String getStrategyName() {
		return "salesforce";
	}
}
