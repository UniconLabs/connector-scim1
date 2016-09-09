package com.evolveum.polygon.scim;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.json.JSONArray;
import org.json.JSONObject;

import com.evolveum.polygon.scim.common.HttpPatch;

public class SalesforceHandlingStrategy extends StandardScimHandlingStrategy implements HandlingStrategy {

	private static final Log LOGGER = Log.getLog(SalesforceHandlingStrategy.class);
	private static final String ID = "id";
	private static final String TYPE = "type";
	private static final String DEFAULT = "default";
	private static final String SCHEMATYPE = "urn:scim:schemas:extension:enterprise:1.0";
	private static final String SUBATTRIBUTES = "subAttributes";
	private static final String MULTIVALUED = "multiValued";
	private static final String CANONICALVALUES = "canonicalValues";
	private static final String REFERENCETYPES = "referenceTypes";
	private static final String CONTENTTYPE = "application/json";

	@Override
	public Set<Attribute> attributeInjection(Set<Attribute> injectedAttributeSet,
			Map<String, Object> autoriazationData) {

		JSONObject loginObject = null;
		String orgID = null;

		if (autoriazationData.containsKey("json")) {

			loginObject = (JSONObject) autoriazationData.get("json");
		}

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

			// TODO schema version might change
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
		return null;
	}

	@Override
	public Uid groupUpdateProcedure(HttpResponse response, JSONObject jsonObject, String uri, Header authHeader) {

		HttpClient httpClient = HttpClientBuilder.create().build();
		Uid id = null;
		Integer statusCode = response.getStatusLine().getStatusCode();

		LOGGER.warn(
				"Status code from first update query: {0}. Processing trought Salesforce \"group/member update\" workaround. ",
				statusCode);
		HttpGet httpGet = new HttpGet(uri);
		httpGet.addHeader(authHeader);
		httpGet.addHeader(PRETTYPRINTHEADER);

		try {
			response = httpClient.execute(httpGet);

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

					response = httpClient.execute(httpPatch);
					statusCode = response.getStatusLine().getStatusCode();
					LOGGER.info("status code: {0}", statusCode);
					if (statusCode == 200 || statusCode == 201) {
						LOGGER.info("Update of resource was succesfull");
						responseString = EntityUtils.toString(response.getEntity());
						json = new JSONObject(responseString);
						id = new Uid(json.getString(ID));
						LOGGER.ok("Json response: {0}", json.toString(1));
						return id;
					} else {
						responseString = EntityUtils.toString(response.getEntity());

						CrudManagerScim.onNoSuccess(response, "updating object");
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

			LOGGER.error(
					"An error has occurred while processing the http response. Occurrence in the process of updating a resource object: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An error has occurred while processing the http response. Occurrence in the process of creating a resource object: {0}",
					e);

			throw new ConnectorIOException(
					"An error has occurred while processing the http response. Occurrence in the process of creating a resource object",
					e);

		}

		return id;
	}

	@Override
	public List<String> excludeFromAssembly(List<String> excludedAttributes) {

		excludedAttributes.add("schemas");
		excludedAttributes.add("meta");
		excludedAttributes.add("alias");

		return excludedAttributes;
	}

	@Override
	public Map<String, Object> translateReferenceValues(Map<String, Map<String, Object>> attributeMap,
			JSONArray referenceValues, Map<String, Object> subAttributeMap, int position, String attributeName) {

		JSONObject referenceValue = new JSONObject();
		Boolean isComplex = null;
		Map<String, Object> processedParameters = new HashMap<String, Object>();

		/*
		 * Salesforce scim schema inconsistencies workaround
		 * (canonicalValues,referenceTypes) defined as array of json objects ->
		 * should be defined as array of string values
		 */
		LOGGER.warn(
				"Processing trought Salesforce scim schema inconsistencies workaround (canonicalValues,referenceTypes) ");
		referenceValue = ((JSONArray) referenceValues).getJSONObject(position);
		for (String subAttributeKeyNames : subAttributeMap.keySet()) {
			if (!TYPE.equals(subAttributeKeyNames)) {
				StringBuilder complexAttrName = new StringBuilder(attributeName);
				attributeMap.put(
						complexAttrName.append(".").append(referenceValue.get("value")).append(".")
								.append(subAttributeKeyNames).toString(),
						(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
				isComplex = true;

			}
		}
		if (isComplex != null) {
			processedParameters.put("isComplex", isComplex);
		}
		processedParameters.put("attributeMap", attributeMap);

		return processedParameters;
	}

	@Override
	public AttributeInfoBuilder injectAttributeInfoBuilderData(AttributeInfoBuilder infoBuilder, String attributeName) {

		if ("members.User.value".equals(attributeName) || "members.Group.value".equals(attributeName)
				|| "members.default.value".equals(attributeName) || "members.default.display".equals(attributeName)) {
			infoBuilder.setMultiValued(true);
		}

		return infoBuilder;
	}
}
