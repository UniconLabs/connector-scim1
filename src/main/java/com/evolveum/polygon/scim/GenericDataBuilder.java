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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import com.evolveum.polygon.common.GuardedStringAccessor;

/**
 * 
 * @author Macik
 * 
 *         A class that contains the methods needed for construction of json
 *         object representations of provided data sets. Attributes are
 *         translated to json objects and arrays of json objects depending on
 *         the attributes and dictionary.
 */
public class GenericDataBuilder implements ObjectTranslator {

	private static final Log LOGGER = Log.getLog(GenericDataBuilder.class);
	private final String operation;
	private final int scimVersion;

	/**
	 * Constructor used to populate the local variable "operation".
	 * 
	 * @param operation
	 *            String variable indicating that the delete (SCIM v1)/remove (SCIM v2) operation
	 *            parameter should be added in the constructed json object. The
	 *            values which this parameter might acquire:
	 *            <li>"remove"</li>
	 *            <li>"add"</li>
	 *            <li>"replace"</li>
	 *
	 * @param scimVersion
	 * 				The SCIM protocol version as an integer.
	 **/
	public GenericDataBuilder(final String operation, final int scimVersion) {
		this.operation = operation;
		this.scimVersion = scimVersion;
	}

	/**
	 * Constructs a json object representation out of the provided data set and
	 * schema dictionary. The json object representation will contain only
	 * attributes which comply to the provided schema and operation attributes
	 * as defined in the SCIM patch specification.
	 * 
	 * @param imsAttributes
	 *            A set of attributes provided by the identity management
	 *            system.
	 * @param injectedAttributes
	 *            A set of attributes which are injected into the provided set.
	 * @return The complete json representation of the provided data set.
	 */
	public JSONObject translateSetToJson(final Set<Attribute> imsAttributes, final Set<Attribute> injectedAttributes,
			final String resourceEndPoint) {

		LOGGER.info("Building account JSONObject...");
		final JSONObject completeJsonObj = buildValueJSONObject(imsAttributes, injectedAttributes, resourceEndPoint);

		if (scimVersion == 1) {
			LOGGER.ok("Returning SCIM V1 JSON Object of {0}", completeJsonObj);
			return completeJsonObj;

		} else if (scimVersion == 2) {
			LOGGER.ok("Returning SCIM V2 JSON Object of {0}", completeJsonObj);
			return buildSCIMv2JSONObject(completeJsonObj);

		} else
			LOGGER.error("Non-supported SCIM version of {0} return empty JSON object!", scimVersion);
			return new JSONObject();
	}

	private JSONObject buildSCIMv2JSONObject(final JSONObject valueObject) throws JSONException {
		final JSONObject scimV2PayloadObject = new JSONObject();
		scimV2PayloadObject.put(SCIM_V2_SCHEMAS, List.of(SCIM_V2_SCHEMA_PATCH));

		//TODO do we need handle remove? Depending on implementation may need to separate attributes into discrete operations?
		final JSONObject op = new JSONObject();
		op.put(SCIM_V2_OP, this.operation);
		op.put(SCIM_V2_VALUE, valueObject); //TODO may need to unravel, handle delete/remove?
		scimV2PayloadObject.put(SCIM_V2_OPERATIONS, List.of(op));

		LOGGER.ok("Processed SCIM v2 JSON Complete Payload of {0}.", scimV2PayloadObject);
		return scimV2PayloadObject;
	}

	private JSONObject buildValueJSONObject(final Set<Attribute> imsAttributes, final Set<Attribute> injectedAttributes,
											final String resourceEndPoint) {

		LOGGER.ok("Building value JsonObject");
		final JSONObject valueJSONObject = new JSONObject();
		final Set<Attribute> multiValueAttribute = new HashSet<>(); // e.g.
		// name.givenName
		final Set<Attribute> multiLayerAttribute = new HashSet<>(); // e.g.
		// emails.work.value
		final Set<Attribute> extensionAttribute = new HashSet<>(); // e.g.
		// urn|scim|schemas|extension|enterprise|1.0.division

		if (injectedAttributes != null) {
			for (final Attribute injectedAttribute : injectedAttributes) {
				final String attributeName = injectedAttribute.getName();
				multiValueAttribute.add(injectedAttribute);

				if (attributeName.contains(DOT)) {

					final String[] keyParts = attributeName.split(DELIMITER); // e.g.
					// schemas.default.blank
					if (keyParts.length == 2) {

						multiValueAttribute.add(injectedAttribute);
					} else {
						multiLayerAttribute.add(injectedAttribute);
					}
				} else {

					valueJSONObject.put(attributeName, AttributeUtil.getSingleValue(injectedAttribute));
				}
			}

		}

		for (final Attribute attribute : imsAttributes) {

			// LOGGER.info("Update or create set attribute: {0}", attribute);
			String attributeName = attribute.getName();

			if (attributeName.contains(DOT)) {

				final String[] keyParts = attributeName.split(DELIMITER); // e.g.
				// emails.work.value
				if (keyParts.length == 2) {

					multiValueAttribute.add(attribute);
				} else {
					multiLayerAttribute.add(attribute);
				}

			} else if (OperationalAttributes.ENABLE_NAME.equals(attributeName)) {
				valueJSONObject.put("active", AttributeUtil.getSingleValue(attribute));
			} else if (OperationalAttributes.PASSWORD_NAME.equals(attributeName)) {

				final GuardedString guardedString = (GuardedString) AttributeUtil.getSingleValue(attribute);
				final GuardedStringAccessor accessor = new GuardedStringAccessor();
				guardedString.access(accessor);

				valueJSONObject.put("password", accessor.getClearString());
			} else if (attributeName.contains(SEPARATOR)) {

				extensionAttribute.add(attribute);

			} else if ("__NAME__".equals(attributeName)) {
				if (resourceEndPoint.equals("Users")) {

					valueJSONObject.put("userName", AttributeUtil.getSingleValue(attribute));

				} else {

					valueJSONObject.put("displayName", AttributeUtil.getSingleValue(attribute));
				}

			} else {

				if (attributeName.contains(FORBIDDEN_SEPARATOR)) {

					attributeName = attributeName.replace(FORBIDDEN_SEPARATOR, SEPARATOR);
				}

				valueJSONObject.put(attributeName, AttributeUtil.getSingleValue(attribute));
			}

		}

		buildMultiValueAttribute(multiValueAttribute, valueJSONObject);

		buildLayeredAttribute(multiLayerAttribute, valueJSONObject);

		buildExtensionAttribute(extensionAttribute, valueJSONObject);

		LOGGER.ok("Json value object returned from json data builder: {0}", valueJSONObject);
		return valueJSONObject;

	}

	/**
	 * Builds a json object representation out of a provided set of
	 * "multi layered attributes". This type of attributes represent an array of
	 * simple or complex json objects.
	 * 
	 * @param multiLayerAttribute
	 *            A provided set of attributes.
	 * @param json
	 *            A json object which may already contain data added in previous
	 *            methods.
	 * @return A json representation of the provided data set.
	 */
	private JSONObject buildLayeredAttribute(final Set<Attribute> multiLayerAttribute, final JSONObject json) {

		String mainAttributeName;
		final List<String> checkedNames = new ArrayList<>();
		for (final Attribute i : multiLayerAttribute) {

			final String attributeName = i.getName();
			final String[] attributeNameParts = attributeName.split(DELIMITER); // e.q.
			// email.work.value

			if (checkedNames.contains(attributeNameParts[0])) {
				//TODO?
			} else {
				final Set<Attribute> subAttributeLayerSet = new HashSet<>();
				mainAttributeName = attributeNameParts[0];
				checkedNames.add(mainAttributeName);

				for (final Attribute j : multiLayerAttribute) {

					String secondLoopAttributeName = j.getName();
					String[] secondLoopAttributeNameParts = secondLoopAttributeName.split(DELIMITER); // e.q.
					// email.work.value

					if (secondLoopAttributeNameParts[0].equals(mainAttributeName)) {
						subAttributeLayerSet.add(j);
					}
				}

				String canonicalTypeName;
				boolean writeToArray = true;
				final JSONArray jArray = new JSONArray();

				final List<String> checkedTypeNames = new ArrayList<>();
				for (final Attribute k : subAttributeLayerSet) {

					final String nameFromSubSet = k.getName();
					final String[] nameFromSubSetParts = nameFromSubSet.split(DELIMITER); // e.q.
					// email.work.value

					if (checkedTypeNames.contains(nameFromSubSetParts[1])) {
						//TODO?
					} else {
						JSONObject multiValueObject = new JSONObject();
						canonicalTypeName = nameFromSubSetParts[1];

						checkedTypeNames.add(canonicalTypeName);
						for (final Attribute subSetAttribute : subAttributeLayerSet) {

							final String secondLoopNameFromSubSetParts = subSetAttribute.getName();
							final String[] finalSubAttributeNameParts = secondLoopNameFromSubSetParts.split(DELIMITER); // e.q.

							// email.work.value
							if (finalSubAttributeNameParts[1].equals(canonicalTypeName)) {
								if (subSetAttribute.getValue() != null && subSetAttribute.getValue().size() > 1) {
									writeToArray = false;
									final List<Object> valueList = subSetAttribute.getValue();

									for (final Object attributeValue : valueList) {
										multiValueObject = new JSONObject();
										multiValueObject.put(finalSubAttributeNameParts[2], attributeValue);

										if (!DEFAULT.equals(nameFromSubSetParts[1])) {
											multiValueObject.put(TYPE, nameFromSubSetParts[1]);
										}

										if (scimVersion == 1 && SCIM_V2_DELETE.equals(operation)) {
											multiValueObject.put(SCIM_V1_OPERATION, SCIM_V1_DELETE);
										}

										jArray.put(multiValueObject);

									}

								} else {

									if (!BLANK.equals(finalSubAttributeNameParts[2])) {
										multiValueObject.put(finalSubAttributeNameParts[2],
												AttributeUtil.getSingleValue(subSetAttribute));
									} else {

										jArray.put(AttributeUtil.getSingleValue(subSetAttribute));
										writeToArray = false;
									}

									if (!DEFAULT.equals(nameFromSubSetParts[1])) {
										multiValueObject.put(TYPE, nameFromSubSetParts[1]);
									}

									if (scimVersion == 1 && SCIM_V2_DELETE.equals(operation)) {
										multiValueObject.put(SCIM_V1_OPERATION, SCIM_V1_DELETE);
									}
								}
							}
						}
						if (writeToArray) {

							jArray.put(multiValueObject);
						}
					}

					String attrName = nameFromSubSetParts[0];
					if (attrName.contains(SEPARATOR)) {
						attrName = attrName.replace(SEPARATOR, FORBIDDEN_SEPARATOR);
					}

					json.put(attrName, jArray);
				}

			}

		}

		return json;
	}

	/**
	 * Builds a json object representation out of a provided set of
	 * "multi value attributes". This type of attributes represent a complex
	 * json object containing other key value pairs.
	 * 
	 * @param multiValueAttribute
	 *            A provided set of attributes.
	 * @param json
	 *            A json representation of the provided data set.
	 * 
	 * @return A json representation of the provided data set.
	 */
	private JSONObject buildMultiValueAttribute(final Set<Attribute> multiValueAttribute, final JSONObject json) {

		String mainAttributeName;
		final List<String> checkedNames = new ArrayList<>();

		final Set<Attribute> specialMlAttributes = new HashSet<>();
		for (final Attribute i : multiValueAttribute) {
			final String attributeName = i.getName();
			final String[] attributeNameParts = attributeName.split(DELIMITER); // e.g.
			// name.givenName

			if (checkedNames.contains(attributeNameParts[0])) {
				//TODO?
			} else {
				JSONObject jObject = new JSONObject();
				mainAttributeName = attributeNameParts[0];
				checkedNames.add(mainAttributeName);

				for (final Attribute j : multiValueAttribute) {
					final String secondLoopAttributeName = j.getName();
					final String[] secondLoopAttributeNameParts = secondLoopAttributeName.split(DELIMITER); // e.g.

					// name.givenName
					if (secondLoopAttributeNameParts[0].equals(mainAttributeName)
							&& !mainAttributeName.equals(SCHEMA)) {
						jObject.put(secondLoopAttributeNameParts[1], AttributeUtil.getSingleValue(j));
					} else if (secondLoopAttributeNameParts[0].equals(mainAttributeName)) {
						specialMlAttributes.add(j);

					}
				}

				if (specialMlAttributes.isEmpty()) {
					json.put(attributeNameParts[0], jObject);

				} else {
					String sMlAttributeName = "No schema type";
					boolean nameWasSet = false;

					for (final Attribute specialAttribute : specialMlAttributes) {
						final String innerName = specialAttribute.getName();
						final String[] innerKeyParts = innerName.split(DELIMITER); // e.g.
						// name.givenName
						if (innerKeyParts[1].equals(TYPE) && !nameWasSet) {
							sMlAttributeName = AttributeUtil.getAsStringValue(specialAttribute);
							nameWasSet = true;
						} else if (!innerKeyParts[1].equals(TYPE)) {

							jObject.put(innerKeyParts[1], AttributeUtil.getSingleValue(specialAttribute));
						}
					}

					if (nameWasSet) {

						json.put(sMlAttributeName, jObject);
						specialMlAttributes.removeAll(specialMlAttributes);

					} else {
						LOGGER.error(
								"Schema type not specified {0}. Error occurrence while translating user object attribute set: {0}",
								sMlAttributeName);
						throw new InvalidAttributeValueException(
								"Schema type not specified. Error occurrence while translating user object attribute set");
					}

				}
			}
		}

		return json;
	}

	/**
	 * Builds a json object representation out of a provided set of
	 * "attributes belonging to an extension". This type of attributes represent
	 * a complex json object containing other key value pairs.
	 * 
	 * @param extensionAttribute
	 *            A provided set of attributes.
	 * @param json
	 *            A json representation of the provided data set.
	 * 
	 * @return A json representation of the provided data set.
	 */

	private JSONObject buildExtensionAttribute(final Set<Attribute> extensionAttribute, final JSONObject json) {

		boolean isPartOfName = false;
		String mainAttributeName = "";
		final Map<String, Map<String, Object>> processedGoods = new HashMap<>();

		for (final Attribute i : extensionAttribute) {

			String attributeName = i.getName();
			attributeName = attributeName.replace(SEPARATOR, FORBIDDEN_SEPARATOR);
			final String[] attributeNameParts = attributeName.split(DELIMITER); // e.q.
			// urn:scim:schemas:extension:enterprise:1.0.division
			for (int position = 1; position < attributeNameParts.length; position++) {

				final String namePart = attributeNameParts[position];

				for (int charPosition = 0; charPosition < namePart.length(); charPosition++) {
					char c = namePart.charAt(charPosition);
					if (Character.isDigit(c)) {
						if (charPosition == 0 && charPosition + 1 == namePart.length()) {
							isPartOfName = true;
						} else if (charPosition + 1 == namePart.length() && !isPartOfName) {

							isPartOfName = false;

						} else {
							isPartOfName = true;
						}
					} else {
						isPartOfName = false;
					}
				}

				if (!isPartOfName) {

					if (mainAttributeName.isEmpty()) {
						mainAttributeName = attributeNameParts[0];
					}

					if (!processedGoods.containsKey(mainAttributeName)) {

						final Map<String, Object> processedAttribute = new HashMap<>();
						processedAttribute.put(namePart, AttributeUtil.getSingleValue(i));
						processedGoods.put(mainAttributeName, processedAttribute);
						mainAttributeName = "";
						break;
					} else {
						final Map<String, Object> processedAttribute = processedGoods.get(mainAttributeName);
						processedAttribute.put(namePart, AttributeUtil.getSingleValue(i));
						processedGoods.put(mainAttributeName, processedAttribute);
						mainAttributeName = "";
						break;
					}
				} else {
					final StringBuilder buildName;
					if (mainAttributeName.isEmpty()) {
						buildName = new StringBuilder(attributeNameParts[0]).append(DOT).append(namePart);
						mainAttributeName = buildName.toString();

					} else {
						buildName = new StringBuilder(mainAttributeName).append(DOT).append(namePart);
						mainAttributeName = buildName.toString();
					}
				}

			}

		}
		if (!processedGoods.isEmpty()) {
			for (final String attributeName : processedGoods.keySet()) {

				final JSONObject subAttributes = new JSONObject();
				final Map<String, Object> sAttribute = processedGoods.get(attributeName);

				for (final String sAttributeName : sAttribute.keySet()) {
					subAttributes.put(sAttributeName, sAttribute.get(sAttributeName));
				}

				json.put(attributeName, subAttributes);

			}
		}

		return json;
	}
}
