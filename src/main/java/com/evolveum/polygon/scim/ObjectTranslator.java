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

import java.util.Set;

import org.identityconnectors.framework.common.objects.Attribute;
import org.json.JSONObject;

/**
 * 
 * @author Macik
 * 
 *         Interface which defines the basic json data builder method.
 */
public interface ObjectTranslator {

	String SCIM_V1_DELETE = "delete";
	String SCIM_V2_DELETE = "remove";
	String SCIM_V2_ADD = "add";
	String SCIM_v2_UPDATE = "replace";
	String DELIMITER = "\\.";
	String DEFAULT = "default";
	String TYPE = "type";
	String SCIM_V1_OPERATION = "operation";
	String SCIM_V2_OPERATIONS = "Operations";
	String SCIM_V2_SCHEMAS = "schemas";
	String SCIM_V2_OP = "op";
	String SCIM_V2_VALUE = "value";
	String SCIM_V2_PATH = "path";
	String SCIM_V2_SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
	String DOT = ".";
	String BLANK = "blank";
	String SCHEMA = "schema";
	String SEPARATOR = "-";
	String FORBIDDEN_SEPARATOR = ":";

	/**
	 * Constructs a json object representation out of the provided data set and
	 * schema dictionary. The json object representation will contain only
	 * attributes which comply to the provided schema and operation attributes
	 * as defined in the SCIM patch specification.
	 * 
	 * @param imsAttributes
	 *            A set of attributes provided by the identity management
	 *            system.
	 *            <p>
	 *            e.g. [Attribute: {Name=name.familyName, Value=[Watson]},
	 *            Attribute: {Name=name.givenName, Value=[John]}]
	 * @param injectedAttributes
	 *            A set of attributes which are injected into the provided set.
	 *            <p>
	 *            e.g. [Attribute: {Name=name.middleName, Value=[Hamish]}]
	 * @param resourceEndPoint 
	 * 			String which indicates what type of resource object is being created.
	 * @return The complete json representation of the provided data set.
	 */
	JSONObject translateSetToJson(final Set<Attribute> imsAttributes, final Set<Attribute> injectedAttributes, final String resourceEndPoint);
}
