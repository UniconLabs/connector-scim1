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

import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.filter.*;

// Missing filterVisitor methods/filters from SCIM v1 specification: not equal, present

/**
 * @author Macik
 * 
 *         Contains methods needed for building a "filter" query which is sent
 *         to the resource provider as a more specific search query.
 */
public class FilterHandler implements FilterVisitor<StringBuilder, String> {

	private static final Log LOGGER = Log.getLog(FilterHandler.class);

	private static final String SPACE = "%20";
	private static final String QUOTATION = "%22";
	private static final String EQUALS = "eq";
	private static final String CONTAINS = "co";
	private static final String STARTSWITH = "sw";
	private static final String ENDSWITH = "ew";
	private static final String GREATERTHAN = "gt";
	private static final String GREATEROREQ = "ge";
	private static final String LESSTHAN = "lt";
	private static final String LESSOREQ = "le";
	private static final String AND = "and";
	private static final String OR = "or";
	private static final String NOT = "not";
	private static final String TYPE = "type";
	private static final String DELIMITER = "\\.";
	private static final String LEFTPAR = "(";
	private static final String RIGHTPAR = ")";

	private static final String OPENINGBRACKET = "[";
	private static final String CLOSINGGBRACKET = "]";

	private static final String DOT = ".";
	

	
	/**
	 * Implementation of the "visitAndFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the "valuePath" string
	 *            value indicating the name of an complex attribute with two or
	 *            more subattributes being processed.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The filter part of an query.
	 */
	@Override
	public StringBuilder visitAndFilter(String p, AndFilter filter) {
		LOGGER.info("Processing request trough \"and\" filter");

		StringBuilder completeQuery= evaluateCompositeFilter(AND, p, filter);

		return completeQuery;
	}

	/**
	 * Implementation of the "visitContainsFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitContainsFilter(String p, ContainsFilter filter) {
		LOGGER.info("Processing request trough \"contains\" filter");
		
		Map<String,String> helperParameterParts = processHelperParameter(p);		
		String attributeName = filter.getName();
		
		if (!attributeName.isEmpty()){
		
			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {
				return buildString(filter.getAttribute(), CONTAINS, attributeName, helperParameterParts);
			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY!");
			throw new InvalidAttributeValueException("No attribute key name provided");
		}
	}

	/**
	 * Implementation of the "visitContainsAllValuesFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The final filter query.
	 */
	@Override
	public StringBuilder visitContainsAllValuesFilter(String p, ContainsAllValuesFilter filter) {

		StrategyFetcher fetcher = new StrategyFetcher();
		HandlingStrategy strategy = fetcher.fetchStrategy(p);

		StringBuilder preprocessedFilter = strategy.processContainsAllValuesFilter(p, filter, this);

		if (null != preprocessedFilter) {
			return preprocessedFilter;
		} else {
			Collection<Filter> filterList = buildValueList(filter, "");
			for (Filter f : filterList) {
				if (f instanceof EqualsFilter) {

					return f.accept(this, p);
				} else if (f instanceof ContainsFilter) {
					return f.accept(this, p);
				}
			}

			Filter andFilterTest = (AndFilter) FilterBuilder.and(filterList);

			return andFilterTest.accept(this, p);

		}

	}

	/**
	 * Implementation of the "visitEqualsFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitEqualsFilter(String p, EqualsFilter filter) {
		LOGGER.info("Processing request trough \"equals\" filter: {0}", filter);
     String attributeName = filter.getName();
		
     Map<String,String> helperParameterParts = processHelperParameter(p);		
     
		if (!attributeName.isEmpty()){
			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {

				return buildString(filter.getAttribute(), EQUALS, attributeName, helperParameterParts);

			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY");
			throw new InvalidAttributeValueException("No attribute key name provided");
		}
	}

	/**
	 * Implementation of the "visitEqualsIgnoreCaseFilter" filter method.
	 *
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitEqualsIgnoreCaseFilter(String s, EqualsIgnoreCaseFilter equalsIgnoreCaseFilter) {
		throw new UnsupportedOperationException("Filter type is not supported: " + equalsIgnoreCaseFilter.getClass());
	}

	/**
	 * Implementation of the "visitExtendedFilter" filter method is not
	 * supported in this connector.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 */
	@Override
	public StringBuilder visitExtendedFilter(String p, Filter filter) {
		LOGGER.error("Usuported filter: {0}", filter);
		throw new NoSuchMethodError("Usuported query filter");
	}

	/**
	 * Implementation of the "visitGreaterThanFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitGreaterThanFilter(String p, GreaterThanFilter filter) {
		LOGGER.info("Processing request trough \"greaterThan\" filter: {0}", filter);

		
		Map<String,String> helperParameterParts = processHelperParameter(p);	
 	String attributeName = filter.getName();	
 	
 	
		if (!attributeName.isEmpty()) {

			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {

				return buildString(filter.getAttribute(), GREATERTHAN, attributeName, helperParameterParts );

			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY: {0}", filter);
			throw new InvalidAttributeValueException("No attribute key name provided");
		}
	}

	/**
	 * Implementation of the "visitGreaterThanOrEqualFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitGreaterThanOrEqualFilter(String p, GreaterThanOrEqualFilter filter) {
		LOGGER.info("Processing request trough \"greaterThanOrEqual\" filter: {0}", filter);
		
		
		Map<String,String> helperParameterParts = processHelperParameter(p);	
		
		String attributeName = filter.getName();
		
		if (!attributeName.isEmpty()) {

			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {

				return buildString(filter.getAttribute(), GREATEROREQ, attributeName, helperParameterParts);
			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY: {0}", filter);
			throw new InvalidAttributeValueException("No attribute key name provided");
		}
	}

	/**
	 * Implementation of the "visitLessThanFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitLessThanFilter(String p, LessThanFilter filter) {
		LOGGER.info("Processing request trough \"lessThan\" filter: {0}", filter);
		
		Map<String,String> helperParameterParts = processHelperParameter(p);	
		
		String attributeName = filter.getName();
		
		if (!attributeName.isEmpty()) {
			

			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {
				return buildString(filter.getAttribute(), LESSTHAN, attributeName, helperParameterParts);

			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY: {0}", filter);
			throw new InvalidAttributeValueException("No attribute key name provided");

		}
	}

	/**
	 * Implementation of the "visitLessThanOrEqualFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitLessThanOrEqualFilter(String p, LessThanOrEqualFilter filter) {
		LOGGER.info("Processing request trough \"lessThanOrEqual\" filter: {0}", filter);
		
		Map<String,String> helperParameterParts = processHelperParameter(p);	
		
		String attributeName = filter.getName();
		
		if (!attributeName.isEmpty()) {

			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {

				return buildString(filter.getAttribute(), LESSOREQ, attributeName,helperParameterParts);
			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY: {0}", filter);
			throw new InvalidAttributeValueException("No attribute key name provided");
		}
	}

	/**
	 * Implementation of the "visitNotFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The complete query.
	 */
	@Override
	public StringBuilder visitNotFilter(String p, NotFilter filter) {
		LOGGER.info("Processing request trough \"not\" filter: {0}", filter);
		StringBuilder completeQuery = new StringBuilder();

		completeQuery.append(NOT).append(SPACE).append(filter.getFilter().accept(this, p));

		return completeQuery;
	}

	/**
	 * Implementation of the "visitOrFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The complete query.
	 */
	@Override
	public StringBuilder visitOrFilter(String p, OrFilter filter) {
		LOGGER.info("Processing request trough \"or\" filter");

		StringBuilder completeQuery= evaluateCompositeFilter(OR, p, filter);

		return completeQuery;
	}

	/**
	 * Implementation of the "visitStartsWithFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitStartsWithFilter(String p, StartsWithFilter filter) {
		LOGGER.info("Processing request trough \"startsWith\" filter: {0}", filter);
		
		Map<String,String> helperParameterParts = processHelperParameter(p);	
		
		String attributeName = filter.getName();
		
		if (!attributeName.isEmpty()){

			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {

				return buildString(filter.getAttribute(), STARTSWITH, attributeName, helperParameterParts);
			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY: {0}", filter);
			throw new InvalidAttributeValueException("No attribute key name provided");
		}
	}

	/**
	 * Implementation of the "visitEndsWithFilter" filter method.
	 * 
	 * @param p
	 *            Helper parameter which may contain the resource provider name
	 *            used for workaround purposes.
	 * @param filter
	 *            The filter or list of filters being processed.
	 * @return The processed filter.
	 */
	@Override
	public StringBuilder visitEndsWithFilter(String p, EndsWithFilter filter) {
		LOGGER.info("Processing request trough \"endsWith\" filter: {0}", filter);
		
		
 	Map<String,String> helperParameterParts = processHelperParameter(p);	
		String attributeName = filter.getName();
		
		if (!attributeName.isEmpty()){
		
			StringBuilder preprocessedFilter = processArrayQ(filter, p);
			if (preprocessedFilter == null) {
				return buildString(filter.getAttribute(), ENDSWITH, attributeName, helperParameterParts);

			} else {
				return preprocessedFilter;
			}
		} else {

			LOGGER.error("Filter attribute key name EMPTY while processing an ends with filter: {0}", filter);
			throw new InvalidAttributeValueException(
					"No attribute key name provided while processing an ends with filter");
		}
	}

	/*
	 * private static final String EQUALS = "eq"; private static final String
	 * CONTAINS = "co"; private static final String STARTSWITH = "sw"; private
	 * static final String ENDSWITH = "ew"; private static final String
	 * GREATERTHAN = "gt"; private static final String GREATEROREQ = "ge";
	 * private static final String LESSTHAN = "lt"; private static final String
	 * LESSOREQ = "le"; private static final String AND = "and"; private static
	 * final String OR = "or"; private static final String NOT = "not"; private
	 * static final String TYPE = "type";
	 */

	/**
	 * Builds the string representation of an filter query.
	 * 
	 * @param attribute
	 *            The attribute on behalf of which the query result should be
	 *            filtered out .
	 * @param operator
	 *            The operator which represents the type of filter used. The
	 *            supported parameter values are:
	 *            <li>"eq" - "Equals" filter operator
	 *            <li>"co" - "Contains" filter operator
	 *            <li>"sw" - "Starts with" filter operator
	 *            <li>"ew" - "Ends with" filter operator
	 *            <li>"gt" - "Greater than" filter operator
	 *            <li>"ge" - "Greater than or equal" filter operator
	 *            <li>"lt" - "Less than" filter operator
	 *            <li>"le" - "Less than or equal" filter operator
	 *            <li>"and" - "And" filter operator
	 *            <li>"or" - "Or" filter operator
	 *            <li>"not" - "Not" filter operator
	 * 
	 * 
	 * @param name
	 *            The name of the attribute which is being used.
	 * @return The string representation of a filter.
	 */
	private StringBuilder buildString(Attribute attribute, String operator, String name,
			Map<String, String> helperParameterParts) {

		// LOGGER.info("String builder processing filter: {0}", operator);

		StringBuilder resultString = new StringBuilder();
		if (attribute == null) {

			LOGGER.error("Filter attribute value is EMPTY while building filter query, please provide attribute value ",
					attribute);
			throw new InvalidAttributeValueException("No attribute value provided while building filter query");
		} else {

			String attributeValue = AttributeUtil.getAsStringValue(attribute);
			try {
				attributeValue = URLEncoder.encode(attributeValue, "UTF-8");

				if ("__NAME__".equals(name)) {

					LOGGER.info("the list: {0}", helperParameterParts.toString());

					if (helperParameterParts.containsKey("resource")) {
						String theResoure = helperParameterParts.get("resource");

						// LOGGER.info("The resource {0}",
						// theResoure.toString());

						if ("Users".equals(theResoure.toString())) {
							name = "userName";
						} else {

							name = "displayName";

						}
					}
				}

				resultString.append(name).append(SPACE).append(operator).append(SPACE).append(QUOTATION)
						.append(attributeValue).append(QUOTATION);
			} catch (UnsupportedEncodingException e) {
				StringBuilder errorBuilder = new StringBuilder(
						"An encoding exception occured while processing the query value: ").append(attributeValue);

				throw new ConnectorException(errorBuilder.toString());
			}
		}

		return resultString;
	}

	/**
	 * Processes through a filter query containing an complex attribute with
	 * subattributes.
	 * 
	 * @param filter
	 *            The filter which is being processed.
	 * @param p
	 *            Helper parameter which can contain the name of the service
	 *            provider for workaround purposes or can be populated with an
	 *            "valuePath" string value indicating the name of a complex
	 *            attribute with two or more subattributes being processed.
	 * @return The final string representation of a filter or null if the
	 *         attribute is evaluated as non complex.
	 */
	public StringBuilder processArrayQ(AttributeFilter filter, String p) {
		if (filter.getName().contains(DOT)) {

			String[] keyParts = filter.getName().split(DELIMITER); // eq.
			// email.work.value
			if (keyParts.length == 3) {
				StringBuilder processedString = new StringBuilder();
				if(!"default".equals(keyParts[1])){

				Collection<Filter> filterList = new ArrayList<Filter>();
					StringBuilder pathName = new StringBuilder(p).append(DOT).append(keyParts[0]);
					p = pathName.toString();
					
					Filter assembled= assembleFilter(filter, keyParts[2],AttributeUtil.getAsStringValue(filter.getAttribute()));

					Filter eq = (EqualsFilter) FilterBuilder
							.equalTo(AttributeBuilder.build(TYPE, keyParts[1]));
					filterList.add(eq);
					filterList.add(assembled);
					
				Filter and = (AndFilter) FilterBuilder.and(filterList);

				processedString = and.accept(this, p);
				return processedString;
			}
				Filter assembled= assembleFilter(filter, keyParts[0],AttributeUtil.getAsStringValue(filter.getAttribute()));
			processedString = assembled.accept(this,p);
			return processedString;
			}
			LOGGER.info(
					"The attribute {0} is not a \"complex\" attribute. The filter query will be processed accordingly.",
					filter.getName());
			return null;
		}
		LOGGER.info(
				"Delimiters not found in the attribute name of {0}, the attribute is non complex. The filter query will be processed accordingly",
				filter.getName());
		return null;
	}

	/**
	 * Method is called if an attribute is processed which contains multiple
	 * values.
	 * 
	 * @param filter
	 *            The filter which is being processed.
	 * @param attributeName
	 *            The name of the attribute which is being processed.
	 * @return List of filters which was built from the list of values.
	 */
	private Collection<Filter> buildValueList(ContainsAllValuesFilter filter, String predefinedName) {

		List<Object> valueList = filter.getAttribute().getValue();
		Collection<Filter> filterList = new ArrayList<Filter>();

		for (Object value : valueList) {
			if (predefinedName.isEmpty()) {

				Filter containsSingleAtribute = (ContainsFilter) FilterBuilder
						.contains(AttributeBuilder.build(filter.getName(), value));
				filterList.add(containsSingleAtribute);
			} else {
				Filter containsSingleAtribute = (EqualsFilter) FilterBuilder
						.equalTo(AttributeBuilder.build(predefinedName, value));
				filterList.add(containsSingleAtribute);
			}

		}

		return filterList;
	}

	private Map<String, String> processHelperParameter(String helperParameter) {

		LOGGER.info("The helper param is {0}", helperParameter.toString());

		String[] helperParameterParts = helperParameter.split(DELIMITER);// e.g
																			// valuePath.members
		Map<String, String> helperValues = new HashMap<String, String>();

		for (int i = 0; i < helperParameterParts.length; i++) {
			if (i == 0) {
				helperValues.put("resource", helperParameterParts[i]);
			} else if (i == 1) {
				helperValues.put("provider", helperParameterParts[i]);

			} else {

				helperValues.put("sttribute", helperParameterParts[i]);
			}

		}

		return helperValues;
	}
	
	private Filter assembleFilter(AttributeFilter filter, String name, String value) {
		Filter assembledFilter;

		if (filter instanceof EqualsFilter) {

			assembledFilter = FilterBuilder.equalTo((AttributeBuilder.build(name, value)));

		} else if (filter instanceof ContainsFilter) {

			assembledFilter = FilterBuilder.contains((AttributeBuilder.build(name, value)));

		} else if (filter instanceof StartsWithFilter) {

			assembledFilter = FilterBuilder.startsWith((AttributeBuilder.build(name, value)));

		} else if (filter instanceof EndsWithFilter) {

			assembledFilter = FilterBuilder.endsWith((AttributeBuilder.build(name, value)));

		} else {
			LOGGER.warn("Evaluated filter is not supported for querying of \"complex\" attributes: {0}.", filter);
			return null;
		}

		return assembledFilter;
	}
	
	private StringBuilder evaluateCompositeFilter(String operator, String p, CompositeFilter filter) {

		StringBuilder completeQuery = new StringBuilder();

		String[] samePathIdParts = p.split(DELIMITER);// e.g valuePath.members

		if (samePathIdParts.length == 3) {
			p = samePathIdParts[2];
		}
		// LOGGER.info("the helper parameter {0}", p);

		// LOGGER.info("part lenght {0}", samePathIdParts.length);
		int position = 0;
		int size = filter.getFilters().size();
		boolean isFirst = true;

		for (Filter processedFilter : filter.getFilters()) {
			// LOGGER.info("The processed filter {0}",
			// processedFilter.getClass().toString());
			position++;

			if (isFirst) {

				if (processedFilter instanceof CompositeFilter) {
					completeQuery.append(LEFTPAR);
					completeQuery.append(processedFilter.accept(this, p).toString());
					completeQuery.append(RIGHTPAR);
					isFirst = false;
				} else if (!p.isEmpty() && samePathIdParts.length == 3) {
					completeQuery.append(p);
					completeQuery.append(OPENINGBRACKET);
					completeQuery.append(processedFilter.accept(this, p));
					isFirst = false;
					if (position == size) {
						completeQuery.append(CLOSINGGBRACKET);
						isFirst = false;
					}
				} else {

					completeQuery = (processedFilter.accept(this, p));
					isFirst = false;
				}
			} else {
				completeQuery.append(SPACE);
				completeQuery.append(operator);
				completeQuery.append(SPACE);
				if (processedFilter instanceof OrFilter || processedFilter instanceof AndFilter) {
					completeQuery.append(LEFTPAR);
					completeQuery.append(processedFilter.accept(this, p).toString());
					completeQuery.append(RIGHTPAR);
				} else {
					completeQuery.append(processedFilter.accept(this, p).toString());
				}
				if (position == size) {
					if (!p.isEmpty() && samePathIdParts.length == 3) {
						completeQuery.append(CLOSINGGBRACKET);
					}
				}
			}

		}

		return completeQuery;
	}
	
}
