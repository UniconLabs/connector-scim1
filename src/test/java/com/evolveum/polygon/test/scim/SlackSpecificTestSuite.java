package com.evolveum.polygon.test.scim;

import java.util.ArrayList;
import java.util.HashMap;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;
import org.testng.Assert;
import org.testng.ITestResult;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.evolveum.polygon.scim.ScimConnector;
import com.evolveum.polygon.scim.ScimConnectorConfiguration;

public class SlackSpecificTestSuite extends StandardScimTestSuite {

	private static Uid userUid;
	private static Uid groupUid;

	private static Integer pageSize;

	private static Integer pageOffset;

	private static Integer testNumber = 0;

	private static ScimConnector connector;

	private static ScimConnectorConfiguration configuration;

	private static final Log LOGGER = Log.getLog(SlackSpecificTestSuite.class);

	@DataProvider(name = "filterMethodTestProvider")
	public static Object[][] filterMethodTestResourcesProvider() {

		// TODO test issues with eq filter slack

		return new Object[][] { { "users", "uid" }, { "groups", "uid" }, { "users", "contains" },
				{ "groups", "contains" }, { "users", "startswith" }, { "groups", "startswith" }, { "users", "equals" },
				{ "groups", "equals" } };
	}

	@DataProvider(name = "configTestProvider")
	public static Object[][] configurationTestResourcesProvider() {

		pageSize = 1;
		pageOffset = 1;

		testNumber = 89;

		HashMap<String, String> configurationParameters = new HashMap<String, String>();
		configurationParameters.put("endpoint", "/scim");
		configurationParameters.put("version", "/v1");
		configurationParameters.put("authentication", "token");
		configurationParameters.put("baseurl", "https://api.slack.com");
		configurationParameters.put("token", "");
		configurationParameters.put("proxy", "");
		configurationParameters.put("proxy_port_number", "");

		return new Object[][] { { configurationParameters, true } };
	}

	@DataProvider(name = "updateUserResourceObjectTestProvider")
	public static Object[][] updateUserResourceObjectTestResourceProvider() throws Exception {
		Uid uid = getUid("user");

		return new Object[][] { { "single", uid }, { "multi", uid }, { "disabled", uid }, { "enabled", uid } };
	}

	@DataProvider(name = "updateGroupResourceObjectTestProvider")
	public static Object[][] updateGroupResourceObjectTestResourceProvider() throws Exception {
		Uid uid = getUid("group");

		return new Object[][] { { "single", uid }, { "multi", uid } };
	}

	@DataProvider(name = "deletetObjectfromResourcesProvider")
	public static Object[][] deletetObjectfromResourcesResourceProvider() {

		return new Object[][] { { "users", userUid }, { "groups", groupUid } };
	}

	@Test(priority = 1, dataProvider = "configTestProvider")
	public void configurationTest(HashMap<String, String> configurationParameters, Boolean assertionVariable) {

		groupUid = null;
		userUid = null;

		configuration = SlackSpecificTestUtils.buildConfiguration(configurationParameters);

		Boolean isValid = SlackSpecificTestUtils.isConfigurationValid(configuration);

		if (isValid) {

			connector = new ScimConnector();
			connector.init(configuration);
			connector.schema();
		}

		Assert.assertEquals(isValid, assertionVariable);

	}

	@Test(priority = 2, dependsOnMethods = { "configurationTest" }, dataProvider = "createTestProvider")
	private void createObjectOnResourcesTest(String resourceName, Boolean assertParameter) {

		Boolean resourceWasCreated = false;

		if ("users".equals(resourceName)) {
			userUid = SlackSpecificTestUtils.createResourceTestHelper(resourceName, testNumber, connector);
			if (userUid != null) {
				resourceWasCreated = true;
			}
		} else if ("groups".equals(resourceName)) {

			groupUid = SlackSpecificTestUtils.createResourceTestHelper(resourceName, testNumber, connector);
			if (groupUid != null) {
				resourceWasCreated = true;
			}
		}

		if (userUid != null) {
			resourceWasCreated = true;
		}

		Assert.assertEquals(resourceWasCreated, assertParameter);

	}

	@Test(priority = 2, dependsOnMethods = {
			"createObjectOnResourcesTest" }, dataProvider = "parameterConsistencyTestProvider")
	private void parameterConsistencyTest(String resourceName, String filterType) {

		StringBuilder testType = new StringBuilder("createObject");

		ArrayList<ConnectorObject> result = new ArrayList<ConnectorObject>();

		OperationOptions options = SlackSpecificTestUtils.getOptions(pageSize, pageOffset);

		result = SlackSpecificTestUtils.filter(filterType, resourceName, testNumber, userUid, groupUid, connector,
				options);

		HashMap<String, String> evaluationResults = SlackSpecificTestUtils.processResult(result, resourceName,
				testType.toString(), userUid, testNumber);

		for (String attributeName : evaluationResults.keySet()) {

			String nameValue = evaluationResults.get(attributeName);

			Assert.assertEquals(nameValue, attributeName);
		}

	}

	@Test(priority = 6, dependsOnMethods = { "createObjectOnResourcesTest" }, dataProvider = "filterMethodTestProvider")
	public void filterMethodTest(String resourceName, String filterType) {

		ArrayList<ConnectorObject> returnedObjects = new ArrayList<ConnectorObject>();

		OperationOptions options = SlackSpecificTestUtils.getOptions(pageSize, pageOffset);

		returnedObjects = SlackSpecificTestUtils.filter(filterType, resourceName, testNumber, userUid, groupUid,
				connector, options);

		Assert.assertFalse(returnedObjects.isEmpty());

	}

	@Test(priority = 5, dependsOnMethods = {
			"createObjectOnResourcesTest" }, dataProvider = "listAllfromResourcesProvider")
	private void listAllfromResourcesTest(int numberOfResources, String resourceName) {
		ArrayList<ConnectorObject> returnedObjects = new ArrayList<ConnectorObject>();

		OperationOptions options = SlackSpecificTestUtils.getOptions(pageSize, pageOffset);

		returnedObjects = SlackSpecificTestUtils.listAllfromResourcesTestUtil(resourceName, connector, options);

		Assert.assertEquals(returnedObjects.size(), numberOfResources);

	}

	@Test(priority = 3, dependsOnMethods = {
			"createObjectOnResourcesTest" }, dataProvider = "updateUserResourceObjectTestProvider")
	private void updateUserResourceObjectTest(String updateType, Uid uid) {

		Uid returnedUid = SlackSpecificTestUtils.updateResourceTest("users", updateType, userUid, groupUid, testNumber,
				connector);

		ArrayList<ConnectorObject> result = new ArrayList<ConnectorObject>();

		StringBuilder testType = new StringBuilder("update").append("-").append(updateType);

		OperationOptions options = SlackSpecificTestUtils.getOptions(pageSize, pageOffset);

		result = SlackSpecificTestUtils.filter("uid", "users", testNumber, userUid, groupUid, connector, options);

		HashMap<String, String> evaluationResults = SlackSpecificTestUtils.processResult(result, "users",
				testType.toString(), userUid, testNumber);

		for (String attributeName : evaluationResults.keySet()) {

			String nameValue = evaluationResults.get(attributeName);

			Assert.assertEquals(nameValue, attributeName);
		}

		Assert.assertEquals(uid, returnedUid);

	}

	@Test(priority = 4, dependsOnMethods = {
			"createObjectOnResourcesTest" }, dataProvider = "updateGroupResourceObjectTestProvider")
	private void updateGroupResourceObjectTest(String updateType, Uid uid) {

		Uid returnedUid = SlackSpecificTestUtils.updateResourceTest("groups", updateType, userUid, groupUid, testNumber,
				connector);

		ArrayList<ConnectorObject> result = new ArrayList<ConnectorObject>();

		StringBuilder testType = new StringBuilder("update").append("-").append(updateType);

		OperationOptions options = SlackSpecificTestUtils.getOptions(pageSize, pageOffset);

		result = SlackSpecificTestUtils.filter("uid", "groups", testNumber, userUid, groupUid, connector, options);

		HashMap<String, String> evaluationResults = SlackSpecificTestUtils.processResult(result, "groups",
				testType.toString(), userUid, testNumber);

		for (String attributeName : evaluationResults.keySet()) {

			String nameValue = evaluationResults.get(attributeName);

			Assert.assertEquals(nameValue, attributeName);
		}

		Assert.assertEquals(uid, returnedUid);

	}

	@Test(priority = 7, dependsOnMethods = {
			"createObjectOnResourcesTest" }, dataProvider = "deletetObjectfromResourcesProvider")
	private void deleteObjectfromResourcesTest(String resourceName, Uid uid) {

		ArrayList<ConnectorObject> returnedObjects = new ArrayList<ConnectorObject>();

		OperationOptions options = SlackSpecificTestUtils.getOptions(pageSize, pageOffset);

		SlackSpecificTestUtils.deleteResourceTestHelper(resourceName, uid, connector);
		returnedObjects = SlackSpecificTestUtils.filter("uid", resourceName, testNumber, userUid, groupUid, connector,
				options);

		Assert.assertTrue(returnedObjects.isEmpty());

	}

	public static Uid getUid(String resourceName) throws Exception {
		Uid uid = null;

		if ("user".equals(resourceName)) {
			uid = userUid;

		} else if ("group".equals(resourceName)) {

			uid = groupUid;
		} else {
			LOGGER.warn("Resource name not defined: {0}", resourceName);

		}

		if (uid == null) {

			throw new Exception("Uid not set");

		}

		return uid;
	}

	@AfterMethod
	private void cleanup(ITestResult result) throws Exception {
		if (result.getStatus() == ITestResult.FAILURE) {

			String methodThatFailed = result.getMethod().getMethodName();

			if ("createObjectOnResourcesTest".equals(methodThatFailed)) {

				if (userUid != null) {
					LOGGER.warn("Atempting to delete resource: {0}", "users");
					deleteObjectfromResourcesTest("users", userUid);
				} else {
					LOGGER.warn(
							"Test failure, uid value of resource \"User\" is null. No resource deletion operation was atempted");
				}
				if (groupUid != null) {
					LOGGER.warn("Atempting to delete resource: {0}", "groups");
					deleteObjectfromResourcesTest("groups", groupUid);
				} else

				{
					LOGGER.warn(
							"Test failure, uid value of resource \"Groups\" is null. No resource deletion operation was atempted");
				}

				throw new Exception("Test failure while creating the resource objects, test suite will not continue.");

			} else if ("updateUserResourceObjectTest".equals(methodThatFailed)) {
				if (userUid != null) {
					LOGGER.warn("Atempting to delete resource: {0}", "users");
					deleteObjectfromResourcesTest("users", userUid);
				}

				if (groupUid != null) {
					LOGGER.warn("Atempting to delete resource: {0}", "groups");
					deleteObjectfromResourcesTest("groups", groupUid);
				}

				throw new Exception(
						"Test failure while updating the \"User\" resource objects, test suite will not continue.");
			}

		}

	}

}
