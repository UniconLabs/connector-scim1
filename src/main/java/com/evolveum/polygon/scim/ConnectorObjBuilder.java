package com.evolveum.polygon.scim;

import java.awt.List;
import java.awt.font.MultipleMaster;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.json.JSONArray;
import org.json.JSONObject;

// Class containing methods needed for building connector objects from json objects

public class ConnectorObjBuilder {
	
	// TODO there will be overhead because we need to get each name from the list of resources 
	// if we list all resources and that can be done only by searching for individual UIDs eg. 
	// ScimCrudManager class caller method of this class

	private static final Log LOGGER = Log.getLog(ScimCrudManager.class);
	
	public ConnectorObject buildConnectorObject(JSONObject jsonObject, String resourceEndPoint) throws ConnectException{
		
		LOGGER.info("Building the connector object from provided json");
		
		if(jsonObject == null){
			LOGGER.error("Empty json object was passed from data provider. Error ocourance while building connector object");
			throw new ConnectException("Empty json object was passed from data provider. Error ocourance while building connector object");
		}
		
		ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
		Map<String, String> objectNameDictionary = null;

		cob.setUid(jsonObject.getString("id"));
		
		if("Users".equals(resourceEndPoint)){
			cob.setName(jsonObject.getString("userName"));
		}else if ("Groups".equals(resourceEndPoint)) {
		
		cob.setName(jsonObject.getString("displayName"));
		cob.setObjectClass(ObjectClass.GROUP);
		}else{
			cob.setName(jsonObject.getString("displayName"));
			StringBuilder objectClassNameBuilder = new StringBuilder("/").append(resourceEndPoint);
			ObjectClass objectClass = new ObjectClass(resourceEndPoint);;
			cob.setObjectClass(objectClass);
			
		}
		for(String key: jsonObject.keySet()){
			Object attribute =jsonObject.get(key);
			
			if(key.intern() == "meta" || key.intern() == "alias" || key.intern() == "schemas"){
				// do nothing -> some inconsistencies found in meta attribute in the schema definition present
				// in the Schemas/ resource and the actual atrributes in an resource representation (salesForce) (meta.location)
			
			}else
			
				if(attribute instanceof JSONArray){
					
					JSONArray jArray = (JSONArray) attribute;
					
					Map<String, Collection<String>> attributeMap= new HashMap<String, Collection<String>>();
					Collection<String> list = new ArrayList<String>();
						for(Object o: jArray){
							StringBuilder objectKeyBilder = new StringBuilder(key.intern());
							String objectKeyName = "";
							if(o instanceof JSONObject){
								for(String s: ((JSONObject) o).keySet()){
									if(s.intern() == "type"){
									objectKeyName = objectKeyBilder.append(".").append(((JSONObject) o).get(s)).toString();
									objectKeyBilder.delete(0, objectKeyBilder.length());
										break;
									}
								}
								
								for(String s: ((JSONObject) o).keySet()){
									
									if(s.intern() == "type"){
								}else {
									if(objectKeyName !=""){
									objectKeyBilder= objectKeyBilder.append(objectKeyName).append(".").append(s.intern());
									}else{
										objectKeyName= objectKeyBilder.append(".").append("default").toString();
										objectKeyBilder= objectKeyBilder.append(".").append(s.intern());
									}
									
									if(list.isEmpty()){
									list.add(((JSONObject) o).getString(s).toString());
									attributeMap.put(objectKeyBilder.toString(), list);
									}else{
										if(attributeMap.containsKey(objectKeyBilder.toString())){
											list.add(((JSONObject) o).getString(s).toString());
										}
										
									}
									
									//cob.addAttribute(objectKeyBilder.toString(), ((JSONObject) o).getString(s));	
									objectKeyBilder.delete(0, objectKeyBilder.length());
									
									
								}
							}
								
								//
							
						}else{
							objectKeyName = objectKeyBilder.append(".").append(o.toString()).toString();
							cob.addAttribute(objectKeyName,o.toString());
							
						}
							}
						
						//test 
							System.out.println(list);
							//cob.addAttribute("members.User.value", list);

				} else if(attribute instanceof JSONObject){
					for(String s: ((JSONObject) attribute).keySet()){
						
						/**if(objectNameDictionary.containsKey(s.intern())){
						cob.addAttribute(objectNameDictionary.get(s),((JSONObject) attribute).get(s));
						
						}
						*/
						StringBuilder nameBuilder = new StringBuilder(key.intern());
						cob.addAttribute(nameBuilder.append(".").append(s).toString(),((JSONObject) attribute).get(s));
						
					}
					
				} else { 
					
						cob.addAttribute(key.intern(), jsonObject.get(key));
						
				}
		}
		
	 LOGGER.info("Connector object {0}", cob.build());
		return cob.build();
		
	}
}


/*
 * builder.addAttributeInfo(Name.INFO);

		builder.addAttributeInfo(AttributeInfoBuilder.define("userName").setRequired(true).build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("name.formatted").build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("name.familyName").setRequired(true).build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("name.givenName").setRequired(true).build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("name.middleName").build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("name.honorificPrefix").build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("name.honorificSuffix").build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("displayName").build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("nickName").build());
		builder.addAttributeInfo(AttributeInfoBuilder.define("profileUrl").build());
 * 
 * */
 