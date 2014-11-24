package org.zaproxy.zap.extension.retire;

import org.apache.commons.httpclient.URI;
import java.io.IOException;
import org.json.simple.*;
import org.json.simple.parser.JSONParser;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.network.HttpMessage;

public class RetireExtension extends ExtensionAdaptor {
	 private static final String RESOURCE = "/org/zaproxy/zap/extension/retire/resources";
	 private static final JSONObject json = initialize();
	
	@Override
	public String getAuthor() {
		// TODO Auto-generated method stub
		return "Nikita";
	}
	
	 /*
	 **This function initializes and reads the vulnerability database*
	 */
	public static JSONObject initialize(){
	  JSONParser parser = new JSONParser();
	  try{
		  String repo = retireUtil.readFile(RESOURCE + "/jsrepository.json"); 
		  repo = repo.replace("§§version§§", "[0-9][0-9.a-z_\\\\\\\\-]+");
		  Object JsonRepo = parser.parse(repo);
		  return (JSONObject)(JsonRepo);
		 }catch(IOException e){
		  System.out.println(e.getMessage());
	   }catch (Exception e) {
		e.printStackTrace();
	  }
	  return null;
   }
	/*
	 * This is the top level function called from the scanner. It first checks if:
	 * 1)Matching vulnerability is found in database for JS file URL, if YES return return HashSet of related info.
	 * 2)Matching vulnerability is found in database for JS file name, if YES return return HashSet of related info.
	 * 3)Matching vulnerability is found in database for JS file content, if YES return return HashSet of related info.
	 * 4)Matching vulnerability is found in database for JS file hash, if YES return HashSet of related info .
	 * 5)Return empty HashSet.
	 */
	public static HashSet<String> scanJS(HttpMessage msg){
		
		URI uri = msg.getRequestHeader().getURI();
		String fileName =  retireUtil.getFileName(uri);
		String content = msg.getResponseBody().toString();
		HashSet<String> result = new HashSet<String>();
		
		//check if in dont check section
		HashMap<String, String> msginfo = new HashMap<String, String>();
		msginfo.put("uri", uri.toString());
		msginfo.put("filename", fileName.toString());
		msginfo.put("filecontent", content);
		
		if(dontcheck(msginfo)){
		  return result;
		}
		
		
		result = scanFileURI(uri.toString());
		if(!result.isEmpty())
			return result;
		
		if(fileName!=null){
			result = scanFileName(fileName);
		}
		if(!result.isEmpty())
			return result;
		
		result = scanFileContent(content);
		if(!result.isEmpty())
			return result;
		
		String hash =  retireUtil.getHash(msg.getResponseBody().toString());
		result = scanHash(hash);
		
		return result;
	}

	/*
	 * This function computes the SHA 1 hash of the HTTP response body,
	 * IF the hash matches that of an existing entry in the vulnerability database
	 * corresponding info is returned. 
	 * ELSE an empty HashSet is returned.
	 */
		
	private static HashSet<String> scanHash(String hash) {
		  HashSet<String> result = new HashSet<String>();
		  for (Object jsfile: json.entrySet()) {
			 Map.Entry<String, JSONObject> mjsFile = (Map.Entry<String, JSONObject>)jsfile;
			 JSONObject extractors =  (JSONObject)mjsFile.getValue().get("extractors");
			 JSONObject hashes = (JSONObject)extractors.get("hashes");
			 			 
			 //reading all filename regexes for this JS library
			 if(hashes != null){
				 for (Object hashi: hashes.entrySet()) {
					 Map.Entry<String, String> hashEntry  = (Map.Entry<String, String>)hashi;
				     System.out.println(hashEntry.getKey() + ":" +  hashEntry.getValue());
				     JSONArray vulnerabilities = (JSONArray)mjsFile.getValue().get("vulnerabilities");
				     if(hash.equalsIgnoreCase(hashEntry.getKey())){
				    	 System.out.println("Match found for" + mjsFile.getKey());
				    	 result = isVersionVulnerable(vulnerabilities, hashEntry.getValue());
				    	 return result;
				      } 
			     }
			 }
	      }	
		  return result;
	}


	private static HashSet<String> scanFileContent(String content) {
		return scan("filecontent", content);
	}



	public static HashSet<String> scanFileName(String filename){
		return scan("filename", filename);
	}

	static HashSet<String> scanFileURI(String fileURI){
		return scan("uri", fileURI);
	}

	/*
	 * This function takes in the criterion used for searching the vulnerability database.
	 * The criterion can be:
	 * FileName OR FileURL OR FileContent
	 */
		
	public static HashSet<String> scan(String criterion, String inputFile){
		 HashSet<String> results = new HashSet<String>();
		
		 //reading each entry for JS libraries in repo
		for (Object jsfile: json.entrySet()){
			 Map.Entry<String, JSONObject> mjsFile = (Map.Entry<String, JSONObject>)jsfile;
			 JSONObject extractors =  (JSONObject)mjsFile.getValue().get("extractors");
			 JSONArray matches = (JSONArray)extractors.get(criterion);
			 
			 //reading all  regexes with this criterion(i.e. fileURI, fileName or fileContent for this particular JS library
			 if(matches != null){
				 Iterator<String> iterator = matches.iterator();
				 while (iterator.hasNext()) {
					 String next=iterator.next();
					 if(next!=null){
					 Pattern p = Pattern.compile(next);
					 Matcher m = p.matcher(inputFile);
						//doing a match for each filename regex
		                if(m.find()){
		                	//retrieve file version
		                	String inpversion =  m.group(1);
		                	System.out.println("Current version is" + inpversion);
		                	
		                	//now try to detect if this version is vulnerable
		                	JSONArray vulnerabilities = (JSONArray)mjsFile.getValue().get("vulnerabilities");
		                	results  = isVersionVulnerable(vulnerabilities, inpversion);
	                    }
	                } 	
	            }
			 }
	   } 
	 return results;
   }

  private static boolean dontcheck(HashMap<String, String> msginfo) {
		// TODO Auto-generated method stub
	    JSONArray matches = null;
	    JSONObject j = (JSONObject)json.get("dont check");
	    JSONObject extractors = (JSONObject)j.get("extractors");
	    
	    //iterating over extractors
	    for(String criterion: msginfo.keySet()){
	    	matches = (JSONArray) extractors.get(criterion);	    	
	    	if(matches != null){
			 Iterator<String> iterator = matches.iterator();
			 while(iterator.hasNext()){
				 String next=iterator.next();
				 if(next!=null){
				 Pattern p = Pattern.compile(next);
				 Matcher m = p.matcher(msginfo.get(criterion));
					//doing a match for each filename regex
	                if(m.find()){
	                	return true;
	                }
				 }
			  }
	        }
	    }
	  return false;
	}

/*
   * This function depending on the vulnerablity info of a passed JS library,
   * detects if the current version is vulnerable.
   * If YES returns the HashSet of vulnerability info.
   * else returns an empty HashSet. 
   */
   private static HashSet<String> isVersionVulnerable(JSONArray vulnerabilities, String inpversion){
    	//Do a match for each of the above vulnerabilities
    	HashSet<String> results = new HashSet<String>();
    	Iterator<JSONObject> viterator = vulnerabilities.iterator();
    	
		 while (viterator.hasNext()) {
		 		Boolean isVulnerable = false;
			    JSONObject vnext= viterator.next();
			       
            if(vnext.containsKey("atOrAbove") && vnext.containsKey("below")){
            	System.out.println("Vulnerability at or above" + (String)vnext.get("atOrAbove") + "and below" + (String)vnext.get("below"));
            	if( retireUtil.isAtOrAbove(inpversion, (String)vnext.get("atOrAbove")) &&
            			! retireUtil.isAtOrAbove(inpversion, (String)vnext.get("below"))){
            		isVulnerable = true;
            		
            	} 	
             }else if(vnext.containsKey("below")){
            	System.out.println("Vulnerability below" + (String)vnext.get("below"));
            	if(! retireUtil.isAtOrAbove(inpversion, (String)vnext.get("below"))){
            		isVulnerable = true;
         	     } 
            } 
           else if(vnext.containsKey("atOrAbove")){
        	   System.out.println("Vulnerability above" + (String)vnext.get("atOrAbove"));
             	if( retireUtil.isAtOrAbove(inpversion, (String)vnext.get("atOrAbove"))){
           		     isVulnerable = true; 
             	} 
           }
           if(isVulnerable){
        	   System.out.println("Current version is vulnerable.");
     		   JSONArray info = (JSONArray)vnext.get("info");
     		   Iterator<String> iiterator = info.iterator();
     		   while(iiterator.hasNext())
     			  results.add((String)iiterator.next()); 	 
         }         
	  } 
      return results;
  }
	
   /*
    * Testing stub
    **/
   public static void main(String[] args){
		HashMap<String, String> msginfo = new HashMap<String, String>();
		msginfo.put("uri","http://wwwdd.google-analytics.com/ga.js");
		msginfo.put("filename", "nikita");
		msginfo.put("filecontent", "nikita");

		System.out.println(dontcheck(msginfo));
		//System.out.println("RESULT");
		//System.out.println(scanFileURI("http://ajax.googleapis.com/ajax/libs/angularjs/1.2.19/angular.min.js"));
	}
}
