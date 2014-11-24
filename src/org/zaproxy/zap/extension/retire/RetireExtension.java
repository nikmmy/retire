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
	 //private static final String RESOURCE = "/home/nikita/Downloads/workspace-zap/zap-extensions-alpha/src/org/zaproxy/zap/extension/retire/resources";
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
	public static Result scanJS(HttpMessage msg){
		
		URI uri = msg.getRequestHeader().getURI();
		String fileName =  retireUtil.getFileName(uri);
		String content = msg.getResponseBody().toString();
		Result r;
		
		//check if in dont check section
		HashMap<String, String> msginfo = new HashMap<String, String>();
		msginfo.put("uri", uri.toString());
		msginfo.put("filename", fileName.toString());
		msginfo.put("filecontent", content);
		
		if(dontcheck(msginfo)){
		  return null;
		}
		
		
		r = scanFileURI(uri.toString());
		if(r!=null)
			return r;
		
		if(fileName!=null){
			r = scanFileName(fileName);
		}
		if(r!=null)
			return r;
		
		r = scanFileContent(content);
		if(r!=null)
			return r;
		
		String hash =  retireUtil.getHash(msg.getResponseBody().toString());
		r = scanHash(hash);
		
		return r;
	}

	/*
	 * This function computes the SHA 1 hash of the HTTP response body,
	 * IF the hash matches that of an existing entry in the vulnerability database
	 * corresponding info is returned. 
	 * ELSE an empty HashSet is returned.
	 */
		
	private static Result scanHash(String hash) {
		  HashSet<String> results = new HashSet<String>();
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
				    	 results = isVersionVulnerable(vulnerabilities, hashEntry.getValue());
				    	 return new Result(mjsFile.getKey(),hashEntry.getValue(),results);
				      } 
			     }
			 }
	      }	
		  return null;
	}


	private static Result scanFileContent(String content) {
		return scan("filecontent", content);
	}



	public static Result  scanFileName(String filename){
		return scan("filename", filename);
	}

	static Result scanFileURI(String fileURI){
		return scan("uri", fileURI);
	}

	/*
	 * This function takes in the criterion used for searching the vulnerability database.
	 * The criterion can be:
	 * FileName OR FileURL OR FileContent
	 */
		
	public static Result scan(String criterion, String inputFile){
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
		                	if(!results.isEmpty()){
		                		return new Result(mjsFile.getKey(), inpversion, results);
		                	}
	                    }
	                } 	
	            }
			 }
	   } 
	 return null;
   }

 /*
  * This function informs whether to scan a JS library at all. There are certain
  * libraries we know for sure are secure, so we just ignore those.
  */
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
		/*HashMap<String, String> msginfo = new HashMap<String, String>();
		msginfo.put("uri","http://wwwdd.google-analytics.com/ga.js");
		msginfo.put("filename", "nikita");
		msginfo.put("filecontent", "nikita");
   */
		//System.out.println(dontcheck(msginfo));
		//System.out.println("RESULT");
	   Result r = scanFileURI("http://ajax.googleapis.com/ajax/libs/angularjs/1.2.19/angulassr.min.js");
		System.out.println(r.filename + r.version + r.info);
	}
}


class Result{
	HashSet<String> info = new HashSet<String>();
	String version;
	String filename;
	
	Result(String filename, String version, HashSet<String> info){
		this.filename = filename;
		this.version = version;
		this.info = info;
	}
}