package org.zaproxy.zap.extension.retire;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.network.HttpMessage;

public class RetireExtension extends ExtensionAdaptor {
	 private static final String RESOURCE = "/org/zaproxy/zap/extension/retire/resources";
	 private static final JSONObject json = initialize();

	@Override
	public String getAuthor() {
		return "Nikita";
	}

	 /*
	 **This function initializes and reads the vulnerability database*
	 */
	public static JSONObject initialize(){
	  JSONParser parser = new JSONParser();
	  try{
		   String path = RESOURCE + "/jsrepository.json";
		   String repo = RetireUtil.getStringResource(path);
		   repo = repo.replace("§§version§§", "[0-9][0-9.a-z_\\\\\\\\-]+");
		   Object JsonRepo = parser.parse(repo);
		   return (JSONObject)(JsonRepo);

		 }catch (Exception e) {
		    return null;
	     }
   }
	/*
	 * This is the top level function called from the scanner. It first checks if:
	 * 1)Matching vulnerability is found in database for JS file URL, if YES return return HashSet of related info.
	 * 2)Matching vulnerability is found in database for JS file name, if YES return return HashSet of related info.
	 * 3)Matching vulnerability is found in database for JS file content, if YES return return HashSet of related info.
	 * 4)Matching vulnerability is found in database for JS file hash, if YES return HashSet of related info .
	 * 5)Return empty HashSet.
	 */
	public static Result scanJS(final HttpMessage msg){

		URI uri = msg.getRequestHeader().getURI();
		String fileName =  RetireUtil.getFileName(uri);
		String content = msg.getResponseBody().toString();
		Result r;

		//check if in dont check section
		HashMap<String, String> msginfo = new HashMap<String, String>();
		msginfo.put("uri", uri.toString());
		if(fileName!=null)
			msginfo.put("filename", fileName.toString());
		msginfo.put("filecontent", content);

		if(dontcheck(msginfo)){
		  return null;
		}


		r = scanFileURI(uri.toString());
		if(r != null) {
			return r;
		}

		if(fileName != null){
			r = scanFileName(fileName);
		}
		if(r != null) {
			return r;
		}

		r = scanFileContent(content);
		if(r != null) {
			return r;
		}

		String hash = RetireUtil.getHash(msg.getResponseBody().toString());
		return scanHash(hash);
	}

	/*
	 * This function computes the SHA 1 hash of the HTTP response body,
	 * IF the hash matches that of an existing entry in the vulnerability database
	 * corresponding info is returned.
	 * ELSE an empty HashSet is returned.
	 */

	private static Result scanHash(final String hash) {
		  HashSet<String> results = new HashSet<String>();
		  for (Object jsfile: json.entrySet()) {
			 Map.Entry<String, JSONObject> mjsFile = (Map.Entry<String, JSONObject>)jsfile;
			 JSONObject extractors =  (JSONObject)mjsFile.getValue().get("extractors");
			 JSONObject hashes = (JSONObject)extractors.get("hashes");

			 //reading all filename regexes for this JS library
			 if(hashes != null){
				 for (Object hashi : hashes.entrySet()) {
					 Map.Entry<String, String> hashEntry  = (Map.Entry<String, String>)hashi;
				     JSONArray vulnerabilities = (JSONArray)mjsFile.getValue().get("vulnerabilities");
				     if(hash.equalsIgnoreCase(hashEntry.getKey())){
				    	 results = isVersionVulnerable(vulnerabilities, hashEntry.getValue());
				    	 return new Result(mjsFile.getKey(),hashEntry.getValue(),results);
				      }
			     }
			 }
	      }
		  return null;
	}

	private static Result scanFileContent(final String content) {
		return scan("filecontent", content);
	}

	public static Result  scanFileName(final String filename){
		return scan("filename", filename);
	}

	static Result scanFileURI(final String fileURI){
		return scan("uri", fileURI);
	}

	/*
	 * This function takes in the criterion used for searching the vulnerability database.
	 * The criterion can be:
	 * FileName OR FileURL OR FileContent
	 */
	public static Result scan(final String criterion, final String inputFile){
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
  private static boolean dontcheck(final HashMap<String, String> msginfo) {
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
   private static HashSet<String> isVersionVulnerable(final JSONArray vulnerabilities, final String inpversion){
    	//Do a match for each of the above vulnerabilities
    	HashSet<String> results = new HashSet<String>();
    	Iterator<JSONObject> viterator = vulnerabilities.iterator();

		 while (viterator.hasNext()) {
		 		Boolean isVulnerable = false;
			    JSONObject vnext= viterator.next();

            if(vnext.containsKey("atOrAbove") && vnext.containsKey("below")){
            	if(RetireUtil.isAtOrAbove(inpversion, (String)vnext.get("atOrAbove")) &&
            			!RetireUtil.isAtOrAbove(inpversion, (String)vnext.get("below"))){
            		isVulnerable = true;
            	}
            }else if(vnext.containsKey("below")){
            	if(!RetireUtil.isAtOrAbove(inpversion, (String)vnext.get("below"))){
            		isVulnerable = true;
         	     }
            }else if(vnext.containsKey("atOrAbove")){
             	if(RetireUtil.isAtOrAbove(inpversion, (String)vnext.get("atOrAbove"))){
           		     isVulnerable = true;
             	}
            }
            if(isVulnerable){
     		   JSONArray info = (JSONArray)vnext.get("info");
     		   Iterator<String> iiterator = info.iterator();
     		   while(iiterator.hasNext()) {
				results.add(iiterator.next());
			}
            }
	   }
     return results;
  }

   /*
    * Testing stub
    **/
   public static void main(final String[] args){
	   Result r = scanFileURI("http://ajax.googleapis.com/ajax/libs/angularjs/1.2.19/angular.min.js");
		if(r!=null) {
			System.out.println(r.filename + r.version + r.info);
		}
	}
}


class Result{
	HashSet<String> info = new HashSet<String>();
	String version;
	String filename;

	Result(final String filename, final String version, final HashSet<String> info){
		this.filename = filename;
		this.version = version;
		this.info = info;
	}
}