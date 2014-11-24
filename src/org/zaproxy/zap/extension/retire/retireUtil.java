package org.zaproxy.zap.extension.retire;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

public class retireUtil {
	/*
	 * This utility function computes the SHA 1 hash input string
	 */
	static String getHash(String httpbody) {
	    String sha1 = "";
	    try
	    {
	        MessageDigest crypt = MessageDigest.getInstance("SHA-1");
	        crypt.reset();
	        crypt.update(httpbody.getBytes("UTF-8"));
	        sha1 = byteToHex(crypt.digest());
	    }
	    catch(NoSuchAlgorithmException e)
	    {
	        e.printStackTrace();
	    }
	    catch(UnsupportedEncodingException e)
	    {
	        e.printStackTrace();
	    }
	    return sha1;
	}
	
	/*
	 * This utility function computes input byte array to a hex string
	 */
	private static String byteToHex(final byte[] hash)
	{
	    Formatter formatter = new Formatter();
	    for (byte b : hash)
	    {
	        formatter.format("%02x", b);
	    }
	    String result = formatter.toString();
	    formatter.close();
	    return result;
	}
	/*
	 * This utility function retrieves the JS file name from passed URI.
	 */
	static String getFileName(URI uri) {
		String pathname = "";
		try {
			pathname = uri.getPath();
		} catch (URIException e) {
			e.printStackTrace();
		}
		Pattern p = Pattern.compile("\\/([^\\/?#]+)$"); 
		Matcher  m = p.matcher(pathname);
		if(m.find()){
			System.out.println(m.group(1));
			return m.group(1);
		}
		return "";
	}
	
	
	 /*
	  * This utility function reads a file and returns its contents
	  * as a string.
	  */
	static String readFile(String path)  throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded);
	}
		
	/*
	 * This utility function determines if 
     *  version1(of a particular JS library) is >= version2(of a particular JS library)
	 */
	static Boolean isAtOrAbove(String version1, String version2) {
		String[] v1 = version1.split("[\\.-]");
		String[] v2 = version2.split("[\\.-]");
		int l = v1.length > v2.length ? v1.length : v2.length;
		for(int i = 0; i < l; i++) {
			//if either bounds are exceeded
			if(i >=  v1.length)
				return false;
			if(i >= v2.length)
	            return true;
			
			Boolean v1_isnumber = isNumber(v1[i]);
			Boolean v2_isnumber = isNumber(v2[i]);
				
			//if either of v1 or v2 is string
			if (v1_isnumber != v2_isnumber)
				return v1_isnumber;
				
			//if both v1 and v2 are strings
				if(!v1_isnumber && v2_isnumber){
					if (v1[i].compareTo(v2[i]) == -1) 
						return true;
					return false;
				}
		
			//if both are numbers
			if (Integer.parseInt(v1[i]) < Integer.parseInt(v2[i])) 
				return false;
			if(Integer.parseInt(v1[i]) > Integer.parseInt(v2[i]))
				return true;
		 }
	    return true;
	}
	/*
     * This utility function determines if given input string is numerical.	
 	 */
	static Boolean isNumber(String num) {
		if (num.matches("^[0-9]+$")) {
		  return true;
		}
		return false;
	}
}
