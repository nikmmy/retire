package org.zaproxy.zap.extension.retire;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

public class RetireUtil {
	/*
	 * This utility function computes the SHA 1 hash input string
	 */
	static String getHash(final String httpbody) {
	    try
	    {
	        MessageDigest crypt = MessageDigest.getInstance("SHA-1");
	        crypt.update(httpbody.getBytes("UTF-8"));
	        return byteToHex(crypt.digest());
	    }
	    catch(NoSuchAlgorithmException | UnsupportedEncodingException e)
	    {
	        e.printStackTrace();
		    return "";
	    }
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
	static String getFileName(final URI uri) {
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
	  * This utility function reads a file as a stream and returns its contents
	  * as a string.
	  */
	static String getStringResource(final String resourceName) throws IOException {
            InputStream in = null;
            StringBuilder sb = new StringBuilder();
            try{
                    in = RetireExtension.class.getResourceAsStream(resourceName);
                    int numRead=0;
                    byte[] buf = new byte[1024];
                    while((numRead = in.read(buf)) != -1){
                    	sb.append(new String(buf, 0, numRead));
                    }
                   return sb.toString();
            	}finally {
                    if(in != null){
                        try{
                             in.close();
                            }catch (IOException e) {

                            }
                    }
               }
    }


	/*
	 * This utility function determines if
     *  version1(of a particular JS library) is >= version2(of a particular JS library)
	 */
	static Boolean isAtOrAbove(final String version1, final String version2) {
		String[] v1 = version1.split("[\\.-]");
		String[] v2 = version2.split("[\\.-]");
		int l = v1.length > v2.length ? v1.length : v2.length;
		for(int i = 0; i < l; i++) {
			String v1_part = v1.length > i ? v1[i] : "0";
			String v2_part = v2.length > i ? v2[i] : "0";
			Boolean v1_isnumber = isNumber(v1_part);
			Boolean v2_isnumber = isNumber(v2_part);

			//if either of v1 or v2 is string
			if (v1_isnumber != v2_isnumber) {
				return v1_isnumber;
			}

			//if both v1 and v2 are strings
			if(!v1_isnumber && !v2_isnumber){
				return v1_part.compareTo(v2_part) > 0;
			}

			//if both are numbers
			if (Integer.parseInt(v1_part) < Integer.parseInt(v2_part)) {
				return false;
			}
			if(Integer.parseInt(v1_part) > Integer.parseInt(v2_part)) {
				return true;
			}
		 }
	    return true;
	}
	/*
     * This utility function determines if given input string is numerical.
 	 */
	static Boolean isNumber(final String num) {
		return num.matches("^[0-9]+$");
	}
}
