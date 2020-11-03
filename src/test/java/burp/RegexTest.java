package burp;

import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author august
 */
public class RegexTest {

    static List<MatchRule> matchRules = new ArrayList<>();
    static String testResponse;
    static String falsePositives;
	static boolean loadSuccessful; 
    
    @BeforeClass
    public static void setUpClass() throws Exception {
		loadSuccessful = loadMatchRules("burp/match-rules.tab");
        testResponse = loadTestResponse("burp/testResponse.txt");
        falsePositives = loadTestResponse("burp/falsePositives.txt");
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
        //testLoadMatchRules();
    }

    @After
    public void tearDown() throws Exception {
    }
    
    @Test
    public void testLoadMatchRules() {
        System.out.println("***** testLoadMatchRules *****");
        
        //Boolean loadSuccessful = loadMatchRules("burp/match-rules.tab");
        
        assertTrue(loadSuccessful);
    }
    
    @Test
    public void testMatchRules() {
        System.out.println("***** testMatchRules *****");
        
        int matchCount = 0;
        
        for (MatchRule rule : matchRules) {
			System.out.print("Testing rule: " + rule.getPattern());
			Matcher matcher = rule.getPattern().matcher(testResponse);
            long startTime = System.currentTimeMillis();
            int expectedMatches = (rule.getExpectedMatches() != null) ? rule.getExpectedMatches() : 1 ;
            int foundMatches = 0;
            StringBuilder matches = new StringBuilder();
            while (matcher.find()) {
                foundMatches++;
                matches.append(matcher.group()).append("\n");
            }
            
			long endTime = System.currentTimeMillis();
			long elapsedTime = endTime - startTime; 
            System.out.println(" matches: " + foundMatches + " time: " + elapsedTime + " ms");
			System.out.println("   Matched: ");
            System.out.println(matches.toString());
			//check that the match rule regex has acceptable performance
			assertTrue("Regex " + rule.getPattern() + " took too long to execute (" + elapsedTime + "ms)", 200 > elapsedTime);  
            
			if (foundMatches >= expectedMatches) { 
                matchCount++;
            } else {
                System.out.println("Unable to find match for: " + rule.getPattern());
            }
        }
        
        System.out.println(String.format("Found %d matches out of %d", matchCount, matchRules.size()));
        assertEquals(matchRules.size(), matchCount);
    }
    
    @Test
    public void testFalsePositives() {
        System.out.println("***** testFalsePositives *****");
        
        int matchCount = 0;
        
        for (MatchRule rule : matchRules) {
            Matcher matcher = rule.getPattern().matcher(falsePositives);
            int foundMatches = 0;
            while (matcher.find()) {
                foundMatches++;
            }
            
            System.out.println("Testing rule: " + rule.getPattern() + " matches: " + foundMatches);
            
			if (foundMatches >= 1) { 
                matchCount++;
                System.out.println("Found false positive for: " + rule.getPattern());
            }
        }
        
        System.out.println(String.format("Found %d matches out of %d", matchCount, matchRules.size()));
        assertEquals(0, matchCount);
    }
    
    /**
     * Load match rules from a file
     */
    private static boolean loadMatchRules(String url) {
		//load match rules from file
        System.out.println("***** loadMatchRules: " + url);

	try {
	    //read match rules from the stream
	    InputStream is = RegexTest.class.getClassLoader().getResourceAsStream(url); 
	    BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
	    
	    String str;
	    while ((str = reader.readLine()) != null) {
		System.out.println("Match Rule: " + str);
		if (str.trim().length() == 0) {
		    continue;
		}

		String[] values = str.split("\\t");
		
                try {
                    Pattern pattern = Pattern.compile(values[0]);

                    MatchRule rule = new MatchRule(
                            pattern, 
                            new Integer(values[1]), 
                            values[2], 
                            ScanIssueSeverity.fromName(values[3]),
                            ScanIssueConfidence.fromName(values[4])
                    );
                    
                    if (values.length > 5) {
                        rule.setExpectedMatches(new Integer(values[5]));
                    }
                    
                    matchRules.add(rule);
                    
                } catch (PatternSyntaxException pse) {
                    pse.printStackTrace();
                }
	    }
            
            return true;

	} catch (IOException e) {
	    e.printStackTrace();
	} catch (NumberFormatException e) {
	    e.printStackTrace();
        }
        
        return false;
    }

    /**
     * Load match rules from a file
     */
    private static String loadTestResponse(String url) throws URISyntaxException {
		//load match rules from file
        System.out.println("***** loadMatchRules: " + url);
        StringBuilder output = new StringBuilder();
        
	try {
	    //read match rules from the stream
            URI path = RegexTest.class.getClassLoader().getResource(url).toURI();
            File f = new File(path);
	    BufferedReader reader = new BufferedReader(new FileReader(f));
	    
	    String str;
	    while ((str = reader.readLine()) != null) {
		System.out.println("Test response: " + str);
                output.append(str);
	    }
            
            return output.toString();

	} catch (IOException e) {
	    e.printStackTrace();
	} catch (NumberFormatException e) {
	    e.printStackTrace();
	}
        
        return null;
    }
}
