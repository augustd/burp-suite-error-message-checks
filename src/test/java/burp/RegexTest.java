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

    List<MatchRule> matchRules = new ArrayList<>();
    String testResponse;
    String falsePositives;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
        testResponse = loadTestResponse("burp/testResponse.txt");
        falsePositives = loadTestResponse("burp/falsePositives.txt");
        testLoadMatchRules();
    }

    @After
    public void tearDown() throws Exception {
    }
    
    @Test
    public void testLoadMatchRules() {
        System.out.println("***** testLoadMatchRules *****");
        
        Boolean loadSuccessful = loadMatchRules("burp/match-rules.tab");
        
        assertTrue(loadSuccessful);
    }
    
    @Test
    public void testMatchRules() {
        System.out.println("***** testMatchRules *****");
        
        int matchCount = 0;
        
        for (MatchRule rule : matchRules) {
            Matcher matcher = rule.getPattern().matcher(testResponse);
            int expectedMatches = (rule.getExpectedMatches() != null) ? rule.getExpectedMatches() : 1 ;
            int foundMatches = 0;
            while (matcher.find()) {
                foundMatches++;
            }
            
            System.out.println("Testing rule: " + rule.getPattern() + " matches: " + foundMatches);
            
	    if (foundMatches >= expectedMatches) { 
                matchCount++;
            } else {
                System.out.println("Unable to find match for: " + rule.getPattern());
            }
        }
        
        System.out.println(String.format("Found %d matches out of %d", matchCount, matchRules.size()));
        assertEquals(matchCount, matchRules.size());
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
            } else {
                System.out.println("Unable to find match for: " + rule.getPattern());
            }
        }
        
        System.out.println(String.format("Found %d matches out of %d", matchCount, matchRules.size()));
        assertEquals(matchCount, 0);
    }
    
    /**
     * Load match rules from a file
     */
    private boolean loadMatchRules(String url) {
	//load match rules from file
	try {
	    //read match rules from the stream
	    InputStream is = BurpExtender.class.getClassLoader().getResourceAsStream(url); 
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
    private String loadTestResponse(String url) throws URISyntaxException {
        StringBuilder output = new StringBuilder();
        
	//load match rules from file
	try {
	    //read match rules from the stream
            Class clazz = getClass();
            URI path = clazz.getClassLoader().getResource(url).toURI();
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
