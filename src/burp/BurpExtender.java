package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp Extender to find instances of applications revealing detailed error messages 
 * 
 * Some examples: 
 * <li>Fatal error: Call to a member function getId() on a non-object in /var/www/docroot/application/modules/controllers/ModalController.php on line 609
 * <li>Server: Apache/2.2.4 (Unix) mod_perl/2.0.3 Perl/v5.8.8
 * <li>X-AspNet-Version: 4.0.30319
 * 
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    
    //regex for error message identifiers
    private static final Pattern PHP_ON_LINE = Pattern.compile("\\.php on line [0-9]+");
    private static final Pattern PHP_FATAL_ERROR = Pattern.compile("Fatal error:");
    private static final Pattern PHP_LINE_NUMBER = Pattern.compile("\\.php:[0-9]+");
    private static final Pattern MSSQL_ERROR = Pattern.compile("\\[(ODBC SQL Server Driver|SQL Server)\\]");
    private static final Pattern MYSQL_SYNTAX_ERROR = Pattern.compile("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near");
    private static final Pattern JAVA_LINE_NUMBER = Pattern.compile("\\.java:[0-9]+");
    private static final Pattern JAVA_COMPILED_CODE = Pattern.compile("\\.java\\((Inlined )?Compiled Code\\)");
    private static final Pattern ASP_STACK_TRACE = Pattern.compile("[A-Za-z\\.]+\\(([A-Za-z0-9, ]+)?\\) \\+[0-9]+");
    private static final Pattern PERL_STACK_TRACE = Pattern.compile("at (\\/[A-Za-z0-9\\.]+)*\\.pm line [0-9]+");
    private static final Pattern PYTHON_STACK_TRACE = Pattern.compile("File \"[A-Za-z0-9\\-_\\./]*\", line [0-9]+, in");
    private static final Pattern RUBY_LINE_NUMBER = Pattern.compile("\\.rb:[0-9]+:in");
    
    private static final List<MatchRule> rules = new ArrayList<MatchRule>();
    static {
	rules.add(new MatchRule(PHP_ON_LINE, 0, "PHP"));
	rules.add(new MatchRule(PHP_FATAL_ERROR, 0, "PHP"));
	rules.add(new MatchRule(PHP_LINE_NUMBER, 0, "PHP"));
	rules.add(new MatchRule(MSSQL_ERROR, 0, "Microsoft SQL Server"));
	rules.add(new MatchRule(MYSQL_SYNTAX_ERROR, 0, "MySQL"));
	rules.add(new MatchRule(JAVA_LINE_NUMBER, 0, "Java"));
	rules.add(new MatchRule(JAVA_COMPILED_CODE, 0, "Java"));
	rules.add(new MatchRule(ASP_STACK_TRACE, 0, "ASP.Net"));
	rules.add(new MatchRule(PERL_STACK_TRACE, 0, "Perl"));
	rules.add(new MatchRule(PYTHON_STACK_TRACE, 0, "Python"));
	rules.add(new MatchRule(RUBY_LINE_NUMBER, 0, "Ruby"));
    }
    
    
    /**
     * implement IBurpExtender
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
	// keep a reference to our callbacks object
	this.callbacks = callbacks;

	// obtain an extension helpers object
	helpers = callbacks.getHelpers();

	// set our extension name
	callbacks.setExtensionName("Error Message Checks");

	// register the extension as a custom scanner check
	callbacks.registerScannerCheck(this);
	
	//get the output stream for info messages
	output = callbacks.getStdout();
	
	println("Loaded Error Message Checks");
    }

    /**
    * implement IScannerCheck
    */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
	List<ScannerMatch> matches = new ArrayList<ScannerMatch>();
	List<IScanIssue> issues = new ArrayList<IScanIssue>();

	//get the URL of the requst
	URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
	println("Scanning for error messages: " + url.toString());
	
	//get the body of the response
	byte[] responseBytes = baseRequestResponse.getResponse();
	String response = helpers.bytesToString(responseBytes);
	
	//iterate through rules and check for matches
	for (MatchRule rule : rules) {
	    Matcher matcher = rule.getPattern().matcher(response);
	    while (matcher.find()) {
		println("FOUND " + rule.getType() + "!");
		
		//get the actual match 
		String group;
		if (rule.getMatchGroup() != null) {
		    group = matcher.group(rule.getMatchGroup());
		} else {
		    group = matcher.group();
		}

		println("start: " + matcher.start() + " end: " + matcher.end() + " group: " + group);

		matches.add(new ScannerMatch(matcher.start(), matcher.end(), group, rule.getType()));
	    }
	}
		
	// report the issues ------------------------
	if (!matches.isEmpty()) {
	    Collections.sort(matches);  //matches must be in order 
	    
	    ScannerMatch firstMatch = matches.get(0);
	    StringBuilder description = new StringBuilder(matches.size() * 256);
	    description.append("The application displays detailed error messages when unhandled ").append(firstMatch.getType()).append(" exceptions occur.<br>");
	    description.append("Detailed technical error messages can allow an adversary to gain information about the application and database that could be used to conduct further attacks.");

	    List<int[]> startStop = new ArrayList<int[]>(1);
	    for (ScannerMatch match : matches) {
		println("Processing match: " + match);
		println("    start: " + match.getStart() + " end: " + match.getEnd() + " match: " + match.getMatch() + " match: " + match.getMatch());

		//add a marker for code highlighting
		startStop.add(new int[]{match.getStart(), match.getEnd()});
	    }

	    println("    Description: " + description.toString());

	    issues.add(new CustomScanIssue(
			baseRequestResponse.getHttpService(),
			helpers.analyzeRequest(baseRequestResponse).getUrl(),
			new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, startStop)},
			"Detailed Error Messages Revealed",
			description.toString(),
			"Medium",
			"Firm"));

	    println("issues: " + issues.size());

	    return issues;
	    
	}
    
	return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, 
					 IScannerInsertionPoint insertionPoint) {

	return null;

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
	// This method is called when multiple issues are reported for the same URL 
	// path by the same extension-provided check. The value we return from this 
	// method determines how/whether Burp consolidates the multiple issues
	// to prevent duplication
	//
	// Since the issue name is sufficient to identify our issues as different,
	// if both issues have the same name, only report the existing issue
	// otherwise report both issues
	if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
	    println("DUPLICATE ISSUE! Consolidating...");
	    return -1;
	} else {
	    return 0;
	}
    }
    
    private void println(String toPrint) {
	try {
	    output.write(toPrint.getBytes());
	    output.write("\n".getBytes());
	    output.flush();
	} catch (IOException ioe) {
	    ioe.printStackTrace();
	} 
    }
}



/**
 * class implementing IScanIssue to hold our custom scan issue details
 */
class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(
	    IHttpService httpService,
	    URL url,
	    IHttpRequestResponse[] httpMessages,
	    String name,
	    String detail,
	    String severity,
	    String confidence) {
	this.httpService = httpService;
	this.url = url;
	this.httpMessages = httpMessages;
	this.name = name;
	this.detail = detail;
	this.severity = severity;
	this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
	return url;
    }

    @Override
    public String getIssueName() {
	return name;
    }

    @Override
    public int getIssueType() {
	return 0;
    }

    @Override
    public String getSeverity() {
	return severity;
    }

    @Override
    public String getConfidence() {
	return confidence;
    }

    @Override
    public String getIssueBackground() {
	return null;
    }

    @Override
    public String getRemediationBackground() {
	return null;
    }

    @Override
    public String getIssueDetail() {
	return detail;
    }

    @Override
    public String getRemediationDetail() {
	return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
	return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
	return httpService;
    }

}


class ScannerMatch implements Comparable<ScannerMatch> {

    private Integer start;
    private int end;
    private String match;
    private String type;

    public ScannerMatch(int start, int end, String match, String type) {
	this.start = start;
	this.end = end;
	this.match = match;
	this.type = type;
    }

    public int getStart() {
	return start;
    }

    public int getEnd() {
	return end;
    }

    public String getMatch() {
	return match;
    }

    public String getType() {
	return type;
    }    
    
    @Override
    public int compareTo(ScannerMatch m) {
        return start.compareTo(m.getStart());
    }
}


class MatchRule {
    private Pattern pattern;
    private Integer matchGroup;
    private String type;

    public MatchRule(Pattern pattern, Integer matchGroup, String type) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
    }

    public Pattern getPattern() {
	return pattern;
    }

    public Integer getMatchGroup() {
	return matchGroup;
    }

    public String getType() {
	return type;
    }
}