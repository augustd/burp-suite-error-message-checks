package burp;

import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssue;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import java.util.List;
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
public class BurpExtender extends PassiveScan {

    public static final String ISSUE_NAME = "Detailed Error Messages Revealed";
    
    @Override
    protected void initialize() {
	//call the superclass initializer
	super.initialize();
	
	//set the extension Name
	extensionName = "Error Message Checks";
	
	//create match rules
	rules.add(new com.codemagi.burp.MatchRule(PHP_ON_LINE, 0, "PHP"));
	rules.add(new com.codemagi.burp.MatchRule(PHP_HTML_ON_LINE, 0, "PHP"));
	rules.add(new com.codemagi.burp.MatchRule(PHP_FATAL_ERROR, 0, "PHP"));
	rules.add(new com.codemagi.burp.MatchRule(PHP_LINE_NUMBER, 0, "PHP"));
	rules.add(new com.codemagi.burp.MatchRule(MSSQL_ERROR, 0, "Microsoft SQL Server"));
	rules.add(new com.codemagi.burp.MatchRule(MYSQL_SYNTAX_ERROR, 0, "MySQL"));
	rules.add(new com.codemagi.burp.MatchRule(JAVA_LINE_NUMBER, 0, "Java"));
	rules.add(new com.codemagi.burp.MatchRule(JAVA_COMPILED_CODE, 0, "Java"));
	rules.add(new com.codemagi.burp.MatchRule(ASP_STACK_TRACE, 0, "ASP.Net"));
	rules.add(new com.codemagi.burp.MatchRule(PERL_STACK_TRACE, 0, "Perl"));
	rules.add(new com.codemagi.burp.MatchRule(PYTHON_STACK_TRACE, 0, "Python"));
	rules.add(new com.codemagi.burp.MatchRule(RUBY_LINE_NUMBER, 0, "Ruby"));
    }

    @Override
    protected String getIssueName() {
	return ISSUE_NAME;
    }

    @Override
    protected String getIssueDetail(List<com.codemagi.burp.ScannerMatch> matches) {
	com.codemagi.burp.ScannerMatch firstMatch = matches.get(0);

	StringBuilder description = new StringBuilder(matches.size() * 256);
	description.append("The application displays detailed error messages when unhandled ").append(firstMatch.getType()).append(" exceptions occur.<br>");
	description.append("Detailed technical error messages can allow an adversary to gain information about the application and database that could be used to conduct further attacks.");

	return description.toString();
    }
    
    @Override
    protected ScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<com.codemagi.burp.ScannerMatch> matches, List<int[]> startStop) {
	return new ScanIssue(
		baseRequestResponse.getHttpService(), 
		helpers.analyzeRequest(baseRequestResponse).getUrl(), 
		new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, startStop)}, 
		getIssueName(), 
		getIssueDetail(matches), 
		ScanIssueSeverity.MEDIUM.getName(), 
		ScanIssueConfidence.FIRM.getName());
    }
    
    //regex for error message identifiers
    private static final Pattern PHP_ON_LINE = Pattern.compile("\\.php on line [0-9]+");
    private static final Pattern PHP_HTML_ON_LINE = Pattern.compile("\\.php</b> on line <b>[0-9]+");
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
    
}