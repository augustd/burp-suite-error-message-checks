package burp;

import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.RuleTableComponent;
import com.codemagi.burp.ScanIssue;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.codemagi.burp.ScannerMatch;
import com.monikamorrow.burp.BurpSuiteTab;
import com.monikamorrow.burp.ToolsScopeComponent;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Burp Extender to find instances of applications revealing detailed error messages
 *
 * Some examples:
 * <li>Fatal error: Call to a member function getId() on a non-object in /var/www/docroot/application/modules/controllers/ModalController.php on line 609
 * <li>[SEVERE] at net.minecraft.server.World.tickEntities(World.java:1146)
 * <li>Use of uninitialized value in string eq at /Library/Perl/5.8.6/WWW/Mechanize.pm line 695
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 * @contributor James Kettle (Ruby detection pattern)
 */
public class BurpExtender extends PassiveScan implements IHttpListener {

	public static final String ISSUE_NAME = "Detailed Error Messages Revealed";

	protected RuleTableComponent rulesTable;
	protected ToolsScopeComponent toolsScope;
	protected BurpSuiteTab mTab;

	@Override
	protected void initPassiveScan() {
		//set the extension Name
		extensionName = "Error Message Checks";

		//set the settings namespace
		settingsNamespace = "EMC_";

		//Create the GUI
		rulesTable = new RuleTableComponent(this, callbacks, "https://raw.githubusercontent.com/augustd/burp-suite-error-message-checks/master/src/main/resources/burp/match-rules.tab");
		mTab = new BurpSuiteTab(extensionName, callbacks);
		mTab.addComponent(rulesTable);
		
		toolsScope = new ToolsScopeComponent(callbacks);
		toolsScope.setEnabledToolConfig(IBurpExtenderCallbacks.TOOL_PROXY, false); 
		toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_PROXY, false);
		toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_SCANNER, true);
		toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_REPEATER, true);
		toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_INTRUDER, true);
		mTab.addComponent(toolsScope);
		
		//register this extension as an HTTP listener
		callbacks.registerHttpListener(this);
	}

	protected String getIssueName() {
		return ISSUE_NAME;
	}

	protected String getIssueDetail(List<com.codemagi.burp.ScannerMatch> matches) {
		com.codemagi.burp.ScannerMatch firstMatch = matches.get(0);

		StringBuilder description = new StringBuilder(matches.size() * 256);
		description.append("The application displays detailed error messages when unhandled ").append(firstMatch.getType()).append(" exceptions occur.<br>");
		description.append("Detailed technical error messages can allow an adversary to gain information about the application and database that could be used to conduct further attacks.");

		return description.toString();
	}

	protected ScanIssueSeverity getIssueSeverity(List<com.codemagi.burp.ScannerMatch> matches) {
		ScanIssueSeverity output = ScanIssueSeverity.INFO;
		for (ScannerMatch match : matches) {
			//if the severity value of the match is higher, then update the stdout value
			ScanIssueSeverity matchSeverity = match.getSeverity();
			if (matchSeverity != null && 
				output.getValue() < matchSeverity.getValue()) {

				output = matchSeverity;
			}
		}
		return output;
	}

	protected ScanIssueConfidence getIssueConfidence(List<com.codemagi.burp.ScannerMatch> matches) {
		ScanIssueConfidence output = ScanIssueConfidence.TENTATIVE;
		for (ScannerMatch match : matches) {
			//if the severity value of the match is higher, then update the stdout value
			ScanIssueConfidence matchConfidence = match.getConfidence();
			if (matchConfidence != null
				&& output.getValue() < matchConfidence.getValue()) {

				output = matchConfidence;
			}
		}
		return output;
	}

	@Override
	protected IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> startStop) {
		ScanIssueSeverity overallSeverity = getIssueSeverity(matches);
		ScanIssueConfidence overallConfidence = getIssueConfidence(matches);

		return new ScanIssue(
				baseRequestResponse,
				helpers,
				callbacks,
				startStop,
				getIssueName(),
				getIssueDetail(matches),
				overallSeverity.getName(),
				overallConfidence.getName());
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (!messageIsRequest && toolsScope.isToolSelected(toolFlag)) {
			//first get the scan issues
			List<IScanIssue> issues = runPassiveScanChecks(messageInfo);

			//if we have found issues, consolidate duplicates and add new issues to the Scanner tab
			if (issues != null && !issues.isEmpty()) {
				callbacks.printOutput("NEW issues: " + issues.size());
				//get the request URL prefix
				URL url = helpers.analyzeRequest(messageInfo).getUrl();
				String urlPrefix = url.getProtocol() + "://" + url.getHost() + url.getPath();
				callbacks.printOutput("Consolidating issues for urlPrefix: " + urlPrefix);
				
				//get existing issues
				IScanIssue[] existingArray = callbacks.getScanIssues(urlPrefix);
				Set<IScanIssue> existingIssues = new HashSet<>();
				for (IScanIssue arrayIssue : existingArray) {
					//create instances of ScanIssue class so we can compare them
					ScanIssue existing = new ScanIssue(arrayIssue);
					//add to HashSet to resolve dupes
					existingIssues.add(existing);
				}
				
				//iterate through newly found issues
				for (IScanIssue newIssue : issues) {
					if (!existingIssues.contains(newIssue)) {
						callbacks.printOutput("Adding NEW scan issue: " + newIssue);
						callbacks.addScanIssue(newIssue);
					}
				}
			}
		}
	}

}
