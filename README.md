[![Build Status](https://travis-ci.org/augustd/burp-suite-error-message-checks.svg?branch=master)](https://travis-ci.org/augustd/burp-suite-error-message-checks)
[![Dependency Status](https://www.versioneye.com/user/projects/5a6688570fb24f0ff7d620b9/badge.svg?style=flat-square)](https://www.versioneye.com/user/projects/5a6688570fb24f0ff7d620b9)

# burp-suite-error-message-checks
This Burp Suite 1.5+ extension passively detects server error messages in running applications. Some examples:

- Fatal error: Call to a member function getId() on a non-object in /var/www/docroot/application/modules/controllers/ModalController.php on line 609
- You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax
- [SEVERE] at net.minecraft.server.World.tickEntities(World.java:1146)
- System.Web.UI.Page.ProcessRequestMain(Boolean includeStagesBeforeAsyncPoint) +2071
- c() called at [/tmp/include.php:10]
- Use of uninitialized value in string eq at /Library/Perl/5.8.6/WWW/Mechanize.pm line 695

Often error messages may go unnoticed by a tester who is only looking at the application UI. This extension is designed to passively detect error messages, even during scanning, spidering, etc.

Match rules are loaded from a [remote tab-delimited file](https://github.com/augustd/burp-suite-error-message-checks/blob/master/src/main/resources/burp/match-rules.tab) at extension startup. Users can also load their own match rules from a local file or using the BApp GUI.

## Building: 
`mvn clean install`
