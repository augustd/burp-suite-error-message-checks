This is a Burp Suite 1.5+ extension to detect error messages in running applications. Some examples:

```
- Fatal error: Call to a member function getId() on a non-object in /var/www/docroot/application/modules/controllers/ModalController.php on line 609
- You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax
- [SEVERE] at net.minecraft.server.World.tickEntities(World.java:1146)
- System.Web.UI.Page.ProcessRequestMain(Boolean includeStagesBeforeAsyncPoint) +2071
- c() called at [/tmp/include.php:10]
- Use of uninitialized value in string eq at /Library/Perl/5.8.6/WWW/Mechanize.pm line 695
```

Often error messages may not be noticed during the normal course of testing. This extension is designed to passively detect error messages, even during scanning, spidering, etc.
