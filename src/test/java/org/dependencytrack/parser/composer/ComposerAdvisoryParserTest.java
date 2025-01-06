package org.dependencytrack.parser.composer;

import java.io.IOException;

import org.dependencytrack.parser.composer.model.ComposerAdvisory;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

public class ComposerAdvisoryParserTest {

    public final static JSONObject vulnDrupal = new JSONObject("""
              {
                "advisoryId": "SA-CORE-2018-003",
                "packageName": "drupal/core",
                "title": "Drupal core - Moderately critical - Cross Site Scripting - SA-CORE-2018-003",
                "link": "https://www.drupal.org/sa-core-2018-003",
                "cve": "CVE-2018-9861",
                "affectedVersions": "\u003E= 8.0.0 \u003C8.4.7 || \u003E=8.5.0 \u003C8.5.2",
                "reportedAt": "2018-04-18 15:34:09",
                "composerRepository": "https://packagist.org/",
                "sources": [
                  {
                    "name": "Drupal core - Moderately critical - Cross Site Scripting - SA-CORE-2018-003",
                    "remoteId": "SA-CORE-2018-003"
                  }
                ]
              }
            """);

    public final static JSONObject vulnGHSA = new JSONObject("""
                {
                  "advisoryId": "PKSA-228k-hrjg-43zp",
                  "packageName": "magento/community-edition",
                  "remoteId": "GHSA-297f-r9w7-w492",
                  "title": "Magento Improper input validation vulnerability",
                  "link": "https://github.com/advisories/GHSA-297f-r9w7-w492",
                  "cve": "CVE-2022-42344",
                  "affectedVersions": "=2.4.4|\u003E=2.4.0,\u003C2.4.3-p3|\u003C2.3.7-p4",
                  "source": "GitHub",
                  "reportedAt": "2022-10-20 19:00:29",
                  "composerRepository": "https://packagist.org",
                  "severity": "high",
                  "sources": [
                    {
                      "name": "GitHub",
                      "remoteId": "GHSA-297f-r9w7-w492"
                    }
                  ]
                },
            """);

    public final static JSONObject vulnFriendsNoCve = new JSONObject(
            """
                    {
                      "advisoryId": "PKSA-n8hw-tywm-xrh7",
                      "packageName": "drupal/core",
                      "remoteId": "drupal/core/2019-12-18-1.yaml",
                      "title": "Drupal core - Moderately critical - Denial of Service - SA-CORE-2019-009",
                      "link": "https://www.drupal.org/sa-core-2019-009",
                      "cve": null,
                      "affectedVersions": "\u003E=8.0.0,\u003C8.1.0|\u003E=8.1.0,\u003C8.2.0|\u003E=8.2.0,\u003C8.3.0|\u003E=8.3.0,\u003C8.4.0|\u003E=8.4.0,\u003C8.5.0|\u003E=8.5.0,\u003C8.6.0|\u003E=8.6.0,\u003C8.7.0|\u003E=8.7.0,\u003C8.7.11|\u003E=8.8.0,\u003C8.8.1",
                      "source": "FriendsOfPHP/security-advisories",
                      "reportedAt": "2019-12-18 00:00:00",
                      "composerRepository": "https://packagist.org",
                      "severity": "critical",
                      "sources": [
                        {
                          "name": "FriendsOfPHP/security-advisories",
                          "remoteId": "drupal/core/2019-12-18-1.yaml"
                        },
                        {
                          "name": "GitHub",
                          "remoteId": "GHSA-7v68-3pr5-h3cr"
                        }
                      ]
                    }
                      """);

    public final static JSONObject vulnFriends = new JSONObject(
            """
                    {
                      "advisoryId": "PKSA-p9s6-dthp-ws2d",
                      "packageName": "simplesamlphp/saml2",
                      "remoteId": "simplesamlphp/saml2/CVE-2016-9814.yaml",
                      "title": "Incorrect signature verification",
                      "link": "https://simplesamlphp.org/security/201612-01",
                      "cve": "CVE-2016-9814",
                      "affectedVersions": "\u003C1.8.1|\u003E=1.9.0,\u003C1.9.1|\u003E=1.10,\u003C1.10.3|\u003E=2.0,\u003C2.3.3",
                      "source": "FriendsOfPHP/security-advisories",
                      "reportedAt": "2016-11-29 13:12:44",
                      "composerRepository": "https://packagist.org",
                      "severity": "critical",
                      "sources": [
                        {
                          "name": "GitHub",
                          "remoteId": "GHSA-r8v4-7vwj-983x"
                        },
                        {
                          "name": "FriendsOfPHP/security-advisories",
                          "remoteId": "simplesamlphp/saml2/CVE-2016-9814.yaml"
                        }
                      ]
                    },
                    """);

    // Hypothetical vulnerability to future proof our parser
    public final static JSONObject vulnComposer = new JSONObject(
            """
                      {
                        "advisoryId": "PKSA-m9t7-ggb8-abcd",
                        "packageName": "social/media",
                        "remoteId": null,
                        "title": "File REST resource does not properly validate",
                        "link": "https://www.drupal.org/SA-CORE-2017-003",
                        "cve": null,
                        "affectedVersions": "\u003E=8.0,\u003C8.1.0|\u003E=8.1.0,\u003C8.2.0|\u003E=8.2.0,\u003C8.3.0|\u003E=8.3.0,\u003C8.3.4",
                        "source": "somesource",
                        "reportedAt": "2017-06-21 18:13:27",
                        "composerRepository": "https://packagist.org",
                        "severity": "medium",
                        "sources": []
                      }
                    """);

    public final static JSONObject vulnInvalidDateTime = new JSONObject(
            """
                    {
                      "advisoryId": "PKSA-n8hw-tywm-xrh7",
                      "packageName": "drupal/core",
                      "remoteId": "drupal/core/2019-12-18-1.yaml",
                      "title": "Drupal core - Moderately critical - Denial of Service - SA-CORE-2019-009",
                      "link": "https://www.drupal.org/sa-core-2019-009",
                      "cve": null,
                      "affectedVersions": "\u003E=8.0.0,\u003C8.1.0|\u003E=8.1.0,\u003C8.2.0|\u003E=8.2.0,\u003C8.3.0|\u003E=8.3.0,\u003C8.4.0|\u003E=8.4.0,\u003C8.5.0|\u003E=8.5.0,\u003C8.6.0|\u003E=8.6.0,\u003C8.7.0|\u003E=8.7.0,\u003C8.7.11|\u003E=8.8.0,\u003C8.8.1",
                      "source": "FriendsOfPHP/security-advisories",
                      "reportedAt": "2019-122222-18 00:00:00",
                      "composerRepository": "https://packagist.org",
                      "severity": "critical",
                      "sources": [
                        {
                          "name": "FriendsOfPHP/security-advisories",
                          "remoteId": "drupal/core/2019-12-18-1.yaml"
                        },
                        {
                          "name": "GitHub",
                          "remoteId": "GHSA-7v68-3pr5-h3cr"
                        }
                      ]
                    }
                      """);
// TODO VS Test wildcardall versions
    public final static JSONObject vulnWildcardAll = new JSONObject("""
            {
              "advisoryId": "PKSA-n8hw-tywm-xrh7",
              "packageName": "drupal/core",
              "remoteId": "drupal/core/2019-12-18-1.yaml",
              "title": "Drupal core - Moderately critical - Denial of Service - SA-CORE-2019-009",
              "link": "https://www.drupal.org/sa-core-2019-009",
              "cve": null,
              "affectedVersions": "*",
              "source": "FriendsOfPHP/security-advisories",
              "reportedAt": "2019-122222-18 00:00:00",
              "composerRepository": "https://packagist.org",
              "severity": "critical",
              "sources": [
                {
                  "name": "FriendsOfPHP/security-advisories",
                  "remoteId": "drupal/core/2019-12-18-1.yaml"
                },
                {
                  "name": "GitHub",
                  "remoteId": "GHSA-7v68-3pr5-h3cr"
                }
              ]
            }
              """);


              //TODO VS Test NoOp version
    public final static JSONObject vulnOneVersionNoOperator = new JSONObject("""
            {
              "advisoryId": "PKSA-n8hw-tywm-xrh7",
              "packageName": "drupal/core",
              "remoteId": "drupal/core/2019-12-18-1.yaml",
              "title": "Drupal core - Moderately critical - Denial of Service - SA-CORE-2019-009",
              "link": "https://www.drupal.org/sa-core-2019-009",
              "cve": null,
              "affectedVersions": "8.1.0",
              "source": "FriendsOfPHP/security-advisories",
              "reportedAt": "2019-122222-18 00:00:00",
              "composerRepository": "https://packagist.org",
              "severity": "critical",
              "sources": [
                {
                  "name": "FriendsOfPHP/security-advisories",
                  "remoteId": "drupal/core/2019-12-18-1.yaml"
                },
                {
                  "name": "GitHub",
                  "remoteId": "GHSA-7v68-3pr5-h3cr"
                }
              ]
            }
              """);

    @Test
    public void testDateTime() {
        ComposerAdvisory vuln = ComposerAdvisoryParser.parseAdvisory(vulnInvalidDateTime);
        Assert.assertNull(vuln.getReportedAt());
    }

    @Test
    public void testSources() {
        ComposerAdvisory vuln = ComposerAdvisoryParser.parseAdvisory(vulnFriends);
        Assert.assertEquals(2, vuln.getSources().size());
        Assert.assertTrue(vuln.getSources().containsKey("github"));
        Assert.assertEquals("GHSA-r8v4-7vwj-983x", vuln.getSources().get("github"));
        Assert.assertTrue(vuln.getSources().containsKey("friendsofphp/security-advisories"));
        Assert.assertEquals("simplesamlphp/saml2/CVE-2016-9814.yaml", vuln.getSources().get("friendsofphp/security-advisories"));
    }

    @Test
    public void testParseNoErrors() throws IOException {
        ComposerAdvisoryParser.parseAdvisory(vulnFriends);
        ComposerAdvisoryParser.parseAdvisory(vulnComposer);
        ComposerAdvisoryParser.parseAdvisory(vulnDrupal);
        ComposerAdvisoryParser.parseAdvisory(vulnGHSA);
        ComposerAdvisoryParser.parseAdvisory(vulnFriendsNoCve);
        ComposerAdvisoryParser.parseAdvisory(vulnInvalidDateTime);
    }

}
