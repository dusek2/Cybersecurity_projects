<h1>
Docker set up
  
- containers composed
  
- wp scan results: 

</h1>

```
PS C:\Windows\System32> docker ps -a
>>
CONTAINER ID   IMAGE             COMMAND                  CREATED      STATUS          PORTS                  NAMES
fcd2fff2a602   wordpress:4.1.0   "/entrypoint.sh apac…"   5 days ago   Up 34 minutes   0.0.0.0:8080->80/tcp   wpvskali-wordpress-1
c3d3c516d671   mysql:5.7         "docker-entrypoint.s…"   5 days ago   Up 34 minutes   3306/tcp, 33060/tcp    wpvskali-db-1
c788a1b4ed88   wpvskali_kali     "/bin/bash"              6 days ago   Up 34 minutes                          kaliCP
PS C:\Windows\System32> docker exec -it c788a1b4ed88 bash
┌──(root㉿docker-desktop)-[~]
└─# wpscan --url http://127.0.0.1:8080 --api-token ydQVHvt6AfhzKyW1xdKf5RBs6zzKntIubMreA6NTDfs
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://127.0.0.1:8080/ [127.0.0.1]
[+] Started: Sat Apr 16 00:52:59 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.10 (Debian) PHP/5.6.5
 |  - X-Powered-By: PHP/5.6.5
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://127.0.0.1:8080/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://127.0.0.1:8080/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://127.0.0.1:8080/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1 identified (Insecure, released on 2014-12-18).
 | Found By: Meta Generator (Passive Detection)
 |  - http://127.0.0.1:8080/, Match: 'WordPress 4.1'
 | Confirmed By: Atom Generator (Aggressive Detection)
 |  - http://127.0.0.1:8080/?feed=atom, <generator uri="http://wordpress.org/" version="4.1">WordPress</generator>
 |
 | [!] 92 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 4.1.1 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/604b553d-5492-4f8c-af7a-db7169780032
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3438
 |      - https://wordpress.org/news/2015/04/wordpress-4-1-2/
 |      - https://cedricvb.be/post/wordpress-stored-xss-vulnerability-4-1-2/
 |
 | [!] Title: WordPress 3.9-4.1.1 - Same-Origin Method Execution
 |     Fixed in: 4.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/8a34afeb-062c-4720-a516-5db11c23d587
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3439
 |      - https://wordpress.org/news/2015/04/wordpress-4-1-2/
 |      - http://zoczus.blogspot.fr/2015/04/plupload-same-origin-method-execution.html
 |
 | [!] Title: WordPress 4.1-4.2.1 - Unauthenticated Genericons Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/21169b6d-61dd-4abc-b77b-167ff5f122ac
 |      - https://codex.wordpress.org/Version_4.2.2
 |
 | [!] Title: WordPress 4.1 - 4.1.1 - Arbitrary File Upload
 |     Fixed in: 4.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/3768fb47-f39d-41f7-8c9a-7032760b788e
 |      - https://www.openwall.com/lists/oss-security/2015/06/10/11
 |      - https://core.trac.wordpress.org/changeset/32172
 |
 | [!] Title: WordPress <= 4.2.2 - Authenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.6
 |     References:
 |      - https://wpscan.com/vulnerability/0f027d7d-674b-4a63-9603-25ea68069c1d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5622
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5623
 |      - https://wordpress.org/news/2015/07/wordpress-4-2-3/
 |      - https://twitter.com/klikkioy/status/624264122570526720
 |      - https://klikki.fi/adv/wordpress3.html
 |
 | [!] Title: WordPress <= 4.2.3 - wp_untrash_post_comments SQL Injection
 |     Fixed in: 4.1.7
 |     References:
 |      - https://wpscan.com/vulnerability/b52728fa-c068-4098-b796-ce421f31bde5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2213
 |      - https://github.com/WordPress/WordPress/commit/70128fe7605cb963a46815cf91b0a5934f70eff5
 |
 | [!] Title: WordPress <= 4.2.3 - Timing Side Channel Attack
 |     Fixed in: 4.1.7
 |     References:
 |      - https://wpscan.com/vulnerability/3c4fe98d-04dd-4217-945d-11e06a173916
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5730
 |      - https://core.trac.wordpress.org/changeset/33536
 |
 | [!] Title: WordPress <= 4.2.3 - Widgets Title Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.7
 |     References:
 |      - https://wpscan.com/vulnerability/32787617-081f-4743-a9a7-5dd6642308b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5732
 |      - https://core.trac.wordpress.org/changeset/33529
 |
 | [!] Title: WordPress <= 4.2.3 - Nav Menu Title Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.7
 |     References:
 |      - https://wpscan.com/vulnerability/4df947ed-d886-4e99-bc8c-b5be1af9844f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5733
 |      - https://core.trac.wordpress.org/changeset/33541
 |
 | [!] Title: WordPress <= 4.2.3 - Legacy Theme Preview Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.7
 |     References:
 |      - https://wpscan.com/vulnerability/7d99fa14-0b94-4e9a-9fc0-d3f22648be4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5734
 |      - https://core.trac.wordpress.org/changeset/33549
 |      - https://blog.sucuri.net/2015/08/persistent-xss-vulnerability-in-wordpress-explained.html
 |
 | [!] Title: WordPress <= 4.3 - Authenticated Shortcode Tags Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.8
 |     References:
 |      - https://wpscan.com/vulnerability/5c59d5d8-e7aa-4252-b878-d7d3091eeb35
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5714
 |      - https://wordpress.org/news/2015/09/wordpress-4-3-1/
 |      - https://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
 |      - http://blog.knownsec.com/2015/09/wordpress-vulnerability-analysis-cve-2015-5714-cve-2015-5715/
 |
 | [!] Title: WordPress <= 4.3 - User List Table Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.8
 |     References:
 |      - https://wpscan.com/vulnerability/0e19f0d4-7d1d-4da8-8314-88df77ce1187
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7989
 |      - https://wordpress.org/news/2015/09/wordpress-4-3-1/
 |      - https://github.com/WordPress/WordPress/commit/f91a5fd10ea7245e5b41e288624819a37adf290a
 |
 | [!] Title: WordPress <= 4.3 - Publish Post & Mark as Sticky Permission Issue
 |     Fixed in: 4.1.8
 |     References:
 |      - https://wpscan.com/vulnerability/1764515d-2232-40a0-931d-0447ce47d045
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5715
 |      - https://wordpress.org/news/2015/09/wordpress-4-3-1/
 |      - https://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
 |      - http://blog.knownsec.com/2015/09/wordpress-vulnerability-analysis-cve-2015-5714-cve-2015-5715/
 |
 | [!] Title: WordPress  3.7-4.4 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.9
 |     References:
 |      - https://wpscan.com/vulnerability/09329e59-1871-4eb7-b6ea-fd187cd8db23
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1564
 |      - https://wordpress.org/news/2016/01/wordpress-4-4-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/7ab65139c6838910426567849c7abed723932b87
 |
 | [!] Title: WordPress 3.7-4.4.1 - Local URIs Server Side Request Forgery (SSRF)
 |     Fixed in: 4.1.10
 |     References:
 |      - https://wpscan.com/vulnerability/b19b6a22-3ebf-488d-b394-b578cd23c959
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2222
 |      - https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/36435
 |      - https://hackerone.com/reports/110801
 |
 | [!] Title: WordPress 3.7-4.4.1 - Open Redirect
 |     Fixed in: 4.1.10
 |     References:
 |      - https://wpscan.com/vulnerability/8fba3ea1-553c-4426-ad00-03cc258bff3f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2221
 |      - https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/36444
 |
 | [!] Title: WordPress <= 4.4.2 - SSRF Bypass using Octal & Hexedecimal IP addresses
 |     Fixed in: 4.5
 |     References:
 |      - https://wpscan.com/vulnerability/0810e7fe-7212-49ae-8dd1-75260130b7f5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4029
 |      - https://codex.wordpress.org/Version_4.5
 |      - https://github.com/WordPress/WordPress/commit/af9f0520875eda686fd13a427fd3914d7aded049
 |
 | [!] Title: WordPress <= 4.4.2 - Reflected XSS in Network Settings
 |     Fixed in: 4.5
 |     References:
 |      - https://wpscan.com/vulnerability/238b69c9-4d56-4820-b09f-e778f108faf7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6634
 |      - https://codex.wordpress.org/Version_4.5
 |      - https://github.com/WordPress/WordPress/commit/cb2b3ed3c7d68f6505bfb5c90257e6aaa3e5fcb9
 |
 | [!] Title: WordPress <= 4.4.2 - Script Compression Option CSRF
 |     Fixed in: 4.5
 |     References:
 |      - https://wpscan.com/vulnerability/c0775703-ed52-4b6b-b395-7bf440ee0d77
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6635
 |      - https://codex.wordpress.org/Version_4.5
 |
 | [!] Title: WordPress <= 4.5.1 - Pupload Same Origin Method Execution (SOME)
 |     Fixed in: 4.1.11
 |     References:
 |      - https://wpscan.com/vulnerability/a82a6c6f-1787-4adc-84dd-3151f1edfd06
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4566
 |      - https://wordpress.org/news/2016/05/wordpress-4-5-2/
 |      - https://github.com/WordPress/WordPress/commit/c33e975f46a18f5ad611cf7e7c24398948cecef8
 |      - https://gist.github.com/cure53/09a81530a44f6b8173f545accc9ed07e
 |
 | [!] Title: WordPress 3.6-4.5.2 - Authenticated Revision History Information Disclosure
 |     Fixed in: 4.1.12
 |     References:
 |      - https://wpscan.com/vulnerability/12a47b8e-83e8-47b1-9713-cdd690b069e5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5835
 |      - https://wordpress.org/news/2016/06/wordpress-4-5-3/
 |      - https://github.com/WordPress/WordPress/commit/a2904cc3092c391ac7027bc87f7806953d1a25a1
 |      - https://www.wordfence.com/blog/2016/06/wordpress-core-vulnerability-bypass-password-protected-posts/
 |
 | [!] Title: WordPress 2.6.0-4.5.2 - Unauthorized Category Removal from Post
 |     Fixed in: 4.1.12
 |     References:
 |      - https://wpscan.com/vulnerability/897d068a-d3c1-4193-bc55-f65225265967
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5837
 |      - https://wordpress.org/news/2016/06/wordpress-4-5-3/
 |      - https://github.com/WordPress/WordPress/commit/6d05c7521baa980c4efec411feca5e7fab6f307c
 |
 | [!] Title: WordPress 2.5-4.6 - Authenticated Stored Cross-Site Scripting via Image Filename
 |     Fixed in: 4.1.13
 |     References:
 |      - https://wpscan.com/vulnerability/e84eaf3f-677a-465a-8f96-ea4cf074c980
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7168
 |      - https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c9e60dab176635d4bfaaf431c0ea891e4726d6e0
 |      - https://sumofpwn.nl/advisory/2016/persistent_cross_site_scripting_vulnerability_in_wordpress_due_to_unsafe_processing_of_file_names.html
 |      - https://seclists.org/fulldisclosure/2016/Sep/6
 |
 | [!] Title: WordPress 2.8-4.6 - Path Traversal in Upgrade Package Uploader
 |     Fixed in: 4.1.13
 |     References:
 |      - https://wpscan.com/vulnerability/7dcebd34-1a38-4f61-a116-bf8bf977b169
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7169
 |      - https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/54720a14d85bc1197ded7cb09bd3ea790caa0b6e
 |
 | [!] Title: WordPress 2.9-4.7 - Authenticated Cross-Site scripting (XSS) in update-core.php
 |     Fixed in: 4.1.14
 |     References:
 |      - https://wpscan.com/vulnerability/8b098363-1efb-4831-9b53-bb5d9770e8b4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5488
 |      - https://github.com/WordPress/WordPress/blob/c9ea1de1441bb3bda133bf72d513ca9de66566c2/wp-admin/update-core.php
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 3.4-4.7 - Stored Cross-Site Scripting (XSS) via Theme Name fallback
 |     Fixed in: 4.1.14
 |     References:
 |      - https://wpscan.com/vulnerability/6737b4a2-080c-454a-a16e-7fc59824c659
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5490
 |      - https://www.mehmetince.net/low-severity-wordpress/
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/ce7fb2934dd111e6353784852de8aea2a938b359
 |
 | [!] Title: WordPress <= 4.7 - Post via Email Checks mail.example.com by Default
 |     Fixed in: 4.1.14
 |     References:
 |      - https://wpscan.com/vulnerability/0a666ddd-a13d-48c2-85c2-bfdc9cd2a5fb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5491
 |      - https://github.com/WordPress/WordPress/commit/061e8788814ac87706d8b95688df276fe3c8596a
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 2.8-4.7 - Accessibility Mode Cross-Site Request Forgery (CSRF)
 |     Fixed in: 4.1.14
 |     References:
 |      - https://wpscan.com/vulnerability/e080c934-6a98-4726-8e7a-43a718d05e79
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5492
 |      - https://github.com/WordPress/WordPress/commit/03e5c0314aeffe6b27f4b98fef842bf0fb00c733
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 3.0-4.7 - Cryptographically Weak Pseudo-Random Number Generator (PRNG)
 |     Fixed in: 4.1.14
 |     References:
 |      - https://wpscan.com/vulnerability/3e355742-6069-4d5d-9676-613df46e8c54
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5493
 |      - https://github.com/WordPress/WordPress/commit/cea9e2dc62abf777e06b12ec4ad9d1aaa49b29f4
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 3.5-4.7.1 - WP_Query SQL Injection
 |     Fixed in: 4.1.15
 |     References:
 |      - https://wpscan.com/vulnerability/481e3398-ed2e-460a-af67-ff58027901d1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5611
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/
 |      - https://github.com/WordPress/WordPress/commit/85384297a60900004e27e417eac56d24267054cb
 |
 | [!] Title: WordPress 3.6.0-4.7.2 - Authenticated Cross-Site Scripting (XSS) via Media File Metadata
 |     Fixed in: 4.1.16
 |     References:
 |      - https://wpscan.com/vulnerability/2c5632d8-4d40-4099-9e8f-23afde51b56e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6814
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/28f838ca3ee205b6f39cd2bf23eb4e5f52796bd7
 |      - https://sumofpwn.nl/advisory/2016/wordpress_audio_playlist_functionality_is_affected_by_cross_site_scripting.html
 |      - https://seclists.org/oss-sec/2017/q1/563
 |
 | [!] Title: WordPress 2.8.1-4.7.2 - Control Characters in Redirect URL Validation
 |     Fixed in: 4.1.16
 |     References:
 |      - https://wpscan.com/vulnerability/d40374cf-ee95-40b7-9dd5-dbb160b877b1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6815
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/288cd469396cfe7055972b457eb589cea51ce40e
 |
 | [!] Title: WordPress  4.0-4.7.2 - Authenticated Stored Cross-Site Scripting (XSS) in YouTube URL Embeds
 |     Fixed in: 4.1.16
 |     References:
 |      - https://wpscan.com/vulnerability/3ee54fc3-f4b4-4c35-8285-9d6719acecf0
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6817
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/419c8d97ce8df7d5004ee0b566bc5e095f0a6ca8
 |      - https://blog.sucuri.net/2017/03/stored-xss-in-wordpress-core.html
 |
 | [!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset
 |     References:
 |      - https://wpscan.com/vulnerability/b3f2f3db-75e4-4d48-ae5e-d4ff172bc093
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295
 |      - https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
 |      - https://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
 |      - https://core.trac.wordpress.org/ticket/25239
 |
 | [!] Title: WordPress 2.7.0-4.7.4 - Insufficient Redirect Validation
 |     Fixed in: 4.1.18
 |     References:
 |      - https://wpscan.com/vulnerability/e9e59e08-0586-4332-a394-efb648c7cd84
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9066
 |      - https://github.com/WordPress/WordPress/commit/76d77e927bb4d0f87c7262a50e28d84e01fd2b11
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |
 | [!] Title: WordPress 2.5.0-4.7.4 - Post Meta Data Values Improper Handling in XML-RPC
 |     Fixed in: 4.1.18
 |     References:
 |      - https://wpscan.com/vulnerability/973c55ed-e120-46a1-8dbb-538b54d03892
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9062
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/3d95e3ae816f4d7c638f40d3e936a4be19724381
 |
 | [!] Title: WordPress 3.4.0-4.7.4 - XML-RPC Post Meta Data Lack of Capability Checks
 |     Fixed in: 4.1.18
 |     References:
 |      - https://wpscan.com/vulnerability/a5a4f4ca-19e5-4665-b501-5c75e0f56001
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9065
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/e88a48a066ab2200ce3091b131d43e2fab2460a4
 |
 | [!] Title: WordPress 2.5.0-4.7.4 - Filesystem Credentials Dialog CSRF
 |     Fixed in: 4.1.18
 |     References:
 |      - https://wpscan.com/vulnerability/efe46d58-45e4-4cd6-94b3-1a639865ba5b
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9064
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/38347d7c580be4cdd8476e4bbc653d5c79ed9b67
 |      - https://sumofpwn.nl/advisory/2016/cross_site_request_forgery_in_wordpress_connection_information.html
 |
 | [!] Title: WordPress 3.3-4.7.4 - Large File Upload Error XSS
 |     Fixed in: 4.1.18
 |     References:
 |      - https://wpscan.com/vulnerability/78ae4791-2703-4fdd-89b2-76c674994acf
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9061
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/8c7ea71edbbffca5d9766b7bea7c7f3722ffafa6
 |      - https://hackerone.com/reports/203515
 |      - https://hackerone.com/reports/203515
 |
 | [!] Title: WordPress 3.4.0-4.7.4 - Customizer XSS & CSRF
 |     Fixed in: 4.1.18
 |     References:
 |      - https://wpscan.com/vulnerability/e9535a5c-c6dc-4742-be40-1b94a718d3f3
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9063
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/3d10fef22d788f29aed745b0f5ff6f6baea69af3
 |
 | [!] Title: WordPress 2.3.0-4.8.1 - $wpdb->prepare() potential SQL Injection
 |     Fixed in: 4.1.19
 |     References:
 |      - https://wpscan.com/vulnerability/9b3414c0-b33b-4c55-adff-718ff4c3195d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14723
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://github.com/WordPress/WordPress/commit/fc930d3daed1c3acef010d04acc2c5de93cd18ec
 |
 | [!] Title: WordPress 2.3.0-4.7.4 - Authenticated SQL injection
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpscan.com/vulnerability/95e87ae5-eb01-4e27-96d3-b1f013deff1c
 |      - https://medium.com/websec/wordpress-sqli-bbb2afcc8e94
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://wpvulndb.com/vulnerabilities/8905
 |
 | [!] Title: WordPress 2.9.2-4.8.1 - Open Redirect
 |     Fixed in: 4.1.19
 |     References:
 |      - https://wpscan.com/vulnerability/571beae9-d92d-4f9b-aa9f-7c94e33683a1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14725
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41398
 |
 | [!] Title: WordPress 3.0-4.8.1 - Path Traversal in Unzipping
 |     Fixed in: 4.1.19
 |     References:
 |      - https://wpscan.com/vulnerability/d74ee25a-d845-46b5-afa6-b0a917b7737a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14719
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41457
 |      - https://hackerone.com/reports/205481
 |
 | [!] Title: WordPress <= 4.8.2 - $wpdb->prepare() Weakness
 |     Fixed in: 4.1.20
 |     References:
 |      - https://wpscan.com/vulnerability/c161f0f0-6527-4ba4-a43d-36c644e250fc
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16510
 |      - https://wordpress.org/news/2017/10/wordpress-4-8-3-security-release/
 |      - https://github.com/WordPress/WordPress/commit/a2693fd8602e3263b5925b9d799ddd577202167d
 |      - https://twitter.com/ircmaxell/status/923662170092638208
 |      - https://blog.ircmaxell.com/2017/10/disclosure-wordpress-wpdb-sql-injection-technical.html
 |
 | [!] Title: WordPress 2.8.6-4.9 - Authenticated JavaScript File Upload
 |     Fixed in: 4.1.21
 |     References:
 |      - https://wpscan.com/vulnerability/0d2323bd-aecd-4d58-ba4b-597a43034f57
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17092
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/67d03a98c2cae5f41843c897f206adde299b0509
 |
 | [!] Title: WordPress 1.5.0-4.9 - RSS and Atom Feed Escaping
 |     Fixed in: 4.1.21
 |     References:
 |      - https://wpscan.com/vulnerability/1f71a775-e87e-47e9-9642-bf4bce99c332
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17094
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/f1de7e42df29395c3314bf85bff3d1f4f90541de
 |
 | [!] Title: WordPress 3.7-4.9 - 'newbloguser' Key Weak Hashing
 |     Fixed in: 4.1.21
 |     References:
 |      - https://wpscan.com/vulnerability/809f68d5-97aa-44e5-b181-cc7bdf5685c5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17091
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/eaf1cfdc1fe0bdffabd8d879c591b864d833326c
 |
 | [!] Title: WordPress 3.7-4.9.1 - MediaElement Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.22
 |     References:
 |      - https://wpscan.com/vulnerability/6ac45244-9f09-4e9c-92f3-f339d450fe72
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5776
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9263
 |      - https://github.com/WordPress/WordPress/commit/3fe9cb61ee71fcfadb5e002399296fcc1198d850
 |      - https://wordpress.org/news/2018/01/wordpress-4-9-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/42720
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.1.23
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.1.23
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.1.23
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.1.24
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.1.25
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 5.0.1
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.1.26
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.1.27
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.1.29
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.1.29
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20042
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.1.29
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.1.29
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.1.30
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.1.30
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.1.30
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.1.30
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.1.30
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress <= 5.2.3 - Hardening Bypass
 |     Fixed in: 4.1.28
 |     References:
 |      - https://wpscan.com/vulnerability/378d7df5-bce2-406a-86b2-ff79cd699920
 |      - https://blog.ripstech.com/2020/wordpress-hardening-bypass/
 |      - https://hackerone.com/reports/436928
 |      - https://wordpress.org/news/2019/11/wordpress-5-2-4-update/
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS via Media Files
 |     Fixed in: 4.1.31
 |     References:
 |      - https://wpscan.com/vulnerability/741d07d1-2476-430a-b82f-e1228a9343a4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4047
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27
 |
 | [!] Title: WordPress < 5.4.2 - Open Redirection
 |     Fixed in: 4.1.31
 |     References:
 |      - https://wpscan.com/vulnerability/12855f02-432e-4484-af09-7d0fbf596909
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4048
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload
 |     Fixed in: 4.1.31
 |     References:
 |      - https://wpscan.com/vulnerability/d8addb42-e70b-4439-b828-fd0697e5d9d4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4049
 |      - https://www.exploit-db.com/exploits/48770/
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p
 |      - https://hackerone.com/reports/406289
 |
 | [!] Title: WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation
 |     Fixed in: 4.1.31
 |     References:
 |      - https://wpscan.com/vulnerability/b6f69ff1-4c11-48d2-b512-c65168988c45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4050
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc
 |
 | [!] Title: WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments
 |     Fixed in: 4.1.31
 |     References:
 |      - https://wpscan.com/vulnerability/eea6dbf5-e298-44a7-9b0d-f078ad4741f9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25286
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 4.1.33
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress < 5.8 - Plugin Confusion
 |     Fixed in: 5.8
 |     References:
 |      - https://wpscan.com/vulnerability/95e01006-84e4-4e95-b5d7-68ea7b5aa1a8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44223
 |      - https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 4.1.34
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 4.1.34
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 4.1.34
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 4.1.34
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469
 |
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 4.1.35
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:18 <=========================================> (137 / 137) 100.00% Time: 00:00:18

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 1
 | Requests Remaining: 24

[+] Finished: Sat Apr 16 00:53:39 2022
[+] Requests Done: 183
[+] Cached Requests: 4
[+] Data Sent: 45.83 KB
[+] Data Received: 11.823 MB
[+] Memory used: 201.34 MB
[+] Elapsed time: 00:00:40


 ```
