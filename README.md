# osxlockdown
osxlockdown was built to audit, and remediate, security configuration settings on OS X 10.11 (El Capitan).  

This checks and flips various configuration settings. Many are simply stripping out features to reduce the attack surface.  You may not like this.  This is a compilation of numerous resources listed in the Resources section which could be converted to bash scripts.  This is different than those resources in that instead of requiring the user to read a 100+ page doc, click through numerous GUIs, and try to decide if some esoteric output is good or bad, this tool combines all the steps into a single command. This tool is focused on enterprise deployments of OSX with regard to what it does, but made to be usable for stand-alone home users as well.

*Warning*: Many of the rules disable functionality in the name of security.  This may make you sad.

*Warning*: System commands and dark arts are involved, so ensure you have your system backed up first.


Getting osxlockdown
-------
You can build osxlockdown with Go, by cloning this repo and running `go build osxlockdown`

You can download releases at https://github.com/SummitRoute/osxlockdown/releases
 

Usage
-----

Run `sudo ./osxlockdown` to check security settings. 
Run `sudo ./osxlockdown --remediate` to fix them.

The commands.json file may be edited to disable certain rules by setting `enabled` to `false`.

Available command-line options:

- `--remediate`: Apply fixes to the problems found. By default the tool only audits for problems.
- `--hide_summary`: Hides the summary output the end.
- `--hide_passes`: Only show issues that failed the audit.
- `--commands_file <filename>`: Change the location of the commands file instead of the default `commands.json` in the current directory.

Sample output
-------------
```
$ sudo ./osxlockdown
[PASSED] Verify all application software is current
[PASSED] Enable Auto Update
[PASSED] Disable Bluetooth
[PASSED] Disable infrared receiver
[PASSED] Disable AirDrop
[PASSED] Set time and date automatically
[PASSED] Set an inactivity interval of 10 minutes or less for the screen saver
[PASSED] Enable secure screen saver corners
[PASSED] Require a password to wake the computer from sleep or screen saver
[PASSED] Ensure screen locks immediately when requested
[PASSED] Disable Remote Apple Events
[PASSED] Disable Remote Login
[PASSED] Disable Internet Sharing
[PASSED] Disable Screen Sharing
[PASSED] Disable Printer Sharing
[PASSED] Disable Wake on Network Access
[PASSED] Disable File Sharing
[PASSED] Disable Remote Management
[PASSED] Enable FileVault
[PASSED] Destroy File Vault Key when going to standby
[PASSED] Enable hibernation mode (no memory power on sleep)
[PASSED] Enable Gatekeeper
[PASSED] Enable Firewall
[PASSED] Enable Firewall Stealth Mode
[PASSED] Disable signed apps from being auto-permitted to listen through firewall
[PASSED] Disable iCloud drive
[PASSED] Require an administrator password to access system-wide preferences
[PASSED] Disable IPv6
[PASSED] Disable Previews
[PASSED] Secure Safari by crippling it
-------------------------------------------------------------------------------
osxlockdown 0.9
Date: 2016-01-02T13:01:11-08:00
SerialNumber: C02XXXXXXXXX
HardwareUUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
Final Score 100%: Pass rate: 30/30
```

Resources
=========
This project pulled from numerous resources including:

- https://github.com/drduh/OS-X-Security-and-Privacy-Guide
- DISA's STIG for Apple OSX 10.10: http://iase.disa.mil/stigs/os/mac/Pages/index.aspx (they need to do some serious rework on that)
- https://github.com/jackiesingh/Mac-OSX-STIG
- The IRS Safeguard Computer Security Evaluation Matrix (SCSEM) [safeguards-scsem_MacOSX10.8.xlsx](https://www.irs.gov/pub/irs-utl/safeguards-scsem_MacOSX10.8.xlsx)
- [CIS Apple OSX 10.10 Benchmark](https://benchmarks.cisecurity.org/tools2/osx/CIS_Apple_OSX_10.10_Benchmark_v1.0.0.pdf)
- Articles from https://derflounder.wordpress.com/
- Apple's [Mac OS X Security Configuration For Mac OS X Version 10.6 Snow Leopard](https://www.apple.com/support/security/guides/docs/SnowLeopard_Security_Config_v10.6.pdf)


Limitations
===========

- Some attempts have been made to check for things that a user likely would never enable anyway, but if they did would make the system insecure.  However, it is impossible to check all such possibilities, and this is in general not my goal.
- Some security auditing requires manual review, such as what apps should have firewall exceptions, or permissions on files and folders.  For such auditing, no rules have been created.
- File Vault (full disk encryption) is tested for, but can not be remediated because user involvement is required to write down the recovery key.
- Rules related to creating audit logs have not been created.


FAQ
===

- *Why isn't this just a bash script, or python code? Why would anyone write a Go wrapper around bash scripts within a json file? Why isn't this an ansible|puppet script?*
    - This seemed like the cleanest solution for my needs.
- *I locked myself out. What now?*
    - An earlier release of osxlockdown set a flag to lock users out if they entered an incorrect password more than 5 times on login. This is not good for single-user systems and I have since removed the password related policy rule.  To remove all password related policies you can run `pwpolicy clearaccountpolicies`.  To gain access again, follow the instructions here: https://support.apple.com/en-us/HT203114 
- *Why are you disabling X?*
    - osxlockdown minimizes the features of the OS as much as possible, with the expectation that this will reduce it's attack's surface.  If it's not needed, throw it out.  Some people will not like some of the features I disable.
    
FAQ for specific features
-------------------------
- *Why are you disabling IPv6?*
    - The NSA, DISA, and Apple themselves all recommend disabling IPv6 for maximum security.  In Apple's security guide, they state "If your organization’s network cannot use or does not require IPv6, turn it off."  Apple and the NSA's guidance are for 10.6 (from 2009) so perhaps this was fear at the time that it was too new.  However, again, my goal is to reduce the attack surface. 
 - *Why are you crippling Safari?*
    - I personally run Chrome and I cripple it in the same way I am crippling Safari here.  I do believe Chrome is more secure though.  One reason is they build most of the main components Safari is made from anyway, so they have more expertise with it.  Another reason is they have discovered more security problems than Safari's team has, for example, they [detected](https://googleonlinesecurity.blogspot.com/2011/08/update-on-attempted-man-in-middle.html) Diginotar had been compromised and had issued a certificate to MiTM users.
 