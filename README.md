# osxlockdown
osxlockdown was built to audit, and remediate, security configuration settings on OS X 10.11 (El Capitan).  

This checks and flips various configuration settings. Many are simply stripping out features to reduce the attack surface.  You may not like this.  This is a compilation of numerous resources listed in the Resources section which could be converted to bash scripts.  This is different than those resources in that instead of requiring the user to read a 100+ page doc, click through numerous GUIs, and try to decide if some esoteric output is good or bad, this tool combines all the steps into a single command. This tool is focused on enterprise deployments of OSX with regard to what it does, but made to be usable for stand-alone home users as well.

Running the command by itself will tell you which audit checks passed and failed.  Adding the `--remediate` flag will fix the problems identified.  The commands.json file may be edited to disable certain rules by setting `enabled` to `false`.

*Warning*: Many of the rules disable functionality in the name of security.  This may make you sad.

*Warning*: System commands and dark arts are involved, so ensure you have your system backed up first.
 

Usage
-----

Run `sudo ./osxlockdown` to check security settings. 
Run `sudo ./osxlockdown --remediate` to fix them.

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
[PASSED] Enable "Set time and date automatically"
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
[PASSED] Enable Gatekeeper
[PASSED] Enable Firewall
[PASSED] Enable Firewall Stealth Mode
[PASSED] Disable signed apps from being auto-permitted to listen through firewall
[PASSED] Disable iCloud drive
[PASSED] Require an administrator password to access system-wide preferences
[PASSED] Complex passwords required
[PASSED] Disable IPv6
[PASSED] Disable Previews
[PASSED] Secure Safari by crippling it
-------------------------------------------------------------------------------
Date: 2015-12-29T13:00:18-08:00
SerialNumber: C02XXXXXXXXX
HardwareUUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
Final Score 100%: Pass rate: 29/29
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
- *Why are you disabling X?*
    - osxlockdown minimizes the features of the OS as much as possible, with the expectation that this will reduce it's attack's surface.  If it's not needed, throw it out.  Some people will not like some of the features I disable.
- *Why are you disabling IPv6?*
    - The NSA, DISA, and Apple themselves all recommend disabling IPv6 for maximum security.  In Apple's security guide, they state "If your organization’s network cannot use or does not require IPv6, turn it off."  Apple and the NSA's guidance are for 10.6 (from 2009) so perhaps this was fear at the time that it was too new.  However, again, my goal is to reduce the attack surface. 
 