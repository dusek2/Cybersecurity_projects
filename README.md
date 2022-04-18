# Project 7 - WordPress Pentesting

Time spent: 6 hours spent in total

> Objective: Find, analyze, recreate, and document **five vulnerabilities** affecting an old version of WordPress

## Pentesting Report

### Setting up pentesting enviroment 

 - using
     - Docker
     - WordPress

<img src="1_wpscan.gif" alt="WP Scan on localhost">

### 1. Arbitrary File Upload
  - [ ] Summary: 
    - Vulnerability types: File upload
    - Tested in version: 3.1.3
    - Fixed in version: 3.1.4
  - [ ] Steps to recreate: Adding Reflex Gallery and running exploit with Metasploit
  - [ ] Affected source code:
    - [Link 1](https://wpscan.com/vulnerability/7867)
### 2. SQL Injection via WP_Query
  - [ ] Summary: 
    - Vulnerability types: SQLI
    - Tested in version: 4.1.0
    - Fixed in version: 4.1.34
  - [ ] Steps to recreate: Using sqlmap to find and exploiting SQLI
  - [ ] Affected source code:
    - [Link 1](https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317)
### 3. XSS via Post Slugs
  - [ ] Summary: 
    - Vulnerability types: XSS
    - Tested in version: 4.1.0
    - Fixed in version: 4.1.34
  - [ ] Steps to recreate: Affecting high privilege using low privilage accounts
  - [ ] Affected source code:
    - [Link 1](https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8)

## Assets

sqlmap
wpscan
kali
metasploit 

## Resources

- [WordPress Source Browser](https://core.trac.wordpress.org/browser/)
- [WordPress Developer Reference](https://developer.wordpress.org/reference/)
- [WP Scan]https://wpscan.com/

GIFs created with [ScreenToGif](https://www.screentogif.com/).

## Notes

This challenge brought great challange in terms of learning how to set up docker containters and learning how to find and exploit vulnerabilities 

