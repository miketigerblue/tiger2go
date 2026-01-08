# Feed validation report

Total feeds: 36  
OK: 20  
FAIL: 16

## Failures

### NCSC Threat Reports
- URL: `https://www.ncsc.gov.uk/api/1/services/v1/alerts-rss-feed.xml`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html`
- Snippet: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no"><meta name="theme-color" content="#051c48"><link rel="shortcut icon" href="/files/favicon.ico"><t…`

### ACSC Alerts
- URL: `https://www.cyber.gov.au/alerts/rss.xml`
- Kind: `Fetch`

### CCCS Cyber Alerts
- URL: `https://www.cyber.gc.ca/en/rss/advisories.xml`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html; charset=utf-8`
- Snippet: `<!DOCTYPE html><html class="no-js" lang="en" dir="ltr"><head>   <meta charset="utf-8">   <title>Canadian Centre for Cyber Security</title>   <base href="/">   <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale…`

### JPCERT Vulnerability Notes
- URL: `https://www.jpcert.or.jp/rss/jvn.rdf`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html`
- Snippet: `<!DOCTYPE html> <html lang="ja-jp"> <head> 	<meta charset="UTF-8"> 	<meta http-equiv="X-UA-Compatible" content="IE=edge"> 	 	<title>JPCERT コーディネーションセンター</title> 	<meta name="keywords" content="" /> 	<meta name="description" content=…`

### CERT-Bund advisories
- URL: `https://wid.cert-bund.de/feeds/rss/advisories`
- Kind: `UnexpectedHtml`
- HTTP status: `200`
- Content-Type: `text/html;charset=UTF-8`
- Snippet: `<!DOCTYPE html><html lang="de" data-beasties-container=""><head><base href="/portal/">     <meta charset="utf-8">     <title>Warn- und Informationsdienst</title>     <meta name="description" content="">     <meta name="viewport" content="wi…`

### RedHat Security Advisories
- URL: `https://access.redhat.com/security/updates/rss/`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html; charset=UTF-8`
- Snippet: `<!DOCTYPE html> <html dir="ltr" lang="en" data-ignored="not set" data-contentid-eddl="8743983"  data-page-category-eddl="servicetest" data-page-type-eddl="demo" data-page-sub-type-eddl="development" data-site-name-eddl="customerportal">   <…`

### VMware Security Advisories
- URL: `https://www.vmware.com/security/advisories.xml`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html; charset=utf-8`
- Snippet: `<!doctype html><html lang="en"><head><script nomodule>window.location.href = '/browser-not-supported';</script> <title>Page not found</title> <link rel="icon" type="image/png" href="/vm-favicon.png"> <link rel="icon" type="image/png" href="…`

### Apple Security Updates
- URL: `https://support.apple.com/en-gb/feeds/security-updates`
- Kind: `UnexpectedHtml`
- HTTP status: `200`
- Content-Type: `text/html; charset=UTF-8`
- Snippet: `<!DOCTYPE html> <html xmlns="http://www.w3.org/1999/xhtml" lang="en-GB" class="no-js"> <head>  	<meta http-equiv="X-UA-Compatible" content="IE=edge" /> <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" …`

### Cisco Talos Intelligence
- URL: `https://blog.talosintelligence.com/feeds/posts/default`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html; charset=utf-8`
- Snippet: `<!DOCTYPE html> <html class="no-js" lang="en">   <head>     <meta charset="UTF-8" />      <title>404 — Page not found</title>      <meta name="viewport" content="user-scalable=no, width=device-width, initial-scale=1, maximum-scale=1">     <…`

### Mandiant Threat Intelligence
- URL: `https://cloud.google.com/blog/topics/threat-intelligence/rss.xml`
- Kind: `UnexpectedHtml`
- HTTP status: `200`
- Content-Type: `text/html; charset=utf-8`
- Snippet: `<!doctype html><html lang="en-US" dir="ltr"><head><base href="https://cloud.google.com/blog/"><link rel="preconnect" href="//www.gstatic.com"><meta name="referrer" content="origin"><meta name="viewport" content="initial-scale=1, width=devic…`

### Microsoft Azure Security Blog
- URL: `https://techcommunity.microsoft.com/plugins/custom/microsoft/o365/custom-blog-rss?board=AzureSecurity`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html;charset=UTF-8`
- Snippet: `<!DOCTYPE html><html prefix="og: http://ogp.me/ns#" dir="ltr" lang="en" class="no-js"> 	<head> 	 	<title> 	Page not found - Microsoft Community Hub </title> 	 	 	<meta content="TECHCOMMUNITY.MICROSOFT.COM" property="og:site_name"/> 		<meta…`

### Google Cloud Security
- URL: `https://cloud.google.com/blog/topics/security/rss.xml`
- Kind: `UnexpectedHtml`
- HTTP status: `200`
- Content-Type: `text/html; charset=utf-8`
- Snippet: `<!doctype html><html lang="en-US" dir="ltr"><head><base href="https://cloud.google.com/blog/"><link rel="preconnect" href="//www.gstatic.com"><meta name="referrer" content="origin"><meta name="viewport" content="initial-scale=1, width=devic…`

### Abuse.ch URLhaus
- URL: `https://urlhaus.abuse.ch/downloads/rss/`
- Kind: `HttpStatus`
- HTTP status: `404`
- Content-Type: `text/html; charset=iso-8859-1`
- Snippet: `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"> <html><head> <title>404 Not Found</title> </head><body> <h1>Not Found</h1> <p>The requested URL was not found on this server.</p> <hr> <address>Apache Server at urlhaus.abuse.ch Port 443</a…`

### PhishTank Feed
- URL: `https://www.phishtank.com/phish_search.php?format=rss&active=y`
- Kind: `HttpStatus`
- HTTP status: `403`
- Content-Type: `text/html; charset=UTF-8`
- Snippet: `<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=Edge"><meta name="robots" content="noindex,nofollow"><m…`

### CERT-UA Advisories
- URL: `https://cert.gov.ua/rss`
- Kind: `UnexpectedHtml`
- HTTP status: `200`
- Content-Type: `text/html`
- Snippet: `<!doctype html> <html lang="uk" id="_html" #_html [id]="_html"> <head>   <meta charset="utf-8">   <title>CERT-UA</title>   <base href="/">   <meta name="viewport" content="width=device-width, initial-scale=1">    <meta data-vue-meta="true" …`

### OpenBugBounty Vulnerabilities
- URL: `https://www.openbugbounty.org/latest.atom`
- Kind: `HttpStatus`
- HTTP status: `403`
- Content-Type: `text/html; charset=UTF-8`
- Snippet: `<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=Edge"><meta name="robots" content="noindex,nofollow"><m…`
