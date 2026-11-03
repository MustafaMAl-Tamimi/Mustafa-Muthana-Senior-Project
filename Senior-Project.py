from email.parser import BytesParser
from email import policy
import re
from urllib.parse import urlparse
import hashlib
import os
import requests

emailFile = open("virus.eml", "rb")

emailData = emailFile.read()

emailContent = BytesParser(policy=policy.default).parsebytes(emailData)

subject = emailContent.get("Subject")
sender = emailContent.get("From")
recepient = emailContent.get("To")
replyTo = emailContent.get("Reply-To")
returnPath = emailContent.get("Return-Path")
date = emailContent.get("Date")


print("Subject = " + str(subject))
print("Sender = " + str(sender))
print("Recepient = " + str(recepient))
print("Reply-To= " + str(replyTo))
print("Return Path = " + str(returnPath))
print("Date = " + str(date))


authResults = emailContent.get("Authentication-Results")
if authResults:
    authResults = authResults.lower()

if authResults and "spf=fail" in authResults:
    print("!!SPF FAILED!!")
    indicators += 1
elif not authResults:
    print("NO AUTHENTICATION RESULTS!")
else: 
    print("..SPF PASSED..")

if authResults and "dkim=fail" in authResults:
    print("!!DKIM FAILED!!")
    indicators += 1
elif not authResults:
    print("NO AUTHENTICATION RESULTS!")
else: 
    print("..DKIM PASSED..")

if authResults and "dmarc=fail" in authResults:
    print("!!DMARC FAILED!!")
    indicators += 1
elif not authResults:
    print("NO AUTHENTICATION RESULTS!")
else:
    print("..DMARC PASSED..")


emailAsString = emailContent.get_body(preferencelist=("plain",))
emailAsString = emailAsString.get_content()

results = re.findall(r"https?://[^\s<>\"']+", emailAsString)

indicators = 0
threatLevel =""

keywords = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "secure", "security", "update", "password", "reset",
    "confirm", "confirmation", "authenticate", "authentication",
    "authorize", "authorization", "payment", "billing", "invoice",
    "banking", "bank", "wallet", "transaction", "refund", "suspend",
    "suspended", "locked", "unlock", "limited", "alert", "warning",
    "support", "helpdesk", "customer", "webmail", "mail", "email",
    "office365", "microsoft", "outlook", "paypal", "appleid", "amazon",
    "google", "facebook", "instagram", "dropbox", "onedrive",
    "sharepoint", "password-reset", "credential", "credentials",
    "recovery", "access", "document", "attachment", "download",
    "gift", "prize", "winner", "claim", "urgent", "immediately",
    "expire", "expired"
]

for url in results:
    print("URL: " + url)
    domain = urlparse(url).hostname
    print("Domain: " + domain)
    for keyword in keywords:
        if keyword in url:
            indicators += 1
            print("Keyword " + keyword + " found in URL")

    
    result = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
    if result:
        print("WARNING!! DOMAIN RETURNS IP ADDRESS: " + result.group())
        indicators += 1


if indicators <=  1:
    threatLevel = "Low"

elif indicators > 1 and indicators < 5:
    threatLevel = "Medium"

else: 
    threatLevel = "High"

print("Total Indicators = " + str(indicators) + " ## Threat Level = " + threatLevel)

virusTotalKey = os.getenv("virusTotalKey")
print("Key Loaded Status: " + str(bool(virusTotalKey)))


headers = {
    "x-apikey": virusTotalKey
}

for attachment in emailContent.iter_attachments():
    print("File Name: " + attachment.get_filename())
    print("Content Type: " + attachment.get_content_type())
    attachmentB4Hash = attachment.get_payload(decode=True)
    attachmentHash = hashlib.sha256(attachmentB4Hash)
    stringHash = attachmentHash.hexdigest()
    print("SHA256 HASH: " + stringHash)
    virusTotalUrl = "https://www.virustotal.com/api/v3/files/" + stringHash
    virusTotalRequest = requests.get(virusTotalUrl, headers=headers)
    print(virusTotalRequest.status_code)
    virusTotalData = virusTotalRequest.json()
    virusTotalStats = virusTotalData["data"]["attributes"]["last_analysis_stats"]


    if virusTotalRequest.status_code == 200:
        print("File was found in VirusTotal!")
        print(virusTotalStats)
    elif virusTotalRequest.status_code == 404:
        print("File was not found in VirusTotal!")
    else:
        print("Unexpected response:", virusTotalRequest.status_code)


