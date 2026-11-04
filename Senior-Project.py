##~Imports~##

from email.parser import BytesParser
from email import policy
import re
from urllib.parse import urlparse
import hashlib
import os
import requests
print("**************************************************************************************************************************************************************************************************************************************")
print("\n\n")
##~Get Virus Total Api Key That is Stored on PC~##
virusTotalKey = os.getenv("virusTotalKey")
headers = {
    "x-apikey": virusTotalKey
     }


##~Open Email File and Parse its Contents~##
emailFile = open("xyz.eml", "rb")

emailData = emailFile.read()

emailContent = BytesParser(policy=policy.default).parsebytes(emailData)


print("##~~~~++++~~~~++++~~~~++++~~~~++++~~~~##")
print("*********SOC~PHISHING~ANALYSIS**********")
print("##~~~~++++~~~~++++~~~~++++~~~~++++~~~~##")
print("\n\n")


##~Initialize and Print Out Important Information~##
subject = emailContent.get("Subject")
sender = emailContent.get("From")
recepient = emailContent.get("To")
replyTo = emailContent.get("Reply-To")
returnPath = emailContent.get("Return-Path")
date = emailContent.get("Date")
cc = emailContent.get("Cc")
messageID = emailContent.get("Message-ID")
inReplyTo = emailContent.get("In-Reply-To")
contentType = emailContent.get("Content-Type")
received = emailContent.get_all("Received", [])

print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print("01--EMAIL~INFORMATION::~~~~~~~~~~~~~~~~~")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print("\n\n")

print("Field        | Value              ")
print("----------------------------------")
print("Subject      | " + str(subject))
print("----------------------------------")
print("Sender       | " + str(sender))
print("----------------------------------")
print("Recepient    | " + str(recepient))
print("----------------------------------")
print("Reply-To     | " + str(replyTo))
print("----------------------------------")
print("Return Path  | " + str(returnPath))
print("----------------------------------")
print("Date         | " + str(date))
print("----------------------------------")
print("CC           | " + str(cc))
print("----------------------------------")
print("messageID    | " + str(messageID))
print("----------------------------------")
print("In-Reply-To  | " + str(inReplyTo))
print("----------------------------------")
print("Content-Type | " + str(contentType))
print("----------------------------------")
print("Received     | " + str(received))
print("----------------------------------")
print("\n\n")
##~Check Dkim, SPF, and Dmarc Results~##
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print("02--EMAIL~AUTHENTICATION::~~~~~~~~~~~~~~")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print("\n\n")

authResults = emailContent.get("Authentication-Results")
if authResults:
    authResults = authResults.lower()
print("**********************************")
if authResults and "spf=fail" in authResults:
    print("!!~~~~~~~~SPF FAILED!!~~~~~~~~~~~~")
    indicators += 1
elif not authResults:
    print("NO AUTHENTICATION RESULTS!")
else: 
    print("!!~~~~~~~~SPF PASSED!!~~~~~~~~~~~~")
print("**********************************")
if authResults and "dkim=fail" in authResults:
    print("!!~~~~~~~~DKIM FAILED!!~~~~~~~~~~~")
    indicators += 1
elif not authResults:
    print("NO AUTHENTICATION RESULTS!")
else: 
    print("!!........DKIM PASSED...........!!")
print("**********************************")
if authResults and "dmarc=fail" in authResults:
    print("!!~~~~~~~~DMARC FAILED!!~~~~~~~~~~")
    indicators += 1
elif not authResults:
    print("NO AUTHENTICATION RESULTS!")
else:
    print("!!........DMARC PASSED..........!!")
print("**********************************")
print("\n\n")

print("++++++++++++++++++++++++++++++++++++++++")
print("03--URL~ANALYSIS::----------------------")
print("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_")
print("\n\n")



##~Get Email Body Content and Look for URLs~##
emailAsString = emailContent.get_body(preferencelist=("plain",))
emailAsString = emailAsString.get_content()


results = re.findall(r"https?://[^\s<>\"']+", emailAsString) #Matches Url Pattern
if not results:
    print("----------------------------------")
    print("         (NO_URLS_FOUND)          ")
    print("__________________________________")
    print("\n\n")
indicators = 0
threatLevel =""

##~Looks for Suspicious Keywords in URL~##
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

##~Prints URL/Domain/Suspicious-KeyWords/and Feeds URL into Virus Total~##
for url in results:
    keyWordsInUrl = []
    print("----------(!!URL-FOUND!!)---------")
    print(url)
    print("__________________________________")
    #print("URL: " + url)
    domain = urlparse(url).hostname
    #print("Domain: " + domain)
    for keyword in keywords:
        if keyword in url:
            keyWordsInUrl.append(keyword)
            indicators += 1
            
    print("Key-Words Found in URL:: " + str(keyWordsInUrl))
    print("----------------------------------")

    
    result = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
    if result:
        print("WARNING!! DOMAIN RETURNS IP ADDRESS: " + result.group())
        print("----------------------------------")
        indicators += 1
    virusTotalUrlInit = "https://www.virustotal.com/api/v3/urls"

    urlData = {
    "url": url #Header Initialization
    }

    ##~A Bit Messy Process for Extracting the Final URL and Feeding Into Virus Total~##
    virusTotalUrlRequest = requests.post(virusTotalUrlInit, headers=headers, data=urlData)
    #print("Status Code:", virusTotalUrlRequest.status_code)
    #print("Response:", virusTotalUrlRequest.text)

    viurusTotalUrlData = virusTotalUrlRequest.json()
    virusTotalUrlId = viurusTotalUrlData["data"]["id"]
    virusTotalUrlFin = "https://www.virustotal.com/api/v3/analyses/" + virusTotalUrlId
    virusTotalUrlResponse = requests.get(virusTotalUrlFin, headers=headers)
    virusTotalUrlStatsInit = virusTotalUrlResponse.json()
    virusTotalUrlStats = virusTotalUrlStatsInit["data"]["attributes"]["stats"]
    print("Url Scan Stats: " + str(virusTotalUrlStats))
    print("\n\n")
    
##~Indicator Threat Level Rating~##
if indicators <=  1:
    threatLevel = "Low"

elif indicators > 1 and indicators < 5:
    threatLevel = "Medium"

else: 
    threatLevel = "High"

#print("Total Indicators = " + str(indicators) + " ## Threat Level = " + threatLevel)


#print("Key Loaded Status: " + str(bool(virusTotalKey)))


print("==x====x====x=====x======x======x====x==")
print("04--ATTACHMENT~ANALYSIS::---------------")
print("========================================")
print("\n\n")

##~Looks for Email Attachments, Extracts Hash, Feeds Into Virus Total~##

attachment = list(emailContent.iter_attachments())

if not attachment:
    print("----------------------------------")
    print("     (NO_ATTACHMENTS_FOUND)       ")
    print("__________________________________")
    print("\n\n")

for attachment in emailContent.iter_attachments():
    print("Field        | Value              ")
    print("----------------------------------")
    print("FILE NAME    | " + attachment.get_filename())
    print("----------------------------------")
    print("CONTENT TYPE | " + attachment.get_content_type())
    print("----------------------------------")
    attachmentB4Hash = attachment.get_payload(decode=True)
    attachmentHash = hashlib.sha256(attachmentB4Hash)
    stringHash = attachmentHash.hexdigest()
    print("SHA256 HASH  | " + stringHash)
    virusTotalUrl = "https://www.virustotal.com/api/v3/files/" + stringHash
    virusTotalRequest = requests.get(virusTotalUrl, headers=headers)
    #print(virusTotalRequest.status_code)
    virusTotalData = virusTotalRequest.json()
    print("----------------------------------")

##~Checks for Error Messages, if Succesfull Initialize and Display Stats~##
    if virusTotalRequest.status_code == 200:
        print("STATUS       | File was found in VirusTotal!")
        virusTotalStats = virusTotalData["data"]["attributes"]["last_analysis_stats"]
        print("----------------------------------")
        print("STATS        | " + str(virusTotalStats))
    elif virusTotalRequest.status_code == 404:
        print("STATUS       | File was not found in VirusTotal!")
    elif virusTotalRequest.status_code == 401:
        print("STATUS       | Invalid or Missing API Key!")
    else:
        print("STATUS       | Unexpected response: " + virusTotalRequest.status_code)

print("**************************************************************************************************************************************************************************************************************************************")
