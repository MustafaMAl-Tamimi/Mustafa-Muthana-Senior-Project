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
if not virusTotalKey:
    print("API KEY NOT FOUND!!")
    exit()
headers = {
    "x-apikey": virusTotalKey
     }



##~Open Email File and Parse its Contents~##
emailFileInput = input("ENTER THE NAME OF THE FILE YOU WANT TO ANALYZE: ")
try:
    emailFile = open(emailFileInput, "rb")
except FileNotFoundError:
    print("FILE NOT FOUND!!")
    exit()
emailData = emailFile.read()

emailContent = BytesParser(policy=policy.default).parsebytes(emailData)


print("##~~~~++++~~~~++++~~~~++++~~~~++++~~~~##")
print("*********SOC~PHISHING~ANALYSIS**********")
print("##~~~~++++~~~~++++~~~~++++~~~~++++~~~~##")
print("\n")


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
print("\n")

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
print("\n")
##~Check Dkim, SPF, and Dmarc Results~##
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print("02--EMAIL~AUTHENTICATION::~~~~~~~~~~~~~~")
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print("\n")

authResults = emailContent.get("Authentication-Results")
if authResults:
    authResults = authResults.lower()
print("**********************************")
if authResults and "spf=fail" in authResults:
    print("!!~~~~~~~~SPF FAILED!!~~~~~~~~~~~~")

elif authResults and "spf=pass" in authResults:
    print("!!~~~~~~~~SPF PASSED!!~~~~~~~~~~~~")
else: 
    print("NO AUTHENTICATION RESULTS!")
print("**********************************")
if authResults and "dkim=fail" in authResults:
    print("!!~~~~~~~~DKIM FAILED!!~~~~~~~~~~~")

elif authResults and "dkim=pass" in authResults:
    print("!!........DKIM PASSED...........!!")
else: 
    print("NO AUTHENTICATION RESULTS!")
print("**********************************")
if authResults and "dmarc=fail" in authResults:
    print("!!~~~~~~~~DMARC FAILED!!~~~~~~~~~~")

elif authResults and "dmarc=pass" in authResults:
    print("!!........DMARC PASSED..........!!")
else:
    print("NO AUTHENTICATION RESULTS!")
print("**********************************")
print("\n")

print("++++++++++++++++++++++++++++++++++++++++")
print("03--URL~ANALYSIS::----------------------")
print("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_")
print("\n")



##~Get Email Body Content and Look for URLs~##
emailAsString = emailContent.get_body(preferencelist=("plain",))
if emailAsString:
    emailAsString = emailAsString.get_content()
else:
    emailAsString = ""

results = re.findall(r"https?://[^\s<>\"']+", emailAsString) #Matches Url Pattern
if not results:
    print("----------------------------------")
    print("         (NO_URLS_FOUND)          ")
    print("__________________________________")
    print("\n")

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
    domain = urlparse(url).hostname or ""
    #print("Domain: " + domain)
    for keyword in keywords:
        if keyword in url.lower():
            keyWordsInUrl.append(keyword)

            
    print("Key-Words Found in URL:: " + str(keyWordsInUrl))
    print("----------------------------------")

    
    result = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
    if result:
        print("WARNING!! DOMAIN RETURNS IP ADDRESS: " + result.group())
        print("----------------------------------")

    virusTotalUrlInit = "https://www.virustotal.com/api/v3/urls"

    urlData = {
    "url": url #Header Initialization
    }

    ##~A Bit Messy Process for Extracting the Final URL and Feeding Into Virus Total~##
    virusTotalUrlRequest = requests.post(virusTotalUrlInit, headers=headers, data=urlData)
    #print("Status Code:", virusTotalUrlRequest.status_code)
    #print("Response:", virusTotalUrlRequest.text)

    viurusTotalUrlData = virusTotalUrlRequest.json()
    if virusTotalUrlRequest.status_code in (200, 201):
        virusTotalUrlId = viurusTotalUrlData["data"]["id"]
    else:
        continue    
    virusTotalUrlFin = "https://www.virustotal.com/api/v3/analyses/" + virusTotalUrlId
    virusTotalUrlResponse = requests.get(virusTotalUrlFin, headers=headers)
    if virusTotalUrlResponse.status_code == 200:
        virusTotalUrlStatsInit = virusTotalUrlResponse.json()
        virusTotalUrlStats = virusTotalUrlStatsInit["data"]["attributes"]["stats"]
        print("Url Scan Stats: " + str(virusTotalUrlStats))
        print("\n")
    


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
    print("\n")

for attachment in emailContent.iter_attachments():
    print("Field        | Value              ")
    print("----------------------------------")
    print("FILE NAME    | " + str(attachment.get_filename()))
    print("----------------------------------")
    print("CONTENT TYPE | " + attachment.get_content_type())
    print("----------------------------------")
    attachmentB4Hash = attachment.get_payload(decode=True)
    if attachmentB4Hash is not None:

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
            print("STATUS       | Unexpected response: " + str(virusTotalRequest.status_code))

##~~AI GENERATED LIST OF PHRASES THAT COULD INDICATE PHISHING ~~##

phishingKeyWords = [ "urgent", "urgently", "immediate action required", "action required",
    "act now", "respond immediately", "within 24 hours", "within 48 hours",
    "limited time", "time sensitive", "final warning", "final notice",
    "last chance", "do not delay", "as soon as possible", "failure to respond",
    "deadline approaching", "your account will be closed", "your account will be suspended",
    "avoid suspension", "avoid interruption", "immediate attention",
    "verify your account", "verify your identity", "confirm your identity",
    "account verification", "security verification", "security alert",
    "unusual activity", "suspicious activity", "unauthorized access",
    "account compromised", "account has been compromised", "account temporarily locked",
    "account suspended", "account restricted", "account disabled", "account on hold",
    "confirm your account", "validate your account", "update your account information",
    "restore account access", "secure your account", "unusual sign-in attempt",
    "new login detected", "password expired", "reset your password",
    "confirm your password", "click here to login", "sign in to continue",
    "login required", "re-enter your password", "enter your password",
    "update your credentials", "verify your credentials", "validate your credentials",
    "confirm your login", "authentication required", "reauthenticate",
    "session expired", "your session has expired", "access your account",
    "unlock your account", "restore your password", "password confirmation required",
    "credential verification", "payment failed", "payment declined", "payment overdue",
    "outstanding balance", "unusual transaction", "unauthorized transaction",
    "refund pending", "refund approved", "claim your refund", "invoice attached",
    "overdue invoice", "payment required", "billing information",
    "update payment method", "verify your payment", "bank account suspended",
    "wire transfer", "banking details", "transaction on hold",
    "confirm this transaction", "payment confirmation required",
    "you have won", "you are a winner", "claim your prize", "claim your reward",
    "congratulations", "free gift", "exclusive offer", "you have been selected",
    "you are eligible", "claim your bonus", "limited offer", "free voucher",
    "gift card", "cash reward", "special reward", "unclaimed prize",
    "lottery winner", "you won a giveaway", "redeem your reward",
    "please review the attachment", "see attached document",
    "document requires your attention", "shared a document with you",
    "view the document", "download the attachment", "open the attached file",
    "payment receipt attached", "confidential document", "secure document",
    "purchase order attached", "updated document", "review and sign",
    "electronic signature required", "document awaiting approval",
    "on behalf of", "IT department", "technical support", "system administrator",
    "Microsoft support", "Google security", "Apple support",
    "bank security department", "account management team", "human resources",
    "CEO request", "management request", "official notification",
    "security department", "your service provider", "customer support team",
    "verify with our department", "permanently suspended", "permanently deleted",
    "account termination", "legal action", "account will be terminated",
    "access will be revoked", "service interruption", "service will be discontinued",
    "your account will expire", "data will be deleted", "failure to comply",
    "security breach", "unauthorized activity detected", "your account is at risk",
    "immediate suspension", "final security warning", "send your password",
    "provide your password", "confirm your personal information",
    "verify your personal details", "submit your banking information",
    "provide your bank details", "enter your credit card",
    "confirm your credit card", "social security number",
    "personal identification number", "one-time password", "verification code",
    "send us the code", "share your security code", "provide your login details",
    "identity verification required", "click here", "click the link below",
    "follow this link", "visit the link below", "open this link",
    "download now", "view now", "verify now", "confirm now", "update now",
    "continue here", "access the portal", "complete the form", "take action",
    "review immediately", "do not ignore this email", "please respond",
    "kindly confirm", "kindly verify", "kindly update"]

print("==x====x====x=====x======x======x====x==")
print("05--EMAIL-BODY-ANALYSIS::---------------")
print("========================================")
print("\n")
print("+ ++++ +++ ++++ +++ ++++ +++ ++++ +++ ++")
emailPhrasesFound = []
emailString = emailContent.get_body(preferencelist=("plain",))
if emailString:
    emailString = emailString.get_content()
    emailString = emailString.lower()
    for phrase in phishingKeyWords:
        if phrase in emailString:
            emailPhrasesFound.append(phrase)

if emailPhrasesFound:

    print("::(SUSPICIOUS_EMAIL_PHRASES_FOUND)::\n" + str(emailPhrasesFound))
else: 
    print("(NO__SUSPICIOUS_EMAIL_PHRASES_FOUND)")
print("**************************************************************************************************************************************************************************************************************************************")
