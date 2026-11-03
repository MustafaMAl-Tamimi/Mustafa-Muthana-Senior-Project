from email.parser import BytesParser
from email import policy
import re
from urllib.parse import urlparse

emailFile = open("xyz.eml", "rb")

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
authResults = authResults.lower()

if "spf=fail" in authResults:
    print("!!SPF FAILED!!")
else: print("..SPF PASSED..")

if "dkim=fail" in authResults:
    print("!!DKIM FAILED!!")
else: print("..DKIM PASSED..")

if "dmarc=fail" in authResults:
    print("!!DMARC FAILED!!")
else: print("..DMARC PASSED..")


emailAsString = emailContent.get_body(preferencelist=("plain",))
emailAsString = emailAsString.get_content()

results = re.findall(r"https?://[^\s<>\"']+", emailAsString)

for url in results:
    print("URL: " + url)
    domain = urlparse(url).hostname
    print("Domain: " + domain)
    
    result = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        print("WARNING!! DOMAIN RETURNS IP ADDRESS: " + result.group())


