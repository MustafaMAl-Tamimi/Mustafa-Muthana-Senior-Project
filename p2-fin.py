import re 
import os #Dependencies Needed

maxFailedLogin = 5 #Maximum Number of Logons

#Read File Function
def readLog(file):
    if not os.path.isfile(file): #Checks if File Exists
        print("File does not exist!")
        return [] #Returns Empty List

    logFile = open(file , "r", encoding="utf-8", errors = "replace") #Open File
    
    logFileLines = logFile.readlines() #Log File Lines as a List
    logFile.close() #No Longer Needed
    return logFileLines


def logAnalyzer(logFileLines):
    failedLogins = {} #Dictionary Holding IP and Number of Attempts
    successfulLogins = [] #Users Succesfully Logged in and IP
    failedTotal = 0  #init
    successfulTotal = 0 

    #Look for Patterns Using Re.. ?: Means Not to Put in Group, ? Means Not Necessary, \S+ Captures String
    #[0-9a-fA-   F:.]+ to Create an IPV4 or IPV6 Address 
    failedExtract = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)")
    successfulExtract = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+)")

    for line in logFileLines: #Itterates Through Log File
        failedExtractMatch = failedExtract.search(line)
        if failedExtractMatch: #Check if Exists
            username = failedExtractMatch.group(1) #Extacts Username and IP
            ipAddress = failedExtractMatch.group(2)
            failedTotal = failedTotal + 1 #Increments Failed Total
            
            if ipAddress in failedLogins:
                failedLogins[ipAddress] = failedLogins[ipAddress] + 1 #Increments Per IP Address
            else:
                failedLogins[ipAddress] = 1 #Init to 1

        successfulExtractMatch = successfulExtract.search(line)
        if successfulExtractMatch:
            username = successfulExtractMatch.group(1)
            ipAddress = successfulExtractMatch.group(2)
            login = {
            "username" : username, "ipAddress" : ipAddress #Create Dictionary Object
             }
            successfulLogins.append(login) #Append Dictionary to List
            successfulTotal = successfulTotal + 1
    return failedLogins, successfulLogins, failedTotal, successfulTotal

def bruteForceDetection(failedLogins):
    alerts = []
    
    print("=" * 32)
    print("LOG ANALYSIS REPORT")    #Display
    print("=" * 32)
    print()
    for ipAddress in failedLogins:
        numberOfAttempts = failedLogins[ipAddress]
        if numberOfAttempts >= maxFailedLogin: #Check Which IP Exceeds 5
            alert = {"ip" : ipAddress, "attempts" : numberOfAttempts, "severity" : "High"}
            alerts.append(alert) #Create Dictionary Object Append to Alerts List
    return alerts

def displayAlerts(alerts, failedLogins, successfulLogins, failedTotal, successfulTotal):
    #Print Functions for Dashboard
    print("Total Failed Logins: " +str(failedTotal))
    print("Total Successful Logins: " +str(successfulTotal))
    print("Total Unique IPs With Failed Logins: " + str(len(failedLogins)))
    print("Limit for Failed Logins: " + str(maxFailedLogin) + " attempts")
    print()    
    print("--- Brute-Force Alerts ---") #Print Brute Force Attempts
    if len(alerts) == 0:
        print("No Brute Force Attack")
    else:
        for alert in alerts:
            print("Severity: " + alert["severity"] + " | IP Address: " + alert["ip"] + " | Number of Attempts " +           str(alert["attempts"]))
    print()
    print("--- Failed Logins By IP ---") #Print Failed Logon IP
    if len(failedLogins) == 0:
        print("No Failed Logins")
    else:
        for ipAddress in failedLogins:
            print(ipAddress + " : " + str(failedLogins[ipAddress]))

    print()
    print("--- Successful Logins ---") #Print Successful Logon
    if len(successfulLogins) == 0:
        print("No Successful Logins")
    else:
        for login in successfulLogins:
            print(login["username"] + " from " + login["ipAddress"])
    
    print()
    print("--- Possible Comprimise ---") #Print Indicator of Compromise

    susCount = 0
    for login in successfulLogins:
        for alert in alerts:
            if login["ipAddress"] == alert["ip"]:
                print("Possible Comprimise!! " + login["username"] + " : " + login["ipAddress"])
                susCount = susCount + 1
        if susCount == 0:
            print("No Possible Comprimise..")
        print()



logFileLines = readLog("/var/log/auth.log") 

failedLogins, successfulLogins, failedTotal, successfulTotal = logAnalyzer(logFileLines)

alerts = bruteForceDetection(failedLogins)

displayAlerts(alerts, failedLogins, successfulLogins, failedTotal, successfulTotal)


