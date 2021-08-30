/*
command args
1 - required    - scan_type         = policy|sandobx
2 - required    - porfile_name      = PROFILE_NAME
3 - optional    - app_guid          = EMPTY|APP_GUID
4 - optional    - scan_guid         = EMPTY|SCAN_GUID
5 - optional    - sandbox_name      = SANDBOX_NAME
6 - optional    - sandbox_guid      = SANDBOX_GUID
7 - required    - gitlab_token      = GITLAB PRIVATE TOKEN
8 - required    - create_issue      = true|false
9 - required    - gitlab_project    = GITLAB PROJECT IP 
*/

const fs = require('fs');
const Axios = require('axios');
const Math = require('mathjs');
const auth = require("./auth");
const GitlabOutputFileName = 'output-sast-vulnerabilites.json';
const java_SRC_ROOT = process.env.SRC_ROOT;
const java_JSP_ROOT = process.env.JSP_ROOT;

var workingArgs=[];
var flawsReport=[];



var myArgs = process.argv.slice(2);
console.log('Command Options:')
console.log(myArgs)
var myArgsLength=myArgs.length
var i=0;

while ( i < myArgsLength){
    mySplit = myArgs[i].split('=')
    workingArgs[mySplit[0]] = mySplit[1]
    i++;
}


const VeracodeSASTResultsImport = async (outputFileName) => {
    //find results to import

    //find and set app guid
    if (workingArgs['app_guid']){
        app_guid = workingArgs['app_guid']
    }
    else {
        //find the app guid
        console.log('No APP GUID provided, fnding APP GUID for App Name: '+workingArgs['profile_name'])
        appname = workingArgs['profile_name']
        app_guid = await getAppGUIDbyName(appname)
        console.log('APP GUID found: '+app_guid)
    } 

    //find and set sandbox guid if sandboxscan
    if (workingArgs['scan_type'] == 'sandbox'){
        if (workingArgs['sandbox_guid']){
            sandbox_guid = workingArgs['sandbox_guid']
        }
        else {
            // find sandbox guid
            console.log('No sandbox GUID provided, fnding sandbox GUID for sandbox Name: '+workingArgs['sandbox_name'])
            sandboxname = workingArgs['sandbox_name']
            sandbox_guid = await getSandboxGUIDbyName(sandboxname,app_guid)
            console.log('Sandbox GUID found: '+sandbox_guid)

        }
    }
    else {
        console.log('Not a sandbox scan')
    }

    if ( workingArgs['scan_type'] == 'policy' ){
        // get findings for latest policy scan
        console.log('Get findings from latest policy scan. App profile name:'+workingArgs['profile_name'])
        findingsResult = await getFindings(app_guid)
        //console.log(findings)
    }
    else if ( workingArgs['scan_type'] == 'sandbox' ){
        // git findings for latest sandbox scan
        console.log('Get findings from latest sandbox scan. App profile name: '+workingArgs['profile_name']+' Sandbox name: '+workingArgs['sandbox_name'])
        findingsResult = await getFindings(app_guid,sandbox_guid)
    }

    console.log(findingsResult.length+' policy relevant findings to be imported')

    if (findingsResult.length > 0){
        //always generate security tab json file
        console.log('Json file will be created')
        

        var json_findings=[]

        //json start
        json_start = '{"version": "2.0","vulnerabilities": ['

        //json findings
        m = 0
        while (m < findings.length){

            id = findings[m].issue_id+'-'+findings[m].context_guid+'-'+findings[m].build_id

            if (findings[m].finding_status.status == 'OPEN' || findings[m].finding_status.status == 'REOPENED' || findings[m].finding_status.status == 'NEW'){

                console.log('Finding with flaw ID '+id+' is OPEN and will be placed on JSON report file')

                //setting sevrities
                weight = findings[m].finding_details.severity
                if (weight == '0')
                    severity = 'Info'
                else if (weight == '1')
                    severity = 'Unknown'
                else if (weight == '2')
                    severity = 'Low'
                else if (weight == '3')
                    severity = 'Medium'
                else if (weight == '4')
                    severity = 'High'
                else if (weight == '5')
                    severity = 'Critical'

                //working with description
                description_original = findings[m].description
                desc_replaceSpan = description_original.replaceAll('</span>','\n  ')
                desc_replacebackSpan = desc_replaceSpan.replaceAll('<span>','')
                desc_replaceHTML = desc_replacebackSpan.replaceAll('<a href=\"','\n  ')
                desc_replaceEndHTML = desc_replaceHTML.replaceAll('</a>',' - ')
                desc_replaceClosingHREF = desc_replaceEndHTML.replaceAll('\">',' - ')
                desc_replaceReference = desc_replaceClosingHREF.replaceAll('References','  \nReferences')
                description = desc_replaceReference

                //Java source folder settings
                filePathOrg = findings[m].finding_details.file_path
                if (java_JSP_ROOT != "" && java_SRC_ROOT != ""){
                    if ( filePathOrg.startsWith('WEB-INF') ){
                        filePath = java_JSP_ROOT+filePathOrg
                    } 
                    else {
                        filePath = java_SRC_ROOT+filePathOrg
                    }
                }
                else {
                    filePath = filePathOrg
                }

                id = findings[m].issue_id+'-'+findings[m].context_guid+'-'+findings[m].build_id
                CWEName = findings[m].finding_details.cwe.name
                lineNumber = findings[m].finding_details.file_line_number
                method = findings[m].finding_details.procedure
                cwe = findings[m].finding_details.cwe.id



                json_finding = {
                    id: id,
                    cve: id,
                    category: "sast",
                    name: CWEName,
                    message: CWEName,
                    description: description,
                    severity: severity,
                    confidence: "High",
                    flaw_details_link: "",
                    scanner: {
                    id: "veracode_sast",
                    name: "Veracode Static Code Analysis Scan"
                    },
                    location: {
                    file: filePath,
                    start_line: lineNumber,
                    end_line: lineNumber,
                    class: filePath,
                    method: method,
                    dependency: {
                        package: {}
                    }
                    },
                    identifiers: [
                    {
                        type: "CWE",
                        name: "CWE-"+cwe,
                        value: cwe,
                        url: "https://cwe.mitre.org/data/definitions/"+cwe+".html"
                    }
                    ]
                }
                
                json_findings.push(JSON.stringify(json_finding));
            }
            else {
                console.log('Finding with flaw ID '+id+' is closed and will not be placed on JSON report file')
            }
            m++

        }


        //json end
        json_end = ']}'

        var fullReportJson = json_start+json_findings+json_end
        var flawsReport = JSON.parse(fullReportJson);

        // save to file
        fs.writeFileSync(GitlabOutputFileName,fullReportJson);

        console.log('report file has been created and saved as '+GitlabOutputFileName+' on artefacts')


        //create issues
        if (workingArgs['create_issue'] == 'true'){
            console.log('Issue creation is enabled')

            // check for existing issue and store results in listIssueResponse
            oldIssues = await getOldIssues()

            n = 0
            while (n < findings.length){

                id = findings[n].issue_id+'-'+findings[n].context_guid+'-'+findings[n].build_id

                if (findings[n].finding_status.status == 'OPEN' || findings[n].finding_status.status == 'REOPENED' || findings[n].finding_status.status == 'NEW'){

                    console.log('Finding with flaw ID '+id+' is OPEN and will be created as issue')

                    //setting sevrities
                    weight = findings[n].finding_details.severity
                    if (weight == '0')
                        severity = 'Info' //Informational
                    else if (weight == '1')
                        severity = 'Unknown' //Very Low 
                    else if (weight == '2')
                        severity = 'Low' //Low
                    else if (weight == '3')
                        severity = 'Medium' //Medium
                    else if (weight == '4')
                        severity = 'High' //High
                    else if (weight == '5')
                        severity = 'Critical' //Very High

                    //working with description
                    description_original = findings[n].description
                    desc_replaceSpan = description_original.replaceAll('</span>','\n  ')
                    desc_replacebackSpan = desc_replaceSpan.replaceAll('<span>','')
                    desc_replaceHTML = desc_replacebackSpan.replaceAll('<a href=\"','\n  ')
                    desc_replaceEndHTML = desc_replaceHTML.replaceAll('</a>',' - ')
                    desc_replaceClosingHREF = desc_replaceEndHTML.replaceAll('\">',' - ')
                    desc_replaceReference = desc_replaceClosingHREF.replaceAll('References','  \nReferences')
                    description = desc_replaceReference


                    //Java source folder settings
                    filePathOrg = findings[n].finding_details.file_path
                    if (java_JSP_ROOT != "" && java_SRC_ROOT !=""){
                        if ( filePathOrg.startsWith('WEB-INF') ){
                            filePath = java_JSP_ROOT+filePathOrg
                        } 
                        else {
                            filePath = java_SRC_ROOT+filePathOrg
                        }
                    }
                    else {
                        filePath = filePathOrg
                    }

                    id = findings[n].issue_id+'-'+findings[n].context_guid+'-'+findings[n].build_id
                    CWEName = findings[n].finding_details.cwe.name
                    fileName = findings[n].finding_details.file_name
                    lineNumber = findings[n].finding_details.file_line_number
                    method = findings[n].finding_details.procedure
                    cwe = findings[n].finding_details.cwe.id

                    projectURL = process.env.CI_SERVER_URL
                    projectName = process.env.CI_PROJECT_NAME
                    projectPath = process.env.CI_PROJECT_PATH
                    commitSHA = process.env.CI_COMMIT_SHA
                    fullUrl = projectURL+'/'+projectPath+'/-/blob/'+commitSHA+filePath+'#L'+lineNumber

                    var issueTitle = "Static Code Analysis - "+fileName+":"+lineNumber+" - Severity: "+severity+" - CWE: "+cwe+":"+CWEName;
                    var issueLable = "Static Code Analysis,CWE:"+cwe+","+severity;
                    var issueDescription = "### Static Code Analysis  \n  \n  \n### Description:  \n"+description+"  \n* "+CWEName+":"+cwe+"  \n* File Path: ["+filePath+":"+lineNumber+"]("+fullUrl+")  \n* Scaner: Veracode "+workingArgs['scan_type']+" scan";

                    //console.log('Description: '+issueDescription)


                    //check if issue already exists and if should be overwritten
                    oldIssuesLength = oldIssues.length


                    o=0
                    while (o<oldIssuesLength){
                        if (oldIssues[o].title == issueTitle){
                            exisitingOldIssue = true
                            break
                        }
                        else {
                            exisitingOldIssue = false
                        }
                        o++
                    }


                    if (exisitingOldIssue == true){
                        console.log("Issue '"+issueTitle+"' already exists")
                        if (oldIssues[o].state == 'closed'){
                            //create issue
                            console.log("Flaw is still open, old Gitlab issue is closed, new issue will be created")
                            newIssue = await createIssue(issueTitle,issueLable,issueDescription)
                            console.log(newIssue)
                        }
                        else {
                                console.log('Flaw is still open, old Gitlab issue is open, no need to create an new issue')
                        }
                    }
                    else {
                        //create issue
                        console.log("New issue will be created")
                        newIssue = await createIssue(issueTitle,issueLable,issueDescription)
                        console.log(newIssue)
                    }
                    






                }
                else {
                    console.log('Finding with flaw ID '+id+' is closed and will not create an issue')
                }
                n++
            }
        }
        else {
            console.log("Issue creation is not enabled")
        }
    }
    else {
        console.log("no flaws found to import")
    }
}


var getAppGUIDbyName = async (appname) =>{
        //generate HMAC header
        encodedAppname = encodeURIComponent(appname)
        var options = {
            host: auth.getHost(),
            path: "/appsec/v1/applications?size=100&page=0&name="+encodedAppname,
            method: "GET"
        }
        
        //send request
        try {
            var listIssueResponse = await Axios.request({
              method: 'GET',
              headers:{
                  'Authorization': auth.generateHeader(options.path, options.method),
                  'PRIVATE-TOKEN': workingArgs['gitlab_token']
              },
              url: 'https://api.veracode.com/appsec/v1/applications?size=100&page=0&name='+encodedAppname
            });
            
            apps=listIssueResponse.data._embedded.applications
            appLength=apps.length
            console.log(appLength+' apps found matching the name')

            j=0
            while (j < appLength ){
                if (listIssueResponse.data._embedded.applications[j].profile.name == appname ){
                    return appguid = listIssueResponse.data._embedded.applications[j].guid
                }
                j++
            }
          }
          catch (e) {
            console.log(e)
          }
}

var getSandboxGUIDbyName = async (sandboxname,app_guid) =>{
    //generate HMAC header
    var options = {
        host: auth.getHost(),
        path: '/appsec/v1/applications/'+app_guid+'/sandboxes',
        method: "GET"
    }

    //send request
    try {
        var listIssueResponse = await Axios.request({
          method: 'GET',
          headers:{
              'Authorization': auth.generateHeader(options.path, options.method),
              'PRIVATE-TOKEN': workingArgs['gitlab_token']
          },
          url: 'https://api.veracode.com/appsec/v1/applications/'+app_guid+'/sandboxes'
        });
        
        sandboxes=listIssueResponse.data._embedded.sandboxes
        sandboxesLength=sandboxes.length
        console.log(sandboxesLength+' sandboxes found on the app profile')

        k=0
        while (k < sandboxesLength ){
            if (listIssueResponse.data._embedded.sandboxes[k].name == sandboxname ){
                return sandboxguid = listIssueResponse.data._embedded.sandboxes[k].guid
            }
            k++
        }
      }
      catch (e) {
        console.log(e)
      }
}


var getFindings = async (app_guid,sandbox_guid,) =>{

    if (sandbox_guid){
        //generate HMAC header
        var options = {
            host: auth.getHost(),
            path: '/appsec/v2/applications/'+app_guid+'/findings?scan_type=STATIC&context='+sandbox_guid+'&size=500&violates_policy=TRUE',
            method: "GET"
        }
    }
    else {
        //generate HMAC header
        var options = {
            host: auth.getHost(),
            path: '/appsec/v2/applications/'+app_guid+'/findings?scan_type=STATIC&size=500&violates_policy=TRUE',
            method: "GET"
        }
    }

    //send request
    try {
        var listIssueResponse = await Axios.request({
          method: 'GET',
          headers:{
              'Authorization': auth.generateHeader(options.path, options.method),
              'PRIVATE-TOKEN': workingArgs['gitlab_token']
          },
          url: 'https://api.veracode.com'+options.path
        });
        
        findings = listIssueResponse.data._embedded.findings
        return findings
      }
      catch (e) {
        console.log(e)
      }
}

var getOldIssues = async (app_guid,sandbox_guid,) =>{
    try {
        var listOldIssueResponse = await Axios.request({
            method: 'GET',
            headers:{
                'PRIVATE-TOKEN': workingArgs['gitlab_token']
            },
            url: 'https://gitlab.com/api/v4/projects/'+workingArgs['gitlab_project']+'/issues?per_page=100&lables=Static%21Code%21Analysis'
        });

        oldIssuesResponse = listOldIssueResponse.data
        return oldIssuesResponse
    }
    catch (e) {
        console.log(e)
    }
}

var createIssue = async (issueTitle,issueLable,issueDescription) =>{

    try {
        var data = {
            title: issueTitle,
            labels: issueLable,
            description: issueDescription
          }

        var createIssueResposne = await Axios.request({
          method: 'POST',
          headers:{
              'Content-Type': 'application/json',
              'PRIVATE-TOKEN': workingArgs['gitlab_token']
          },
          data,
          url: 'https://gitlab.com/api/v4/projects/'+workingArgs['gitlab_project']+'/issues'
        });
        //?title='+issueTitle+'&labels='+issueLable+'&description='+issueDescription
        creationResposne = 'Issue with title "'+issueTitle+'" has been created.'
        return creationResposne
      }
      catch (e) {
        console.log(e)
        console.log(e.response.data)
      }
}



try {
    VeracodeSASTResultsImport(GitlabOutputFileName);
} 
catch (error) {
    core.setFailed(error.message);
}

module.exports = {
    SASTResults: VeracodeSASTResultsImport,
}