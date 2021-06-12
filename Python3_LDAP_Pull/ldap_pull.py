# This script uses Python 3 to pull a large (&gt;150,000) Active Directory entries and export
# the results to JSON and CSV for Logstash and Splunk to read from.
from ldap3 import Server, Connection, ALL, NTLM
import json
import os
import re
import sys
import csv
import base64
from time import gmtime, strftime

# Setting result locations, relative to a Unix operating system.
combined_cat_ad = '/etc/addata/results/combined_cat_ad.yaml'
combined_dep_ad = '/etc/addata/results/combined_dep_ad.yaml'
combined_fn_ad = '/etc/addata/results/combined_fn_ad.yaml'
combined_ad_json = '/etc/addata/results/ad_json.json'
final_cat_ad = '/etc/addata/results/cat_ad.yaml'
final_dep_ad = '/etc/addata/results/dep_ad.yaml'
final_fn_ad = '/etc/addata/results/fn_ad.yaml'
config = open('/etc/addata/config.txt', 'r').readlines()

# Uses config file above to read a base64 encoded string and using particular  lines it grabs a username and password and decodes.
# Obviously nowhere near as good as actually encrypting the credentials, but it's the best I have for the time being.
user = base64.b64decode(config[0])
pw = base64.b64decode(config[1])
# ###Enter AD User Info -- need to figure out a way to not hardcode in the future
cusr = user.decode('utf-8')
cpwd = pw.decode('utf-8')

# Function to combine files -- used at the end after AD data is gathered from multiple DNs
def combinefiles(inputfiles, outputfile):
    with open(outputfile, 'w') as outfile:
        for fname in inputfiles:
            with open(fname) as infile:
                for line in infile:
                    outfile.write(line)

# Function to deduplicate lines in a file -- used on the YAML files at the end
def dedupefiles(inputfile, dedupedfile):
    lines = open(inputfile, 'r').readlines()
    lines_set = set(lines)
    out = open(dedupedfile, 'w')
    for line in lines_set:
        out.write(line)

# Write log function to log progress to file and print if run manually

writetolog = '/etc/addata/logs/ad_grabber.log'

# Defines a function to write each activity to a log file for troubleshooting.
def writelog(file_name, textstring):
    logtime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
    logfile = open(file_name, 'a+')
    print("%s %s" % (logtime, textstring))
    logfile.write("%s ad_grabber: %s\n" % (logtime, textstring))

# Iterate through multiple user DNs when specified
multidn = ['&lt;TRUNC&gt;', '&lt;TRUNC&gt;'] ###Line truncated to remove any specific code
for dn in multidn:
    if dn == "&lt;TRUNC&gt;": ###Line truncated to remove any specific code
        dn_dir = "AllUsers"
    else:
        dn_dir = "Migration"

    orig_json = '/etc/addata/results/%s_orig_json.json' % dn_dir
    enhanced_json = '/etc/addata/results/%s_enhanced_data.json' % dn_dir
    csv_convert = '/etc/addata/results/%s_csvexport.csv' % dn_dir
    final_ad = '/etc/addata/results/%s_ad_json.json' % dn_dir
    ad_dept = '/etc/addata/results/%s_dep_ad.yaml' % dn_dir
    ad_cat = '/etc/addata/results/%s_cat_ad.yaml' % dn_dir
    ad_fn = '/etc/addata/results/%s_fn_ad.yaml' % dn_dir

    # Wiping old results
    try:
        os.remove(orig_json)
    except OSError:
        pass

    try:
        os.remove(enhanced_json)
    except OSError:
        pass

    try:
        os.remove(csv_convert)
    except OSError:
        pass

    try:
        os.remove(final_ad)
    except OSError:
        pass

    writelog(writetolog, 'Connecting to AD Server for DN: %s' % dn_dir)

    server = Server('&lt;TRUNC&gt;', use_ssl=True, get_info=ALL) ###Line truncated to remove any specific code
    conn = Connection(server, user=cusr, password=cpwd, auto_bind=True)

    basedn = dn

    writelog(writetolog, 'Connection Established.')

    writelog(writetolog, 'Gathering AD Objects...')

    # Search Criteria and Returning Attributes
    cookie = 'new_cookie'
    searchFilter = "(&amp;(objectClass=user)(objectClass=person)(!(objectClass=computer))(!(sAMAccountName=$*))" \
                   "(!(sAMAccountName=#*))(!(sAMAccountName=a-*))(!(sAMAccountName=w-*)))"
    searchAttributes = ["sAMAccountName", "givenName", "sn", "mail", "l", "co", "telephoneNumber", "mobile",
                        "businessUnitDesc", "manager", "whenCreated", "department", "title", "extensionAttribute1",
                        "managerLevelDesc", "distinguishedName"]

    user_atrb_num = 0

	# The with statement opens the connection and enables a paging pull of 800 results per pull.
	# I noticed with pulls larger than 1000, the results would time out at times.
	# The time outs appeared to be primarily due to the large values within some fields.
    with open(orig_json, 'w') as myfile:
        myfile.write('{"users": { ')
        while cookie:
            if cookie == "new_cookie":
                conn.search(basedn, searchFilter, attributes=searchAttributes, paged_size=5)
                for entry in conn.entries:
                    user_atrb_num += 1
                    json_ldap = entry.entry_to_json()
                    myfile.write('"%s":' % user_atrb_num)
                    myfile.write('%s\n' % json_ldap)
                    myfile.write(',')
                print(str(user_atrb_num) + " cookie objects processed.")
            try:
                cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            except KeyError:
                writelog(writetolog, 'Error: connection failed. Check connection user and password.')
                sys.exit()
            conn.search(basedn, searchFilter, attributes=searchAttributes, paged_size=800, paged_cookie=cookie)
            for entry in conn.entries:
                user_atrb_num += 1
                json_ldap = entry.entry_to_json()
                myfile.write('"%s":' % user_atrb_num)
                myfile.write('%s\n' % json_ldap)
                myfile.write(',')
                print(str(user_atrb_num) + " objects processed.", end='\r')
    logstring = "%s total objects processed." % user_atrb_num
    writelog(writetolog, logstring)

    writelog(writetolog, 'Fixing JSON...')
    # Reformats JSON to acceptable format for ElasticSearch
    with open(orig_json, 'rb+') as myfile:
        myfile.seek(-1, os.SEEK_END)
        myfile.truncate()
    with open(orig_json, 'a') as myfile:
        myfile.write('}}')
    writelog(writetolog, 'Objects  written.')

    config = json.loads(open(orig_json).read())

    writelog(writetolog, 'Enhancing Data...')
    cnt_usermanager = 0
    cnt_userfirst = 0
    cnt_userlast = 0
    # Loops through users and enhances JSON data with new fields that are calculated based on returned attributes
	# This is use case specific and is only kept here in case someone wants to do something similar.
    for obj in config["users"]:
        # Regex to extract Manager EID into its own field
        user_manager = str(config["users"][obj]["attributes"]["manager"])
        p = re.compile('CN=([^,]+)')
        user_manager = p.search(user_manager)
        config["users"][obj]["attributes"]["managedBy"] = []
        try:
            user_manager = '' + user_manager[1] + ''
        except TypeError:
            cnt_usermanager += 1
            user_manager = 'Null'
        config["users"][obj]["attributes"]["managedBy"] = user_manager
        # End manager extraction
        # Calculate Category
        user_title = str(config["users"][obj]["attributes"]["title"])
        r = re.compile('\[(.*)\]')
        user_title = r.search(user_title)
        if user_title[1] == "'Non-associate'":
            user_category = "Non-associate"
        else:
            user_category = "Associate"
        config["users"][obj]["attributes"]["Category"] = user_category
        # End Category Calculation
        # Full Name
        try:
            First = json.dumps(config["users"][obj]["attributes"]["givenName"][0])
        except IndexError:
            cnt_userfirst += 1
            First = 'Null'
        try:
            Last = json.dumps(config["users"][obj]["attributes"]["sn"][0])
        except IndexError:
            cnt_userlast += 1
            Last = 'Null'
        Full_Name = str(First) + " " + str(Last)
        Full_Name = Full_Name.replace('\"', '')
        config["users"][obj]["attributes"]["Full_Name"] = Full_Name

    # Logs the number of erroneous values
    writelog(writetolog, 'Found %s null values for manager. Replacing with null.' % cnt_usermanager)
    writelog(writetolog, 'Found %s null values for user first name. Replacing with null.' % cnt_userfirst)
    writelog(writetolog, 'Found %s null values for user last name. Replacing with null.' % cnt_userlast)
    writelog(writetolog, 'Saving enhanced file...')

    # Writing enhanced JSON to file
    with open(enhanced_json, 'w') as myfile2:
        json.dump(config, myfile2)
    writelog(writetolog, 'File saved.')

    # Converting to CSV for additional manipulations
    writelog(writetolog, 'Converting to CSV...')
    row = ''
    config2 = json.loads(open(enhanced_json).read())
    with open(csv_convert, 'w', encoding='utf-8') as myfile3:
        for obj1 in config2["users"]["1"]["attributes"]:
            myfile3.write('%s,' % obj1)
        for uid in config2["users"]:
            print("Currently converting user %s to csv." % uid, end='\r')
            myfile3.write('\n')
            for attribute in config2["users"]["1"]["attributes"]:
                if attribute != "managedBy" and attribute != "Category" and attribute != "Full_Name":
                    try:
                        user_atrb = str(config2["users"][uid]["attributes"][attribute][0])
                        user_atrb = '"' + user_atrb + '"'
                    except IndexError:
                        user_atrb = ''
                else:
                    try:
                        user_atrb = str(config2["users"][uid]["attributes"][attribute])
                        user_atrb = '"' + user_atrb + '"'
                    except IndexError:
                        user_atrb = ''
                myfile3.write('%s,' % user_atrb)
    logstring = "Finished converting %s users to csv format.\n" % (uid)
    writelog(writetolog, logstring)

    # The original JSON output above is used to write to CSV but that JSON is not line delimited,
    # the below converts that file into line delimitation JSON so that Filebeats doesn't throw a fit
    writelog(writetolog, 'Converting JSON output into line delimitation...')

    csvfile = open(csv_convert, 'r')
    jsonfile = open(final_ad, 'w')
    deptfile = open(ad_dept, 'w')
    catfile = open(ad_cat, 'w')
    fnfile = open(ad_fn, 'w')
    fieldnames = ("businessUnitDesc", "co", "department", "distingushedName", "extensionAttribute1",
                  "givenName", "l", "mail", "manager", "managerLevelDesc", "mobile", "sAMAccountName",
                  "sn", "telephoneNumber", "title", "whenCreated", "managedBy", "Category", "Full_Name",)
    reader = csv.DictReader(csvfile, fieldnames)
    rowstep = 0
    for row in reader:
        if rowstep != 0:
            json.dump(row, jsonfile)
            jsonfile.write('\n')
        rowstep += 1

    writelog(writetolog, 'Finished.')
    # csvfile.close

    # Converting individual AD objects into a 1:1 format in YAML user:&lt;&lt;object&gt;&gt; --
    # this is because Logstash cannot do 1:many translations
    writelog(writetolog, 'Converting to YAML...')
    csvfile = open(csv_convert, 'r')
    reader = csv.reader(csvfile, fieldnames)
    for row in reader:
        # ADEnrichlookup YAML Conversion
        dep = row[2]
        eid = row[11].lower()
        cat = row[17]
        fulln = row[18]
        # Department
        deptfile.write('"%s" : "%s"\n' % (eid, dep))
        # Category
        catfile.write('"%s" : "%s"\n' % (eid, cat))
        # Full Name
        fnfile.write('"%s" : "%s"\n' % (eid, fulln))

# Combine full AD JSON data
writelog(writetolog, 'Combining JSON output...')
filenames = ['/etc/addata/results/AllUsers_ad_json.json', '/etc/addata/results/Migration_ad_json.json']
combinefiles(filenames, combined_ad_json)

# combine AD YAML files and dedupe
writelog(writetolog, 'Combining AD Category YAML output...')
filenames = ['/etc/addata/results/AllUsers_cat_ad.yaml', '/etc/addata/results/Migration_cat_ad.yaml']
combinefiles(filenames, combined_cat_ad)
dedupefiles(combined_cat_ad, final_cat_ad)

writelog(writetolog, 'Combining AD Department YAML output...')
filenames = ['/etc/addata/results/AllUsers_dep_ad.yaml', '/etc/addata/results/Migration_dep_ad.yaml']
combinefiles(filenames, combined_dep_ad)
dedupefiles(combined_dep_ad, final_dep_ad)

writelog(writetolog, 'Combining AD Full Name YAML output...')
filenames = ['/etc/addata/results/AllUsers_fn_ad.yaml', '/etc/addata/results/Migration_fn_ad.yaml']
combinefiles(filenames, combined_fn_ad)
dedupefiles(combined_fn_ad, final_fn_ad)

# cleanup

writelog(writetolog, 'Cleaning up...')
cleanfiles = ['/etc/addata/results/AllUsers_ad_json.json', '/etc/addata/results/Migration_ad_json.json',
              '/etc/addata/results/AllUsers_cat_ad.yaml', '/etc/addata/results/Migration_cat_ad.yaml',
              '/etc/addata/results/AllUsers_orig_json.json', '/etc/addata/results/Migration_orig_json.json',
              '/etc/addata/results/AllUsers_csvexport.csv', '/etc/addata/results/Migration_csvexport.csv',
              '/etc/addata/results/AllUsers_dep_ad.yaml', '/etc/addata/results/Migration_dep_ad.yaml',
              '/etc/addata/results/AllUsers_enhanced_data.json', '/etc/addata/results/Migration_enhanced_data.json',
              '/etc/addata/results/AllUsers_fn_ad.yaml', '/etc/addata/results/Migration_fn_ad.yaml',
              '/etc/addata/results/combined_cat_ad.yaml', '/etc/addata/results/combined_dep_ad.yaml',
              '/etc/addata/results/combined_fn_ad.yaml']
for file in cleanfiles:
    try:
        os.remove(file)
    except OSError:
        pass

writelog(writetolog, 'Job done.')