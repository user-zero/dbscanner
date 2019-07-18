import pymssql
import sys
import getpass
import argparse
import re
import datetime
appversion = 1.22222222222222222222222
appversion = str(appversion)
# Take command line arguments from user.
parser = argparse.ArgumentParser(description='Scan Databases for sensitive information.')
parser.add_argument('-t', required=True, action='store', dest='IPADDR', help='Target IP of the Database to be scanned.')
parser.add_argument('-ad', action='store', dest='DOMAIN', help='Domain the user lives in.')
parser.add_argument('-u', required=True, action='store', dest='UNAME', help='Username used to authenticate to the database.')
parser.add_argument('-d', action='store', dest='DB', help='Name of the target database.')
parser.add_argument('-b', action='store', dest='TABLE', help='Name of the target table.')
parser.add_argument('-c', action='store', dest='COL', help='Name of a specified target column.')
parser.add_argument('-v', action='store', dest='VERB', help='Request more verbose output. Output file will contain sensitive data if found.')
parser.add_argument('-q', action='store', dest='MAP', help='Does not query the database for its contents. Only maps out the DB,Table,Column structure.')
parser.add_argument('-p', action='store', dest='tport', help='Specify a port.')
parser.add_argument('-r', action='store', dest='NumRows', help='Custom number of rows to scan.')
parser.add_argument('-debug', action='store', dest='DEBUG', help='Generates a debug file. DON\'T USE UNLESS NECESSARY.')

args = parser.parse_args()

numRows = args.NumRows
tport = args.tport
server = args.IPADDR
domain = args.DOMAIN
username = args.UNAME
db = args.DB
table = args.TABLE
col = args.COL
noData = args.MAP
debug = args.DEBUG

if tport == None:
    tport = 'Not Defined'
if server == None:
    server = 'Not Defined'
if domain == None:
    domain = 'Not Defined'
if username == None:
    username = 'Not Defined'
if db == None:
    db = 'Not Defined'
if table == None:
    table = 'Not Defined'
if col == None:
    col = 'Not Defined'
if noData == None:
    noData = 'Not Defined'
if numRows ==  None:
    numRows  = 'Not Defined'
if debug ==  None:
    debug  = 'Not Defined'

linesChecked = 0

DB_List = []
Table_List = []
Target_List = []
Findings_List = []
Column_List = []

if tport == 'Not Defined':
    tport = 1433

if domain == 'Not Defined':
    user1 = username
else:
    user1 = domain + '\\' + username


#checks if the user really wants to scan all databases in the event they have not specified a single one.
if db == 'Not Defined':
    print("No database has been specified, this will scan ALL databases on the server. Would you like to continue? (y/n): ")
    yes = {'yes','y', 'ye', ''}
    no = {'no','n'}

    choice = raw_input().lower()
    if choice in yes:
        print("Scanning all Databases...")
    elif choice in no:
        print("Exiting now. No scan will be performed.")
        sys.exit()
    else:
        print("Improper response received, exiting now. No scan will be performed.")
        sys.exit()

#Build result and debug files
now = datetime.datetime.now()
resultsFile = open('DLP_DB_Scan_' + server + ':' + str(tport) + '_' + now.strftime("%d-%m-%Y_%H.%M.%S") + '.csv', 'w')
resultsFile.write('Scan Started on ' + now.strftime("%d-%m-%Y_%H.%M.%S") + ' with the following arguments:\n')
resultsFile.write('Scanner version: ' + appversion + '\n')
resultsFile.write('Target: ' + server.encode('utf-8') + ':' + str(tport) + '\n')
resultsFile.write('Username: ' + user1.encode('utf-8') + '\n')
resultsFile.write('Database Specified: ' + db.encode('utf-8') + '\n')
resultsFile.write('Table Specified: ' + table.encode('utf-8') + '\n')
resultsFile.write('Column Specified: ' + col.encode('utf-8') + '\n')
resultsFile.write('Mapping Only: ' + noData.encode('utf-8'))
if debug != 'Not Defined':
    debugFile = open('DLP_DEBUG_' + server + ':' + str(tport) + '_' + now.strftime("%d-%m-%Y_%H.%M.%S") + '.txt', 'w')
    debugFile.write('Scan Started on ' + now.strftime("%d-%m-%Y_%H.%M.%S") + ' with the following arguments:\n')
    debugFile.write('Scanner version: ' + appversion + '\n')
    debugFile.write('Target: ' + server.encode('utf-8') + ':' + str(tport) + '\n')
    debugFile.write('Username: ' + user1.encode('utf-8') + '\n')
    debugFile.write('Database Specified: ' + db.encode('utf-8') + '\n')
    debugFile.write('Table Specified: ' + table.encode('utf-8') + '\n')
    debugFile.write('Column Specified: ' + col.encode('utf-8') + '\n')
    debugFile.write('Mapping Only: ' + noData.encode('utf-8') + '\n\n')


if noData == True:
    resultsFile.write('\n\n-------Results-------\nDatabase, Table, Column\n')
else:
    resultsFile.write('\n\n-------Results-------\nDatabase, Table, Column, Number of Matches, Number of Lines Checked\n')

server1 = server + ',' + str(tport)
#print server
#prompts for the user's password
password1 = getpass.getpass()

conn = pymssql.connect(host = server, port = tport, user =  user1, password =  password1)
cursor = conn.cursor()

class EnumerateTables:

    def queryForDatabases(self, DB_List):
        if db == 'Not Defined':
            query='SELECT name FROM master.dbo.sysdatabases WHERE name <>\'tempdb\';\n'
            if debug != 'Not Defined':
                debugFile.write(query)
            try:
                cursor.execute(query)
                row = cursor.fetchone()
                while row:
                    DB_List.append(row[0].encode('utf-8'))
                    row = cursor.fetchone()
            except:
                resultsFile.write('Could not perform query: ' + query.encode('utf-8') + '\n')
        else:
            DB_List.append(db)
        print('Databases Enumerated Successfully')
        if debug!='Not Defined':
            debugFile.write('--- List of Databases Discovered ---')
            for i in (DB_List):
                debugFile.write(i + ", ")
            debugFile.write('\n')
        dbquery.queryForTables(Table_List)




    def queryForTables(self,Table_List):

        print('Enumerating Tables')
        for x in (DB_List):
            Table_List = []
            if table == 'Not Defined':
                query = "USE [" + x.encode('utf-8') + "]; SELECT SCHEMA_NAME([schema_id]) +'.'+ name as name FROM sys.tables WHERE type IN ('U', 'TT') AND is_ms_shipped = 0"
                if debug != 'Not Defined':
                    debugFile.write(query)
                    debugFile.write("\n")
                try:
                    cursor.execute(query)
                    row = cursor.fetchone()
                    while row:
                        Table_List.append(row[0].encode('utf-8'))
                        row = cursor.fetchone()
                    print('Table Enumeration Completed.')
                except:
                    resultsFile.write('Could not perform query: ' + query.encode('utf-8') + '\n')
            else:
                Table_List = [(table.encode('utf-8'))]
            print('Enumerating Columns')
            for i in Table_List:
                dbquery.queryForColumns(i, x)
            print('Column enumeration complete.')
            if debug != 'Not Defined':
                debugFile.write('\n--- List of targets to pull data from ---\n')
                for line in Target_List:
                    debugFile.write(str(line) +"\n")

    def queryForColumns(self, tableName, dbname):

        if col == 'Not Defined':
            if tableName != 'Not Defined':
                n = tableName.find('.')
                tablenamestring = tableName[n+1:].encode('utf-8')
                goodtablename = tablenamestring.replace("'","''")
                query = 'USE [' + dbname.encode('utf-8') +'] SELECT s.[COLUMN_NAME] FROM INFORMATION_SCHEMA.COLUMNS s WHERE s.TABLE_NAME =\'' + goodtablename + '\';\n'
                if debug != 'Not Defined':
                    debugFile.write(query)
                try:
                    cursor.execute(query)
                    row = cursor.fetchone()
                    while row:
                        Target_List.append([dbname, tableName, row[0].encode('utf-8')])
                        row = cursor.fetchone()
                except:
                    resultsFile.write('Could not perform query: ' + query.encode('utf-8') + '\n')
        else:
            Target_List.append([dbname, tableName, col])


    def queryData(self,Target_List):
        print('Pulling Data')
        for i in Target_List:
            counter = 0
            linesInColumn = 0
            n = i[1].find('.')
            first = i[1]
            table = first[n+1:]
            schema = first[:n]
            query = 'USE [' + i[0] + '] SELECT TOP 1000 [' + i[2] + '] FROM [' + schema + '].[' + table + ']\n'
            if debug != 'Not Defined':
                debugFile.write(query)
            try:
                cursor.execute(query)
                row = cursor.fetchone()
            except Exception as e:
                if debug != 'Not Defined':
                    debugFile.write('The previous query failed. '+ str(e) + '\n')
            while row:
                for x in row:
                    global linesChecked
                    linesChecked += 1
                    linesInColumn += 1
                    sys.stdout.write("\rLines of Data Checked: " + str(linesChecked))
                    sys.stdout.flush()
                    if dbquery.checkSSN(row[0]) == "Match":
                        counter += 1
                row = cursor.fetchone()
            if counter > 0:
                resultsFile.write(i[0] + ',' + i[1] + ',' + i[2] + ',' + str(counter) + ',' + str(linesInColumn) + '\n')


    def checkSSN(self, checkMe):
        #pattern = re.compile("^(\d{3}-?\d{2}-?\d{4}|XXX-XX-XXXX)$")
        pattern = re.compile("^(?!(000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}$|^(?!(000|666|9))\d{3}(?!00)\d{2}(?!0000)\d{4}$")
        try:
            checkMe = str(checkMe)
        except Exception as e:
            return False
        if (pattern.match(checkMe)):
            if debug != 'Not Defined':
                debugFile.write('Match Found: ' + checkMe.encode('utf-8') + ' \n')
            return "Match"
        else:
            return False

dbquery = EnumerateTables()
dbquery.queryForDatabases(DB_List)
if noData == True:
    for i in Target_List:
        resultsFile.write(' '.join(repr(x).lstrip('u')[1:-1] for x in i)+'\n')
else:
    dbquery.queryData(Target_List)
print("\nScan Completed")
end = datetime.datetime.now()
resultsFile.write('\nScan completed on '+ end.strftime("%d-%m-%Y_%H.%M.%S")+ '\n')
