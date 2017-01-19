'''
Python v2.7 script to download .nessus files of your choosing
than combine all files into merger.nessus file
than finally upload the merged file back to the URL/Server
'''
import os
import requests
import json
import time
import sys
import xml.etree.ElementTree as etree
import shutil
import subprocess

requests.packages.urllib3.disable_warnings() #Suppress Https warnings

url = ''    #input url of nessus server here
verify = False  #verify false to bypass certificate errors w/ self signed certs
token = ''
usr = ''    #input username ex:Admin
pwd = ''    #input password ex:P@$$w0rd
headers = {'X-Cookie': 'token=' + token,'content-type': 'application/json'}
files = ('ScanFile1', 'ScanFile2', 'ScanFile3')    #names of files/scans to download from server


def build_url(resource):
		return '{0}{1}'.format(url, resource)

		
def connect(method, resource, data=None):
'''
connect with html requests such as POST, PUT, DELETE, GET , etc.
'''

		headers = {'X-Cookie': 'token={0}'.format(token),'content-type': 'application/json'}

		data = json.dumps(data)

		if method == 'POST':
				r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
		elif method == 'PUT':
				r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
		elif method == 'DELETE':
				r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
		else:
				r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

		resp = r.json()

		if r.status_code != 200:
				print(resp['error'])
				sys.exit

		return resp

def upload(upload_file):
		"""
		File uploads don't fit easily into the connect method so build the request
		here instead.
		"""
		params = {'no_enc': 0}
		headers = {'X-Cookie': 'token={0}'.format(token)}

		filename = os.path.basename(upload_file)
		files = {'Filename': (filename, filename),
						'Filedata': (filename, open(upload_file, 'rb'))}

		r = requests.post(build_url('/file/upload'), params=params, files=files,
											headers=headers, verify=verify)

		resp = r.json()

		if r.status_code != 200:
				print(resp['error'])
				sys.exit

		return resp['fileuploaded']


def login(usr, pwd):
		login = {'username': usr, 'password': pwd}
		data = connect('POST', '/session', data=login)

		return data['token']


def logout():
		connect('DELETE', '/session')


def import_scan(filename):
		im_file = {'file': filename}

		data = connect('POST', '/scans/import', data=im_file)

		scan_name = data['scan']['name']
		print('Successfully imported the scan {0}.'.format(scan_name))


#login = {'username': usr, 'password': pwd}



s = requests.Session()
req = requests.post('https://localserver:8834/session', data={'username': usr, 'password': pwd}, verify=False) #may have to change URL
jsonres = req.json()
token = jsonres.get('token')
print token

#may have to change URL below
req = s.get('https://localserver:8834/scans', headers={'X-Cookie': 'token=' + token,'content-type': 'application/json'}, verify=False)#may have to change URL
print req
# print r.text  #commented out

jsonres = req.json()
folder_list = jsonres.get('scans')
i = len(folder_list)


#URL was changed here may have to customize for each user or server
for j in folder_list :
		scanobj = (j)
		for k in files :
				if scanobj['name'] == k :
						print(scanobj['id'], scanobj['name'])
						scanid = scanobj['id']

						payload = {'format': 'nessus'}
						t = s.post('https://localserver:8834/scans/' + str(scanid) + '/export', json=payload, headers={'X-Cookie': 'token=' + token,'content-type': 'application/json'}, verify=False)

						print t.text
						jsonfile = t.json()
						fileid = jsonfile.get('file')
						print fileid
						
						q = s.get('https://localserver:8834/scans/' + str(scanid) + '/export/' + str(fileid) + '/status', headers={'X-Cookie': 'token=' + token,'content-type': 'application/json'}, verify=False)

						time.sleep(10)

						u = s.get('https://localserver:8834/scans/' + str(scanid) + '/export/' + str(fileid) + '/download', headers={'X-Cookie': 'token=' + token,'content-type': 'application/json'}, verify=False)
						
						#customize for file path below
						print('Saving scan results to C:\Users\YourNameHere\My Documents\LiClipse Workspace\')
						with open(os.path.join("C:\Users\YourNameHere\My Documents\LiClipse Workspace\",scanobj['name'] + '.nessus'), 'w') as f:
									f.write(u.text)


									
#execfile("merger.py")


#subprocess.call('C:\Users\YourNameHere\My Documents\LiClipse Workspace\merger.py')

#run ('merger.py').returncode

#none of the above worked out to run the merger.py file so I hard coded it below

first = 1
for fileName in os.listdir("."):
    if ".nessus" in fileName:
            print(":: Parsing", fileName)
            if first:
                mainTree = etree.parse(fileName)
                report = mainTree.find('Report')
                report.attrib['name'] = 'Merged Report'
                first = 0
            else:
                tree = etree.parse(fileName)
                for host in tree.findall('.//ReportHost'):
                        existing_host = report.find(".//ReportHost[@name='"+host.attrib['name']+"']")
                        if not existing_host:
                                print "adding host: " + host.attrib['name']
                                report.append(host)
                        else:
                                for item in host.findall('ReportItem'):
                                        if not existing_host.find("ReportItem[@port='"+ item.attrib['port'] +"'][@pluginID='"+ item.attrib['pluginID'] +"']"):
                                                print "adding finding: " + item.attrib['port'] + ":" + item.attrib['pluginID']
                                                existing_host.append(item)
            print(":: => done.")

if "nss_report" in os.listdir("."):
    shutil.rmtree("nss_report")

os.mkdir("nss_report")
mainTree.write("nss_report/report.nessus", encoding="utf-8", xml_declaration=True)


time.sleep(4)

if __name__ == '__main__':
		
		#turns out the below statements were not needed? may tinker further otherwise script runs
		#token = login(username, password)
		#filename = upload("C:\\Users\\YourNameHere\\My Documents\\LiClipse Workspace\\...\\report.nessus")
		
		import_scan("report.nessus")

		logout()
#do not know if file closed is needed, put it in to try and stop Json errors let me know if anyone can figure the errors out        
file.close()
        
