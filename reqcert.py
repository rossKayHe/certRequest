import os, sys, boto3, botocore, configparser, subprocess
from OpenSSL import crypto
from botocore.config import Config
import random, string, time

import smtplib
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

sr = sys.argv[1]
email = sys.argv[2]
OU = sys.argv[3]
cn = sys.argv[4]
C  = 'US' 
ST = 'Washington'
L  = 'Seattle'
O  = 'Nordstrom IT' 
csrfile = cn + '.csr'
keyfile = cn + '.key'
TYPE_RSA = crypto.TYPE_RSA

ca_arn = 'arn:aws:acm-pca:us-west-2:572824850745:certificate-authority/038b1c07-ba46-47b5-9db1-bd14324d2a4a'

config = configparser.ConfigParser()
config.read('/opt/.aws/config.ini')
awsuser = config.get('Section1', 'awsuser')
awsdata = config.get('Section1', 'awsdata')

subprocess.run("/usr/local/bin/awscreds --user " + awsuser + " --password '" + awsdata +"' --role arn:aws:iam::572824850745:role/NORD-Prod_ESB-DevUsers-Team --once", shell=True)

#*************************************
#******* Generate password ***********
sp_range = random.randrange(1,3)
d_range = random.randrange(1,4)

p_string = ''

for x in range(0,sp_range):
    p_string = p_string + random.choice('@#$%&*')
for x in range(0,d_range):
    p_string = p_string + random.choice(string.digits)

p_string = p_string + (''.join([random.choice(string.ascii_letters) for n in range(11-len(p_string))]) )
passwd=(random.choice(string.ascii_letters) + ''.join(random.sample(p_string,len(p_string))))
#*************************************

cert = crypto.X509Req()
cert.get_subject().countryName = C
cert.get_subject().stateOrProvinceName = ST
cert.get_subject().organizationName = O
cert.get_subject().organizationalUnitName = OU
cert.get_subject().commonName = cn
cert.get_subject().CN = cn
extension_list = [
    crypto.X509Extension(type_name=b"basicConstraints",
                         critical=False, value=b"CA:false")]
cert.add_extensions(extension_list)
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)  # generate RSA key-pair
cert.set_pubkey(k)
cert.sign(k, 'sha256')

open(csrfile, 'wb').write(
    crypto.dump_certificate_request(crypto.FILETYPE_PEM, cert))
open(keyfile, 'wb').write(
    crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey=k))


boto3.setup_default_session(profile_name='nordstrom-federated')
client = boto3.client('acm-pca', region_name='us-west-2', config=Config(proxies={'https': 'webproxy.nordstrom.net:8181'}))

crt = open(sys.path[0] + '/' +  cn + '.csr', "rb").read()
issue_response = client.issue_certificate(
	CertificateAuthorityArn=ca_arn,
    Csr=crt,
    SigningAlgorithm='SHA256WITHRSA',
    Validity={
        'Value': 1,
        'Type': 'YEARS'
    }
)
"""Response Syntax
dict
{
    'CertificateArn': 'string'
}"""

print('ACM-PCA issued cert ARN:' + issue_response.get('CertificateArn'))

print('30 second delay before attempting to retrieve the certificate')
time.sleep(30)
for i in range(0,100):
    try:
        cert_response = client.get_certificate(
            CertificateAuthorityArn=ca_arn,
            CertificateArn=issue_response.get('CertificateArn')
        )

    except Exception as e:
        print (str(e))
        continue
    break
    time.sleep(5)

"""Response Syntax
dict
{
    'Certificate': 'string',
    'CertificateChain': 'string'
}"""

acmclient = boto3.client('acm', region_name='us-west-2', config=Config(proxies={'https': 'webproxy.nordstrom.net:8181'}))

#cert_response.get("CertificateChain")
import_response = acmclient.import_certificate(
    Certificate=cert_response.get("Certificate"),
    PrivateKey=crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey=k),
    CertificateChain=cert_response.get("CertificateChain")
)
print ('ACM CertificateArn: ' + import_response.get("CertificateArn"))

response = acmclient.add_tags_to_certificate(
    CertificateArn=import_response.get("CertificateArn"),
    Tags=[
        {
            'Key': 'SR',
            'Value': sr
        },
        {
            'Key': 'Requester',
            'Value': email
        },
        {
            'Key': 'Name',
            'Value': cn
        },
        {   'Key':'DomainName',
            'Value': cn
        },
        {
            'Key': 'OwnerDL',
            'Value': OU
        }
    ]
)

cert_response = acmclient.get_certificate(
    CertificateArn=import_response.get('CertificateArn')
)
f =  open(cn + ".cer", "w")
f.write(cert_response.get("Certificate"))
f.close

cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_response.get("Certificate"))
privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(keyfile).read())
pfx = crypto.PKCS12Type()
pfx.set_privatekey(k)
pfx.set_certificate(cert)
pfxdata = pfx.export(passwd)
with open(cn + '.pfx', 'wb') as pfxfile:
    pfxfile.write(pfxdata)

msg = MIMEMultipart()
msg['From'] = 'teeta@nordstrom.com'
msg['To'] = COMMASPACE.join(email)
msg['Date'] = formatdate(localtime=True)
msg['Subject'] = sr
msg.attach(MIMEText('Dear ' + email + '\n\nAttached is your BST for ' + cn))
with open(cn + '.pfx', "rb") as fil:
        part = MIMEApplication(
            fil.read(),
            Name=cn + '.pfx'
        )
# After the file is closed
part['Content-Disposition'] = 'attachment; filename=' + cn + '.pfx'
msg.attach(part)
try:
    smtp = smtplib.SMTP('exchange.nordstrom.net')
    print('Emailing BST to ' + email)
    smtp.sendmail('teeta@nordstrom.com', email, msg.as_string())
except Exception as e:
    print(str(e))

msg = MIMEMultipart()
msg['From'] = 'teeta@nordstrom.com'
msg['To'] = COMMASPACE.join(email)
msg['Date'] = formatdate(localtime=True)
msg['Subject'] = sr
msg.attach(MIMEText(passwd))
try:
    print('Emailing password to ' + email)
    smtp.sendmail('teeta@nordstrom.com', email, msg.as_string())
    smtp.close()
except Exception as e:
    print(str(e))

