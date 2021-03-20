import os

try:
    import platform
except ImportError:
    os.system('pip install platform')
    import platform

if platform.system() == 'Windows':
    clear = lambda : os.system('cls')
elif platform.system() == 'Linux':
    clear = lambda: os.system('clear')

try:
    import requests
except ImportError:
    os.system('pip install requests')
    import requests
    clear()
try:
    from random import randint, random, choice
except ImportError:
    os.system('pip install random')
    from random import randint, random
    clear()
try:
    from colored import fg
except ImportError:
    os.system('pip install colored')
    from colored import fg
    clear()
try:
    import secrets
except ImportError:
    os.system('pip install secrets')
    import secrets
    clear()

def close():
    input("\n- Prees enter to close /")
    exit()

print('''
   ____    ____        _  __     _                     __  
  / __ \  |___ \__   _(_)/ /_   | |__   ___ _ __ ___   \ \ 
 / / _` |   __) \ \ / / | '_ \  | '_ \ / _ \ '__/ _ \ (_) |
| | (_| |  / __/ \ V /| | (_) | | | | |  __/ | |  __/  _| |
 \ \__,_| |_____| \_/_/ |\___/  |_| |_|\___|_|  \___| (_) |
  \____/            |__/                               /_/ 
''')

username = str(input("[+] Input username : "))
password = str(input("[+] Input password : "))

USER_AGENTS = [
    'Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.3'
]

user = choice(USER_AGENTS)

req = requests.sessions.session()

log_url = 'https://www.instagram.com/accounts/login/ajax/'
x_ig_app_id = randint(90000000000, 1000000000000000)
x_instagram_ajax = secrets.token_hex(6)
log_head = {
    'accept': '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
    'content-length': '281',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://www.instagram.com',
    'referer': 'https://www.instagram.com/',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': user,
    'x-csrftoken': 'missing',
    'x-ig-app-id': str(x_ig_app_id),
    'x-ig-www-claim': '0',
    'x-instagram-ajax': str(x_instagram_ajax),
    'x-requested-with': 'XMLHttpRequest'
}

log_data = {
    'username': username,
    'enc_password': '#PWD_INSTAGRAM_BROWSER:0:1589682409:' + password
}

log = req.post(log_url, headers=log_head, data=log_data)
loginJS = log.json()
cookies = log.cookies

def session_id():

    getsessionid = cookies.get('sessionid')
    save = open(f'@{username}.txt', 'a').write(f'user = {username},\npass = {password},\nsessionid = {sessionid}\nBy @2vj6, Enjoy.')
    print(f'- Done Saving info For @{username} Successfully !')
    close()

def two_factor():
    print('- Two Factor Required !')
    identifier1 = loginJS['two_factor_info']['two_factor_identifier']

    modes = []
    if 'sms_two_factor_on":true,"totp_two_factor_on":true' in log.text:
        # totp means the application ( Duo Mobile )
        phone_nump = loginJS['two_factor_info']['obfuscated_phone_number']
        modes.append("1 - By SMS")
        modes.append('2 - By App')
        print(modes)
        mode = int(input("- Solve it By : "))
        if mode == 1:
            get_twof_info_url = 'https://www.instagram.com/accounts/login/two_factor?__a=1'

            get_twof_info_head = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
                'referer': 'https://www.instagram.com/accounts/login/two_factor?next=%2F',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': user,
                'x-ig-app-id': str(x_ig_app_id),
                'x-ig-www-claim': '0',
                'x-requested-with': 'XMLHttpRequest'
            }

            info = req.get(get_twof_info_url, headers=get_twof_info_head, cookies=cookies)

            Get_sms_message_url = 'https://www.instagram.com/accounts/send_two_factor_login_sms/'

            sms_message_head = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
                'content-length': '35',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/accounts/login/two_factor?next=%2F',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': user,
                'x-csrftoken': csrftoken,
                'x-ig-app-id': str(x_ig_app_id),
                'x-ig-www-claim': '0',
                'x-instagram-ajax': str(x_instagram_ajax),
                'x-requested-with': 'XMLHttpRequest',
            }

            get_sms_data = {
                'username': username,
                'identifier': identifier1
            }

            get_sms = req.post(Get_sms_message_url, headers=sms_message_head, data=get_sms_data, cookies=cookies)

            get_identifier2 = get_sms.json()
            identifier2 = get_identifier2['two_factor_info']['two_factor_identifier']

            if get_sms.status_code == 200:
                pass
            else:
                print("Some Error happened , plz try again later .")
                print(get_sms)

            print(f" Done Sending Code To The Phone That Ends With [{phone_nump}] .")
            print("- Don't Worry if u Didn't Received The Code Yet , Be Patient!")
            code = str(input("- Enter The Code u Got : "))

            send_code_url = 'https://www.instagram.com/accounts/login/ajax/two_factor/'

            send_code_head = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
                'content-length': '100',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/accounts/login/two_factor?next=%2F',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': user,
                'x-csrftoken': csrftoken,
                'x-ig-app-id': str(x_ig_app_id),
                'x-ig-www-claim': 'hmac.AR3ihiFU4BpZNtr3itbgVqLCE4hOBhysg8trxAGmUhxZqswg',
                'x-instagram-ajax': str(x_instagram_ajax),
                'x-requested-with': 'XMLHttpRequest'
            }

            send_code_data = {
                'username': username,
                'verificationCode': code,
                'identifier': identifier2,
                'queryParams': '{"next":"/"}'
            }

            send_code = req.post(send_code_url, headers=send_code_head, data=send_code_data, cookies=cookies)

            if 'userId' in send_code.text:
                print("- logged in Successfully ")
                pass
            elif 'sms_code_validation_code_invalid' in send_code.text:
                print("Wrong Code Please Check your code And Try Again !")
                close()
            elif 'sms_code_validation_code_missing' in send_code.text:
                print("input Your Code Ya 7Mar !")
                close()
            else:
                print("Something Wrong Happened , Check The Response")
                print(send_code.text)
                close()
        elif mode == 2:
            code = input("- Enter The Code From The App : ")

            send_code_url = 'https://www.instagram.com/accounts/login/ajax/two_factor/'

            send_code_head = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
                'content-length': '100',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/accounts/login/two_factor?next=%2F',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': user,
                'x-csrftoken': csrftoken,
                'x-ig-app-id': str(x_ig_app_id),
                'x-ig-www-claim': 'hmac.AR3ihiFU4BpZNtr3itbgVqLCE4hOBhysg8trxAGmUhxZqswg',
                'x-instagram-ajax': str(x_instagram_ajax),
                'x-requested-with': 'XMLHttpRequest'
            }

            send_code_data = {
                'username': username,
                'verificationCode': code,
                'identifier': identifier1,
                'queryParams': '{"next":"/"}'
            }

            send_code = req.post(send_code_url, headers=send_code_head, data=send_code_data, cookies=cookies)

            if 'userId' in send_code.text:
                print("- logged in Successfully")
                pass
            elif 'sms_code_validation_code_invalid' in send_code.text:
                print("Wrong Code Please Check your code And Try Again !")
                close()
            elif 'sms_code_validation_code_missing' in send_code.text:
                print("input Your Code Ya 7Mar !")
                close()
            else:
                print("Something Wrong Happened , Check The Response")
                print(send_code.text)
                close()
    elif 'sms_two_factor_on":true,"totp_two_factor_on":false' in log.text:
        phone_num = loginJS['two_factor_info']['obfuscated_phone_number']
        print(f"- Done Sending Code To The Phone That Ends With [ {phone_num} ] .")
        print("- Don't Worry if u Didn't Received The Code Yet , Be Patient!")
        code = str(input("- Enter The Code u Got : "))

        send_code_url = 'https://www.instagram.com/accounts/login/ajax/two_factor/'

        send_code_head = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
            'content-length': '100',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/accounts/login/two_factor?next=%2F',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': user,
            'x-csrftoken': csrftoken,
            'x-ig-app-id': str(x_ig_app_id),
            'x-ig-www-claim': 'hmac.AR3ihiFU4BpZNtr3itbgVqLCE4hOBhysg8trxAGmUhxZqswg',
            'x-instagram-ajax': str(x_instagram_ajax),
            'x-requested-with': 'XMLHttpRequest'
        }

        send_code_data = {
            'username': username,
            'verificationCode': code,
            'identifier': identifier2,
            'queryParams': '{"next":"/"}'
        }

        send_code = req.post(send_code_url, headers=send_code_head, data=send_code_data, cookies=cookies)

        if 'userId' in send_code.text:
            print("- logged in Successfully")
            pass
        elif 'sms_code_validation_code_missing' in send_code.text:
            print("input Your Code Ya 7Mar !")
            close()
        elif 'sms_code_validation_code_missing' in send_code.text:
            print("input Your Code Ya 7Mar !")
            close()
        else:
            print("Something Wrong Happened , Check The Response")
            print(send_code.text)
            close()
    elif 'sms_two_factor_on":false,"totp_two_factor_on":true' in log.text:
        code = input("- Enter The Code From The App : ")

        send_code_url = 'https://www.instagram.com/accounts/login/ajax/two_factor/'

        send_code_head = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9,ar;q=0.8,he;q=0.7',
            'content-length': '100',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/accounts/login/two_factor?next=%2F',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': user,
            'x-csrftoken': csrftoken,
            'x-ig-app-id': str(x_ig_app_id),
            'x-ig-www-claim': 'hmac.AR3ihiFU4BpZNtr3itbgVqLCE4hOBhysg8trxAGmUhxZqswg',
            'x-instagram-ajax': str(x_instagram_ajax),
            'x-requested-with': 'XMLHttpRequest'
        }

        send_code_data = {
            'username': username,
            'verificationCode': code,
            'identifier': identifier1,
            'queryParams': '{"next":"/"}'
        }

        send_code = req.post(send_code_url, headers=send_code_head, data=send_code_data, cookies=cookies)

        if 'userId' in send_code.text:
            print("- logged in Successfully")
            pass
        elif 'sms_code_validation_code_missing' in send_code.text:
            print("input Your Code Ya 7Mar !")
            close()
        elif 'sms_code_validation_code_missing' in send_code.text:
            print("input Your Code Ya 7Mar !")
            close()
        else:
            print("Something Wrong Happened , Check The Response")
            print(send_code.text)
            close()

def secure():

    print("- Your Account is secure !")

    path = loginJS['checkpoint_url']

    link = f'https://www.instagram.com{path}?__a=1'

    head = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'referer': 'https://www.instagram.com/',
        'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': user
    }

    get_info = req.get(link, headers=head, cookies=cookies)

    if get_info.status_code == 200:
        pass
    else:
        print("There was a proplem with getting secure info , try again later please !")
        close()

    secureJS = get_info.json()

    if 'email' in secureJS['fields'] and 'phone' in secureJS['fields']:
        email = secureJS['fields']['email']
        phone = secureJS['fields']['phone']
        print(f"- [0] phone : {phone} , [1] email : {email})")
        ask = int(input("- Send Code to : "))
        if ask == 0:
            secure_data = {
                'choice': 0
            }
            send_secure_mood = req.post(link, headers=log_head, data=secure_data, cookies=cookies)

            if send_secure_mood.status_code == 200:
                print(f"- Code Seccessfully sent to : {phone}")
                pass
            else:
                print("- there was a problem while sending code to email , try again later please /")
                print(send_secure_mood.text)
                close()
            code = str(input("- Enter Code here : "))

            code_data = {
                'security_code': code
            }
            sendcode = req.post(link, headers=log_head, data=code_data, cookies=cookies)

            if 'CHALLENGE_REDIRECTION' in sendcode.text:
                print("- logged in Seccessfully !")
                pass
            elif 'This field is required.' in sendcode.text:
                print("- enter the code man , what's wrong with you !")
                clear()
                secure()
            elif 'Please check the code we sent you and try again.' in sendcode.text:
                print("- the Code you entered is wrong please check it and try again !")
                clear()
                secure()
            else:
                print("- There was error while sending code , check the response down /")
                print(sendcode.text)

        elif ask == 1:
            secure_data = {
                'choice': 1
            }
            send_secure_mood = req.post(link, headers=log_head, data=secure_data, cookies=cookies)

            if send_secure_mood.status_code == 200:
                print(f"- Code Seccessfully sent to : {email}")
                pass
            else:
                print("- there was a problem while sending code to email , try again later please /")
                print(send_secure_mood.text)
                close()
            code = str(input("- Enter Code here : "))

            code_data = {
                'security_code': code
            }
            sendcode = req.post(link, headers=log_head, data=code_data, cookies=cookies)

            if 'CHALLENGE_REDIRECTION' in sendcode.text:
                print("- logged in Seccessfully !")
                pass
            elif 'This field is required.' in sendcode.text:
                print("- enter the code man , what's wrong with you !")
                clear()
                secure()
            elif 'Please check the code we sent you and try again.' in sendcode.text:
                print("- the Code you entered is wrong please check it and try again !")
                clear()
                secure()
            else:
                print("- There was error while sending code , check the response down /")
                print(sendcode.text)
        else:
            print("- bad input , it's just 0 or 1 !")
            close()
    elif 'phone' in secureJS['fields'] and 'email' not in secureJS['fields']:
        print("- your Account have no email , please link an email to continue and try again")
    elif 'email' in secureJS['fields'] and 'phone' not in secureJS['fields']:
        email = secureJS['fields']['email']
        secure_data = {
            'choice': 1
        }
        send_secure_mood = req.post(link, headers=log_head, data=secure_data, cookies=cookies)

        if send_secure_mood.status_code == 200:
            print(f"- Code Seccessfully sent to : {email}")
            pass
        else:
            print("- there was a problem while sending code to email , try again later please /")
            print(send_secure_mood.text)
            close()

        code = str(input("- Enter Code here : "))

        code_data = {
            'security_code': code
        }
        sendcode = req.post(link, headers=log_head, data=code_data, cookies=cookies)

        if 'CHALLENGE_REDIRECTION' in sendcode.text:
            print("- logged in Seccessfully !")
            pass
        elif 'This field is required.' in sendcode.text:
            print("- enter the code man , what's wrong with you !")
            clear()
            secure()
        elif 'Please check the code we sent you and try again.' in sendcode.text:
            print("- the Code you entered is wrong please check it and try again !")
            clear()
            secure()
        else:
            print("- There was error while sending code , check the response down /")
            print(sendcode.text)
    else:
        print("- your Account have no data to solve the secure ! , please link an email to continue and try again")
        close()

def login():

    if 'userId' in log.text:
        print("- logged in Successfully")
    elif '"user":false,"authenticated":false' in log.text:
        print("Check Your Username PACA !")
        close()
    elif '"user":true,"authenticated":false' in log.text:
        print("Check Your Password PACA !")
        close()
    elif 'checkpoint_required' in log.text:
        secure()
        session_id()
    elif 'two_factor_required":true' in log.text:
        two_factor()
        session_id()
    else:
        print('- Something Went down check the response /')
        print(log.text)

login()
