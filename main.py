import hashlib
import hmac
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import binascii
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import jwt
import json
import os
import threading
import time
import my_pb2
import output_pb2
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Configuration - এখানে সবকিছু সেট করে দিন
CONFIG = {
    "TOTAL_ACCOUNTS": 10000,  # কতগুলো অ্যাকাউন্ট তৈরি করতে চান (এখানে 1000 সেট করা আছে)
    "ACCOUNT_NAME": "GHOST_X",  # অ্যাকাউন্টের নাম (8 ক্যারেক্টারের কম হতে হবে)
    "FILENAME": "freefire_accounts",  # ফাইলের নাম (.json অটোমেটিক যুক্ত হবে)
    "THREAD_COUNT": 50,  # একসাথে কতগুলো থ্রেড চালাতে চান
}

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def run(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return
    access_token = token_data['access_token']
    open_id = token_data['open_id']
    
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()  
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)  
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')  

    url = "https://loginbp.common.ggbluefox.com/MajorLogin"  
    headers = {  
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",  
        'Connection': "Keep-Alive",  
        'Accept-Encoding': "gzip",  
        'Content-Type': "application/octet-stream",  
        'Expect': "100-continue",  
        'X-Unity-Version': "2018.4.11f1",  
        'X-GA': "v1 1",  
        'ReleaseVersion': "OB50"  
    }  
    edata = bytes.fromhex(hex_encrypted_data)  

    response = requests.post(url, data=edata, headers=headers, verify=False)  
    if response.status_code == 200:  
        example_msg = output_pb2.Garena_420()  
        example_msg.ParseFromString(response.content)  
        token = example_msg.token  
        return token

class GarenaGuestAuth:
    def __init__(self, name, filename):
        self.name = name
        self.filename = filename
        self.secretKey = b'2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3'
        self.superscript_digits = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹']
        random_num = random.randint(1, 9999)
        self.passwordRaw = f"{self.name}{''.join(self.superscript_digits[int(d)] for d in str(random_num))}"
        self.actual_password = f"JOBAYAR_{random.randint(1000000000, 9999999999)}"
        self.session = requests.Session()

    def hashPassword(self):  
        return hashlib.sha256(self.actual_password.encode()).hexdigest().upper()  

    def enc_var(self, number):  
        encoded_bytes = []  
        while True:  
            byte = number & 0x7F  
            number >>= 7  
            encoded_bytes.append(byte | (0x80 if number else 0))  
            if not number:  
                break  
        return bytes(encoded_bytes)  

    def vfield(self, field_number, value):  
        return self.enc_var((field_number << 3) | 0) + self.enc_var(value)  

    def ldf(self, field_number, value):  
        encoded_value = value.encode() if isinstance(value, str) else value  
        return self.enc_var((field_number << 3) | 2) + self.enc_var(len(encoded_value)) + encoded_value  

    def taopack(self, fields):  
        packet = bytearray()  
        for field in sorted(fields.keys()):  
            value = fields[field]  
            if isinstance(value, dict):  
                packet.extend(self.ldf(field, self.taopack(value)))  
            elif isinstance(value, int):  
                packet.extend(self.vfield(field, value))  
            elif isinstance(value, (str, bytes)):  
                packet.extend(self.ldf(field, value))  
        return packet  

    def enc_api(self, plain_text):  
        plain_text = bytes.fromhex(plain_text)  
        key = b"Yg&tc%DEuh6%Zc^8"  
        iv = b"6oyZDr22E3ychjM%"  
        cipher = AES.new(key, AES.MODE_CBC, iv)  
        return cipher.encrypt(pad(plain_text, AES.block_size)).hex()  

    def taoSGT(self, data):  
        return hmac.new(self.secretKey, data.encode(), hashlib.sha256).hexdigest()  

    def enc_field_3(self, openId):  
        key = [0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0]  
        return bytes(b ^ key[i % len(key)] ^ 48 for i, b in enumerate(openId.encode()))  

    def decode_jwt(self, token):  
        try:  
            return jwt.decode(token, options={"verify_signature": False})  
        except jwt.InvalidTokenError:  
            return None  

    def save_to_file(self, data):  
        filee = f"{self.filename}.json"  
        try:  
            with lockk:  
                existing_data = []  
                if os.path.exists(filee):  
                    with open(filee, "r", encoding="utf-8") as f:  
                        existing_data = json.load(f)  
                uid = data["uid"]  
                updated = False  
                for i, entry in enumerate(existing_data):  
                    if entry.get("uid") == uid:  
                        existing_data[i] = data  
                        updated = True  
                        break  
                if not updated:  
                    existing_data.append(data)  
                with open(filee, "w", encoding="utf-8") as f:  
                    json.dump(existing_data, f, ensure_ascii=False, indent=2)  
        except Exception:  
            pass  

    def run(self):  
        try:  
            hashedPassword = self.hashPassword()  
            payloadRegister = {  
                'password': hashedPassword,  
                'client_type': '2',  
                'source': '2',  
                'app_id': '100067'  
            }  
            bodyRegister = '&'.join(f'{k}={v}' for k, v in payloadRegister.items())  
            headersRegister = {  
                'User-Agent': 'GarenaMSDK/4.0.19P9(SM-S908E ;Android 11;vi;ID;)',  
                'Authorization': f'Signature {self.taoSGT(bodyRegister)}',  
                'Content-Type': 'application/x-www-form-urlencoded',  
                'Connection': 'Keep-Alive',  
                'Accept-Encoding': 'gzip'  
            }  
            resRegister = self.session.post('https://100067.connect.garena.com/oauth/guest/register',  
                                         data=payloadRegister, headers=headersRegister, timeout=10)  
            resRegister.raise_for_status()  
            uid = str(resRegister.json()['uid'])  

            payloadToken = {  
                'uid': uid,  
                'password': hashedPassword,  
                'response_type': 'token',  
                'client_type': '2',  
                'client_secret': '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',  
                'client_id': '100067'  
            }  
            headersToken = {  
                'User-Agent': 'GarenaMSDK/4.0.19P9(SM-S908E ;Android 11;vi;ID;)',  
                'Content-Type': 'application/x-www-form-urlencoded',  
                'Connection': 'Keep-Alive',  
                'Accept-Encoding': 'gzip'  
            }  
            resToken = self.session.post('https://100067.connect.garena.com/oauth/guest/token/grant',  
                                       data=payloadToken, headers=headersToken, timeout=10)  
            resToken.raise_for_status()  
            tokenData = resToken.json()  
            accessToken = tokenData['access_token']  
            openId = tokenData['open_id']  
            encrypted_field_3 = self.enc_field_3(openId)  
            payload = {  
                1: self.passwordRaw,  
                2: accessToken,  
                3: openId,  
                5: 102000007,  
                6: 4,  
                7: 1,  
                13: 1,  
                14: encrypted_field_3,  
                15: "ID",  
                16: 1  
            }  
            payload_encrypted = self.enc_api(self.taopack(payload).hex())  
            headersMajor = {  
                "Authorization": f"Bearer {accessToken}",  
                "X-Unity-Version": "2018.4.11f1",  
                "X-GA": "v1 1",  
                "ReleaseVersion": "OB50",  
                "Content-Type": "application/octet-stream",  
                "Content-Length": str(len(bytes.fromhex(payload_encrypted))),  
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; RMX1821 Build/QP1A.190711.020)",  
                "Host": "loginbp.ggblueshark.com",  
                "Connection": "Keep-Alive",  
                "Accept-Encoding": "gzip"  
            }  
            resMajor = self.session.post('https://loginbp.ggblueshark.com/MajorRegister',  
                                       data=bytes.fromhex(payload_encrypted), headers=headersMajor, timeout=10)  
            if resMajor.status_code != 200:  
                if resMajor.status_code == 400:  
                    print("\033[39mIP has been \033[31mBlocked\033[39m, Please \033[33mChange\033[32m to New IP\033[39m. "  
          "After \033[32mIP\033[39m Changed Press \033[35mENTER\033[39m!!!")  
                    input()  
                else:  
                    print("\033[31mRegistration Error, Please Check Again!!")  
                return None  
            account_data = {  
                "access_token": accessToken,  
                "open_id": openId,  
                "name": self.passwordRaw,  
                "uid": uid,  
                "password": self.actual_password  
            }  
            token = run(account_data['uid'], hashedPassword)  
            decoded = jwt.decode(token, options={"verify_signature": False})  
            account_id = decoded.get('account_id')  
            nickname = decoded.get('nickname')  
            region = decoded.get('lock_region')  
            self.save_to_file({  
                "uid": account_data['uid'],  
                "password": hashedPassword,  
                "account_id": account_id,  
                "name": nickname,  
                "region": region  
            })  

            return account_data  
        except Exception as e:  
            return None  
        finally:  
            self.session.close()

lockk = threading.Lock()
registered_count = 0
count_lock = threading.Lock()

def startreg(target_count, name, filename):
    global registered_count
    auth = GarenaGuestAuth(name, filename)
    result = auth.run()

    if result:  
        with count_lock:  
            registered_count += 1  
            current_count = registered_count  
        print(f"\n🔄 Registration {current_count}/{target_count}")  
        print(f"👤 Name     : {result['name']}")  
        print(f"🆔 UID      : {result['uid']}")  
        print(f"🔑 Password : {result['password']}")  
        return True  
    return False

def fast_auto_registration():
    global registered_count
    registered_count = 0
    
    total_accounts = CONFIG["TOTAL_ACCOUNTS"]
    thread_count = CONFIG["THREAD_COUNT"]
    account_name = CONFIG["ACCOUNT_NAME"]
    filename = CONFIG["FILENAME"]
    
    print("🚀 Starting Fast Auto Registration...")
    print(f"📊 Target Accounts: {total_accounts}")
    print(f"⚡ Thread Count: {thread_count}")
    print(f"👤 Account Name: {account_name}")
    print(f"💾 Save File: {filename}.json")
    print("⏳ Please wait...\n")
    
    start_time = time.time()
    successful_registrations = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:  
        futures = []  
        while successful_registrations < total_accounts:  
            remaining = total_accounts - successful_registrations  
            batch_size = min(remaining, thread_count)  
            
            # Submit new batch
            for _ in range(batch_size):
                future = executor.submit(startreg, total_accounts, account_name, filename)
                futures.append(future)
            
            # Check completed futures
            for future in as_completed(futures):
                try:
                    if future.result():
                        successful_registrations += 1
                    if successful_registrations >= total_accounts:
                        break
                except Exception as e:
                    print(f"\033[31mThread error: {str(e)}\033[39m")
                futures.remove(future)
            
            # Small delay to avoid overwhelming the system
            time.sleep(0.05)

    end_time = time.time()  
    elapsed_time = end_time - start_time  

    print("\n" + "="*50)
    print("✅ AUTO REGISTRATION COMPLETED!")
    print("="*50)
    print(f"📊 Total Accounts Created : {successful_registrations}")
    print(f"⏱️ Total Time Taken      : {elapsed_time:.2f} seconds")
    print(f"📁 Accounts saved to     : {filename}.json")
    print("="*50)

if __name__ == '__main__':
    # Display configuration
    print("🔧 CURRENT CONFIGURATION:")
    print(f"   • Total Accounts: {CONFIG['TOTAL_ACCOUNTS']}")
    print(f"   • Account Name: {CONFIG['ACCOUNT_NAME']}")
    print(f"   • File Name: {CONFIG['FILENAME']}.json")
    print(f"   • Thread Count: {CONFIG['THREAD_COUNT']}")
    
    # Start immediately without any user input
    fast_auto_registration()
    
    # Exit after completion
    print("\n🎯 Process finished. Press any key to exit...")
    input()