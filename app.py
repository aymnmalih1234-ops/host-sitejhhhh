# ------------------------------------------------------------
# Free Fire Account Info API — Credit: @SENKU_CODEX
# Modified: Added ME Server Support
# JOIN    : @SENKU_CODEX  FOR MORE SRC | API | BOT CODE | METHOD | 🛐
# Purpose : Fetch Free Fire profile details using UID (JWT + AES)
# Note    : THIS CODE MADE BY SENKU_CODEX — KEEP CREDIT
# Endpoint: /info?uid=<PLAYER_UID>&region=<REGION>
# Example : /info?uid=12345678&region=ME
# Regions Supported : IND | BD | PK | ME
# License : Personal / internal use only — retain credit when sharing
# ------------------------------------------------------------

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import time
import threading
import json
import base64

# استيراد ملفات Protobuf المحدثة
try:
    from data_pb2 import AccountPersonalShowInfo
    from uid_generator_pb2 import uid_generator
    from google.protobuf.json_format import MessageToDict
    print("✅ Protobuf files imported successfully")
except ImportError as e:
    print(f"❌ Error importing protobuf files: {e}")
    print("⚠️  Make sure data_pb2.py and uid_generator_pb2.py are in the same directory")
    exit(1)

app = Flask(__name__)
jwt_token = None
jwt_lock = threading.Lock()

# ---------------- JWT HANDLING ----------------
def extract_token_from_response(data, region):
    """Safely extract JWT token from API response."""
    if not isinstance(data, dict):
        return None
    
    # New API format
    if data.get("success") is True and "token" in data:
        return data["token"]
    
    # Fallback for older formats
    if region == "IND":
        if data.get('status') in ['success', 'live']:
            return data.get('token')
    elif region in ["BD", "PK", "ME"]:
        if 'token' in data:
            return data['token']
    
    return None

def get_jwt_token_sync(region):
    """Fetch JWT token synchronously for a region."""
    global jwt_token
    
    # تعريف التوكنات لكل منطقة (يمكن تغييرها حسب الحاجة)
    endpoints = {
        "IND": "https://raihan-access-to-jwt.vercel.app/token?uid=4344656844&password=RAIHANHACKER01",
        "BD": "https://raihan-access-to-jwt.vercel.app/token?uid=4363457346&password=SENKU_692491",
        "PK": "https://raihan-access-to-jwt.vercel.app/token?uid=4363456802&password=SENKU_692458",
        "ME": "https://raihan-access-to-jwt.vercel.app/token?uid=4339385508&password=C30D723A75D3ADF00760F620A03F123A222CF7B4B14689F4BACD6E050C8817A8",
        "default": "https://raihan-access-to-jwt.vercel.app/token?uid=4339385508&password=C30D723A75D3ADF00760F620A03F123A222CF7B4B14689F4BACD6E050C8817A8"
    }
    
    # إذا لم تكن المنطقة مدعومة، استخدم الافتراضي
    if region not in endpoints:
        region = "default"
    
    url = endpoints.get(region)
    
    with jwt_lock:
        try:
            print(f"[JWT] Fetching token for region: {region}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            print(f"[JWT] Raw response: {json.dumps(data, indent=2)[:200]}...")
            
            token = extract_token_from_response(data, region)
            if token:
                jwt_token = token
                print(f"[JWT] ✅ Token for {region} updated: {token[:30]}...")
                return jwt_token
            else:
                print(f"[JWT] ❌ Failed to extract token from response")
                print(f"[JWT] Response keys: {list(data.keys()) if isinstance(data, dict) else 'Not a dict'}")
                
        except Exception as e:
            print(f"[JWT] ❌ Request error for {region}: {e}")
    
    return None

def ensure_jwt_token_sync(region):
    """Ensure JWT token is available; fetch if missing."""
    global jwt_token
    if not jwt_token:
        print(f"[JWT] Token missing for {region}. Fetching...")
        return get_jwt_token_sync(region)
    return jwt_token

def jwt_token_updater(region):
    """Background thread to refresh JWT every 5 minutes."""
    while True:
        get_jwt_token_sync(region)
        time.sleep(300)

# ---------------- API ENDPOINTS ----------------
def get_api_endpoint(region):
    """Get API endpoint for the specified region."""
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",  # Middle East Server
        "default": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    }
    
    # إذا لم تكن المنطقة مدعومة، استخدم الافتراضي
    if region not in endpoints:
        print(f"[API] Region {region} not found, using default")
        region = "default"
    
    endpoint = endpoints.get(region)
    print(f"[API] Using endpoint for {region}: {endpoint}")
    return endpoint

# ---------------- AES ENCRYPTION ----------------
# مفاتيح AES الافتراضية
default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key=default_key, iv=default_iv):
    """Encrypt hex data using AES CBC."""
    try:
        key = key.encode()[:16]
        iv = iv.encode()[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # تحويل hex إلى bytes
        data_bytes = bytes.fromhex(hex_data)
        
        # تطبيق padding
        padded_data = pad(data_bytes, AES.block_size)
        
        # التشفير
        encrypted_data = cipher.encrypt(padded_data)
        
        # تحويل إلى hex
        return binascii.hexlify(encrypted_data).decode()
        
    except Exception as e:
        print(f"[AES] ❌ Encryption error: {e}")
        raise

# ---------------- API CALL ----------------
def apis(idd, region):
    """Make API call to Free Fire server."""
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB51',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': endpoint.split('/')[2]  # استخراج الـ host من الـ URL
    }
    
    try:
        print(f"[API] Calling endpoint: {endpoint}")
        print(f"[API] Data length: {len(idd)} bytes")
        
        # تحويل hex string إلى bytes
        data = bytes.fromhex(idd)
        
        # إرسال الطلب
        response = requests.post(
            endpoint, 
            headers=headers, 
            data=data, 
            timeout=15,
            verify=False
        )
        
        print(f"[API] Response status: {response.status_code}")
        print(f"[API] Response length: {len(response.content)} bytes")
        
        if response.status_code != 200:
            print(f"[API] ❌ Error response: {response.text[:200]}")
            response.raise_for_status()
        
        # تحويل الرد إلى hex
        hex_response = response.content.hex()
        print(f"[API] ✅ Success! Response hex length: {len(hex_response)}")
        
        return hex_response
        
    except requests.exceptions.RequestException as e:
        print(f"[API] ❌ Request to {endpoint} failed: {e}")
        raise
    except Exception as e:
        print(f"[API] ❌ Unexpected error: {e}")
        raise

# ---------------- FLASK ROUTES ----------------
@app.route('/info', methods=['GET'])
def get_player_info():
    """Main endpoint to get player info."""
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'IND').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # التحقق من صحة UID
        if not uid.isdigit():
            return jsonify({"error": "UID must be numeric"}), 400
        
        # المناطق المدعومة (تمت إضافة ME)
        supported_regions = ["IND", "BD", "PK", "ME"]
        
        if region not in supported_regions:
            return jsonify({
                "error": f"Region '{region}' not supported.",
                "supported_regions": supported_regions,
                "example": "/info?uid=12345678&region=ME"
            }), 400
        
        print(f"\n" + "="*60)
        print(f"[INFO] Request received - UID: {uid}, Region: {region}")
        print("="*60)
        
        # بدء تحديث التوكن في الخلفية
        threading.Thread(target=jwt_token_updater, args=(region,), daemon=True).start()
        
        # 1. إنشاء protobuf message
        print(f"[PROTOBUF] Creating protobuf message...")
        message = uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        
        # 2. Serialize to bytes
        protobuf_data = message.SerializeToString()
        print(f"[PROTOBUF] Serialized data length: {len(protobuf_data)} bytes")
        
        # 3. Convert to hex
        hex_data = binascii.hexlify(protobuf_data).decode()
        print(f"[PROTOBUF] Hex data length: {len(hex_data)} chars")
        
        # 4. تشفير البيانات
        print(f"[AES] Encrypting data...")
        encrypted_hex = encrypt_aes(hex_data)
        print(f"[AES] Encrypted hex length: {len(encrypted_hex)} chars")
        
        # 5. استدعاء الـ API
        print(f"[API] Making API call...")
        api_response = apis(encrypted_hex, region)
        
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        print(f"[API] Received response, parsing...")
        
        # 6. Parse the response
        response_bytes = bytes.fromhex(api_response)
        
        # 7. Parse protobuf response
        message = AccountPersonalShowInfo()
        message.ParseFromString(response_bytes)
        
        # 8. Convert to dictionary
        result = MessageToDict(message, preserving_proto_field_name=True)
        
        # 9. إضافة معلومات إضافية
        result['api_info'] = {
            'query': {
                'uid': uid,
                'region': region,
                'timestamp': time.time(),
                'timestamp_human': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'owners': ['SENKU CODEX'],
            'supported_regions': supported_regions,
            'version': '2.0 (ME Support Added)'
        }
        
        print(f"[INFO] ✅ Success! Returning data...")
        print("="*60 + "\n")
        
        return jsonify(result)
    
    except ValueError as e:
        print(f"[ERROR] ValueError: {e}")
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"[ERROR] ❌ Processing request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

@app.route('/status', methods=['GET'])
def status_check():
    """Check API status and supported regions."""
    return jsonify({
        "status": "active",
        "timestamp": time.time(),
        "timestamp_human": time.strftime('%Y-%m-%d %H:%M:%S'),
        "supported_regions": ["IND", "BD", "PK", "ME"],
        "endpoints": {
            "player_info": "/info?uid=<PLAYER_UID>&region=<REGION>",
            "status": "/status",
            "test": "/test"
        },
        "examples": {
            "middle_east": "http://localhost:5000/info?uid=4343242672&region=ME",
            "india": "http://localhost:5000/info?uid=12345678&region=IND",
            "bangladesh": "http://localhost:5000/info?uid=12345678&region=BD",
            "pakistan": "http://localhost:5000/info?uid=12345678&region=PK"
        }
    })

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Test endpoint with example data."""
    test_uid = "4343242672"  # UID من مثالك
    test_region = "ME"
    
    return jsonify({
        "message": "Test endpoint",
        "test_data": {
            "uid": test_uid,
            "region": test_region,
            "test_url": f"http://localhost:5000/info?uid={test_uid}&region={test_region}"
        },
        "instructions": "Use the test URL above to test the API"
    })

@app.route('/favicon.ico')
def favicon():
    return '', 404

@app.route('/')
def index():
    return jsonify({
        "message": "Free Fire Account Info API - SENKU CODEX (Modified with ME Support)",
        "description": "Fetch Free Fire player profile information by UID",
        "endpoint": "/info?uid=PLAYER_UID&region=REGION",
        "supported_regions": ["IND", "BD", "PK", "ME"],
        "examples": [
            "/info?uid=4343242672&region=ME",
            "/info?uid=12345678&region=IND",
            "/info?uid=87654321&region=BD",
            "/info?uid=55555555&region=PK"
        ],
        "status_check": "/status",
        "test": "/test",
        "note": "Keep credit to @SENKU_CODEX when sharing"
    })

# ---------------- UTILITY FUNCTIONS ----------------
def test_protobuf():
    """Test protobuf functionality."""
    try:
        print("🧪 Testing Protobuf functionality...")
        
        # Test uid_generator
        message = uid_generator()
        message.saturn_ = 12345678
        message.garena = 1
        
        data = message.SerializeToString()
        print(f"✅ uid_generator test passed - Serialized {len(data)} bytes")
        
        # Test AccountPersonalShowInfo (empty)
        message2 = AccountPersonalShowInfo()
        data2 = message2.SerializeToString()
        print(f"✅ AccountPersonalShowInfo test passed - Serialized {len(data2)} bytes")
        
        return True
    except Exception as e:
        print(f"❌ Protobuf test failed: {e}")
        return False

# ---------------- MAIN ----------------
if __name__ == "__main__":
    print("=" * 70)
    print("🎮 FREE FIRE ACCOUNT INFO API")
    print("📱 MIDDLE EAST (ME) SERVER SUPPORT ADDED!")
    print("=" * 70)
    
    # اختبار ملفات Protobuf
    if not test_protobuf():
        print("❌ Protobuf test failed. Exiting...")
        exit(1)
    
    # جلب التوكن الأولي للمنطقة الافتراضية
    print("\n🔑 Initializing JWT token...")
    ensure_jwt_token_sync("IND")
    
    print("\n🌍 Supported Regions: IND, BD, PK, ME")
    print("📝 Example Requests:")
    print("  http://localhost:5000/info?uid=4343242672&region=ME")
    print("  http://localhost:5000/info?uid=12345678&region=IND")
    print("\n📊 Status Check: http://localhost:5000/status")
    print("🧪 Test: http://localhost:5000/test")
    print("=" * 70)
    print("🚀 Starting Flask server on http://0.0.0.0:5000")
    print("=" * 70)
    
    # تشغيل السيرفر
    app.run(
        host="0.0.0.0", 
        port=5000, 
        debug=True,
        threaded=True
    )
