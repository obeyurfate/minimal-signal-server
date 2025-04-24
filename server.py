from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
import base64
import uuid
import uvicorn
import time
from datetime import datetime

app = FastAPI(title="Signal API Stub")

# In-memory storage for users, devices, keys, and messages
users = {}  # {number: {"uuid": str, "password": str, "devices": list, "keys": dict}}
messages = {}  # {recipient_id: list of messages}


# Models for request/response validation
class SmsCodeRequest(BaseModel):
    number: str
    androidSmsRetrieverSupported: bool
    captcha: Optional[str] = None
    challenge: Optional[str] = None


class VerifyAccountRequest(BaseModel):
    number: str
    signalingKey: str
    registrationId: int
    fetchesMessages: bool


class PreKey(BaseModel):
    keyId: int
    publicKey: str


class SignedPreKey(BaseModel):
    keyId: int
    publicKey: str
    signature: str


class SetPreKeysRequest(BaseModel):
    identityKey: str
    signedPreKey: SignedPreKey
    lastResortKey: PreKey
    oneTimePreKeys: List[PreKey]


class DeviceLinkRequest(BaseModel):
    deviceLinkingCode: str


class DataMessageRequest(BaseModel):
    destination: str
    deviceId: int
    messageType: str
    content: str
    body: Optional[str] = None
    timestamp: Optional[int] = None
    attachments: Optional[List[dict]] = None


class MessageResponse(BaseModel):
    timestamp: int


class DeviceInfo(BaseModel):
    id: int
    name: str
    lastSeen: int


class VerifyAccountResponse(BaseModel):
    uuid: str
    number: str
    deviceId: int
    registered: bool


class PreKeyBundleResponse(BaseModel):
    identityKey: str
    signedPreKey: SignedPreKey
    preKey: PreKey


class DeviceLinkResponse(BaseModel):
    deviceId: int
    uuid: str


class Message(BaseModel):
    source: str
    sourceDevice: int
    timestamp: int
    type: str
    content: str


# Helper function to validate Basic Auth
def validate_auth(authorization: str, expected_number: str = None):
    if not authorization.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Invalid authorization")
    try:
        decoded = base64.b64decode(authorization[6:]).decode().split(":")
        number, password = decoded[0], decoded[1]
        if expected_number and number != expected_number:
            raise HTTPException(status_code=401, detail="Unauthorized number")
        if number not in users:
            raise HTTPException(status_code=401, detail="User not found")
        if users[number]["password"] != password:
            raise HTTPException(status_code=401, detail="Invalid password")
        return number
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authorization")


# Registration: Request SMS code
@app.post("/v1/accounts/sms/code")
async def request_sms_code(request: SmsCodeRequest):
    return {}


# Registration: Verify account
@app.put("/v1/accounts/code/{verification_code}")
async def verify_account(verification_code: str, request: VerifyAccountRequest):
    if len(verification_code) != 6 or not verification_code.isdigit():
        raise HTTPException(status_code=400, detail="Invalid verification code")
    if request.number in users:
        raise HTTPException(status_code=409, detail="User already exists")

    user_uuid = str(uuid.uuid4())
    users[request.number] = {
        "uuid": user_uuid,
        "password": str(uuid.uuid4()),  # Random password for Basic Auth
        "devices": [{"id": 1, "name": "Primary Device", "lastSeen": int(time.time() * 1000)}],
        "keys": {},
        "signalingKey": request.signalingKey,
        "registrationId": request.registrationId
    }

    return VerifyAccountResponse(
        uuid=user_uuid,
        number=request.number,
        deviceId=1,
        registered=True
    )


# Registration: Set pre-keys
@app.put("/v2/keys")
async def set_pre_keys(request: SetPreKeysRequest, authorization: str = Header(...)):
    number = validate_auth(authorization)
    users[number]["keys"] = request.dict()
    return {}


# Device Authorization: Get devices
@app.get("/v1/devices", response_model=List[DeviceInfo])
async def get_devices(authorization: str = Header(...)):
    number = validate_auth(authorization)
    return users[number]["devices"]


# Device Authorization: Add device
@app.post("/v1/devices/link", response_model=DeviceLinkResponse)
async def add_device(request: DeviceLinkRequest, authorization: str = Header(...)):
    number = validate_auth(authorization)
    new_device_id = max([d["id"] for d in users[number]["devices"]]) + 1
    users[number]["devices"].append({
        "id": new_device_id,
        "name": f"Device {new_device_id}",
        "lastSeen": int(time.time() * 1000)
    })
    return DeviceLinkResponse(deviceId=new_device_id, uuid=users[number]["uuid"])


# Device Authorization: Request sync
@app.post("/v1/sync/devices")
async def request_sync(authorization: str = Header(...)):
    validate_auth(authorization)
    return {}


# Session Creation: Get pre-key bundle
@app.get("/v2/keys/{recipient_id}/{device_id}", response_model=PreKeyBundleResponse)
async def get_pre_key_bundle(recipient_id: str, device_id: int, authorization: str = Header(...)):
    number = validate_auth(authorization)
    for user_number, user_data in users.items():
        if user_data["uuid"] == recipient_id:
            if not user_data["keys"]:
                raise HTTPException(status_code=404, detail="Keys not found")
            return PreKeyBundleResponse(
                identityKey=user_data["keys"]["identityKey"],
                signedPreKey=user_data["keys"]["signedPreKey"],
                preKey=user_data["keys"]["oneTimePreKeys"][0]
            )
    raise HTTPException(status_code=404, detail="Recipient not found")


# Session Creation: Send pre-key message
@app.put("/v1/messages/{recipient_id}", response_model=MessageResponse)
async def send_prekey_message(recipient_id: str, request: DataMessageRequest, authorization: str = Header(...)):
    number = validate_auth(authorization)
    if request.messageType != "PREKEY_BUNDLE":
        raise HTTPException(status_code=400, detail="Invalid message type")
    timestamp = int(time.time() * 1000)
    if recipient_id not in messages:
        messages[recipient_id] = []
    messages[recipient_id].append({
        "source": users[number]["uuid"],
        "sourceDevice": request.deviceId,
        "timestamp": timestamp,
        "type": request.messageType,
        "content": request.content
    })
    return MessageResponse(timestamp=timestamp)


# Messaging: Send message
@app.put("/v1/messages/{recipient_id}", response_model=MessageResponse)
async def send_message(recipient_id: str, request: DataMessageRequest, authorization: str = Header(...)):
    number = validate_auth(authorization)
    if request.messageType != "DATA_MESSAGE":
        raise HTTPException(status_code=400, detail="Invalid message type")
    timestamp = int(time.time() * 1000)
    if recipient_id not in messages:
        messages[recipient_id] = []
    messages[recipient_id].append({
        "source": users[number]["uuid"],
        "sourceDevice": request.deviceId,
        "timestamp": timestamp,
        "type": request.messageType,
        "content": request.content
    })
    return MessageResponse(timestamp=timestamp)


# Messaging: Receive messages
@app.get("/v1/messages", response_model=List[Message])
async def receive_messages(authorization: str = Header(...)):
    number = validate_auth(authorization)
    user_uuid = users[number]["uuid"]
    user_messages = messages.get(user_uuid, [])
    messages[user_uuid] = []  # Clear messages after retrieval
    return user_messages


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)