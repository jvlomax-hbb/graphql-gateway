from typing import List, Dict
import requests
from jose import jwt, jwk, JWTError
from jwt.utils import base64url_decode
from pydantic import BaseModel
from fastapi import HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_401_UNAUTHORIZED
POOL_ID = "eu-west-1_evU2XlBPg"

JWK = Dict[str, str]


class JWKS(BaseModel):
    keys: List[JWK]


class JWTAuthorizationCredentials(BaseModel):
    jwt_token: str
    header: Dict[str, str]
    claims: Dict[str, str]
    signature: str
    message: str



class JWTBearer(HTTPBearer):
    def __init__(self, jwks, auto_error=True):
        super().__init__(auto_error=auto_error)
        self.kid_to_jwk = {jwk["kid"]: jwk for jwk in jwks.keys}

    def verify_jwk_token(self, jwt_credentials):
        try:
            public_key = self.kid_to_jwk[jwt_credentials.header['kid']]
        except KeyError:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="JWT public key not found")

        key = jwk.construct(public_key)
        decoded_signature = base64url_decode(jwt_credentials.signature.encode())
        return key.verify(jwt_credentials.message.encode(), decoded_signature)


    def __call__(self, request):
        credentials: HTTPAuthorizationCredentials = super().__call__(request)

        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Incorrect auth mode")
            jwt_token = credentials.credentials
            message, signature = jwt_token.rsplit(".", 1)
            try:
                jwt_credentials = JWTAuthorizationCredentials(
                    jwt_token=jwt_token,
                    header=jwt.get_unverified_header(jwt_token),
                    claims=jwt.get_unverified_claims(jwt_token),
                    signature=signature,
                    message=message,
                )
            except JWTError:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="JWK invalid")

            if not self.verify_jwk_token(jwt_credentials):
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="JWK invalid")

def get_jwks():
    data = requests.get(f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL_ID}/.well-known/jwks.json").json()
    return data


def get_hmac_key(token, jwks):
    kid = jwt.get_unverified_header(token).get('kid')
    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
            return key


def verify_jwt(token, jwks):
    hmac_key = get_hmac_key(token, jwks)
    if not hmac_key:
        raise ValueError("No public key found")
    hmac_key = jwk.construct(get_hmac_key(token, jwks))

    message, encoded_signature = token.rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode())
    return hmac_key.verify(message.encode(), decoded_signature)


jwks = JWKS.parse_obj(
    requests.get(f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL_ID}/.well-known/jwks.json").json()
)