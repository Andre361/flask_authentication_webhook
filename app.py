import os
import jwt
import json
import logging
import requests
from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from typing import Optional
from dataclasses import dataclass, asdict
from dotenv import load_dotenv
load_dotenv()

# HASURA_URL = "http://graphql-engine:8080/v1/graphql"
HASURA_URL = os.getenv("HASURA_URL")
HASURA_HEADERS = {
    "X-Hasura-Admin-Secret": os.environ.get("HASURA_GRAPHQL_ADMIN_SECRET")}
HASURA_JWT_SECRET = os.getenv(
    "HASURA_GRAPHQL_JWT_SECRET", "a-very-secret-secret")

################
# GRAPHQL CLIENT
################


@dataclass
class Client:
    url: str
    headers: dict

    def run_query(self, query: str, variables: dict, extract=False):
        request = requests.post(
            self.url,
            headers=self.headers,
            json={"query": query, "variables": variables},
        )
        assert request.ok, f"Failed with code {request.status_code}"
        return request.json()

    def find_user_by_email(self, email): return self.run_query(
        """
            query UserByEmail($email: String!) {
                users(where: {email: {_eq: $email}}, limit: 1) {
                    id
                    email
                    password
                }
            }
        """,
        {"email": email},
    )

    def create_user(self, username, email, password): return self.run_query(
        """
            mutation CreateUser($username:String!, $email: String!, $password: String!) {
                insert_users_one(object: {username:$username, email: $email, password: $password}) {
                    id
                    username
                    email
                    password
                }
            }
        """,
        {"email": email, "password": password, "username": username},
    )

    def update_password(self, id, password): return self.run_query(
        """
            mutation UpdatePassword($id: Int!, $password: String!) {
                update_users_by_pk(pk_columns: {id: $id}, _set: {password: $password}) {
                    password
                }
            }
        """,
        {"id": id, "password": password},
    )

#######
# UTILS
#######


Password = PasswordHasher()
client = Client(url=HASURA_URL, headers=HASURA_HEADERS)

# ROLE LOGIC FOR DEMO PURPOSES ONLY
# NOT AT ALL SUITABLE FOR A REAL APP


def generate_token(user) -> str:
    """
    Generates a JWT compliant with the Hasura spec, given a User object with field "id"
    """
    user_roles = ["user"]
    admin_roles = ["user", "admin"]
    is_admin = user["email"] == "admin@site.com"
    payload = {
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": admin_roles if is_admin else user_roles,
            "x-hasura-default-role": "admin" if is_admin else "user",
            "x-hasura-user-id": user["id"],
        }
    }

    # def prepare_key(key):
    #     return jwt.utils.force_bytes(key)
    # jwt.api_jws._jws_global_obj._algorithms['HS256'].prepare_key = prepare_key
    # public_key = open('pubkey.pem', 'r').read()

    token = jwt.encode(payload, HASURA_JWT_SECRET,
                       "HS256")
    return token.decode("utf-8")


def rehash_and_save_password_if_needed(user, plaintext_password):
    if Password.check_needs_rehash(user["password"]):
        client.update_password(user["id"], Password.hash(plaintext_password))


#############
# DATA MODELS
#############

@dataclass
class RequestMixin:
    @classmethod
    def from_request(cls, request):
        """
        Helper method to convert an HTTP request to Dataclass Instance
        """
        values = request.get("input")
        return cls(**values)

    def to_json(self):
        return json.dumps(asdict(self))


@dataclass
class CreateUserOutput(RequestMixin):
    id: int
    email: str
    password: str
    username: str


@dataclass
class JsonWebToken(RequestMixin):
    token: str


@dataclass
class AuthArgs(RequestMixin):
    email: str
    password: str
    username: Optional[str]


@dataclass
class LoginArgs(RequestMixin):
    email: str
    password: str

##############
# MAIN SERVICE
##############


app = Flask(__name__)


@app.route('/')
def home():
    return {"message": "welcome"}


@app.route("/signup", methods=["POST"])
def signup_handler():
    args = AuthArgs.from_request(request.get_json())
    hashed_password = Password.hash(args.password)
    user_response = client.create_user(
        args.username, args.email, hashed_password)
    if user_response.get("errors"):
        return {"message": user_response["errors"][0]["message"]}, 400
    else:
        user = user_response["data"]["insert_users_one"]
        return CreateUserOutput(**user).to_json()


@app.route("/login", methods=["POST"])
def login_handler():
    args = LoginArgs.from_request(request.get_json())
    user_response = client.find_user_by_email(args.email)
    user = user_response["data"]["users"][0]
    try:
        Password.verify(user.get("password"), args.password)
        rehash_and_save_password_if_needed(user, args.password)
        return JsonWebToken(generate_token(user)).to_json()
    except VerifyMismatchError:
        return {"message": "Invalid credentials"}, 401


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
