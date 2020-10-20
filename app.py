import graphene
import requests
from fastapi import FastAPI
from starlette.graphql import GraphQLApp
from pydantic import BaseModel
from fastapi.security import PA
from pycognito import Cognito

u = Cognito("eu-west-1_evU2XlBPg", "5p05ojqacsr782fouu3nv0hm1r",client_secret="password1234", username="jorn.lomax@hubbub.net")

from gateway.auth import get_jwks, JWTBearer, jwks


class User(BaseModel):
    username: str
    email: str
    disabled: bool


class RoomType(graphene.ObjectType):
    id = graphene.Int()
    capacity = graphene.Int()
    faculty = graphene.String()
    projector = graphene.Boolean()
    booked = graphene.Boolean()


class RoomBookingType(graphene.ObjectType):
    room = graphene.Field(RoomType)
    booked_by = graphene.Int()
    booking_date = graphene.DateTime()
    notes = graphene.String()


class Query(graphene.ObjectType):
    rooms = graphene.List(RoomType)
    room = graphene.Field(RoomType, id=graphene.Int(required=True))

    def resolve_rooms(self, info):
        data = requests.get("https://hubbub-room-api.herokuapp.com/rooms/").json()
        return data['results']

    def resolve_room(self, info, id=None):
        return requests.get(f"https://hubbub-room-api.herokuapp.com/rooms/{id}/").json()



app = FastAPI()


app.add_route('/', GraphQLApp(schema=graphene.Schema(query=Query)))