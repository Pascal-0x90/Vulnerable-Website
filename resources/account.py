#!/usr/bin/env python3

from flask import Response, request
from flask_jwt_extended import create_access_token
from database.models import User
from flask_restful import Resource
import datetime
from mongoengine.errors import FieldDoesNotExist, NotUniqueError, DoesNotExist
from resources.errors import SchemaValidationError, EmailAlreadyExistsError, UnauthorizedError, \
InternalServerError

class Account(Resource):
    def get(self):
        #body = request.get_json()
        query = User.objects()
        users = User.objects().to_json()
        return Response(users, mimetype="application/json", status=200)
