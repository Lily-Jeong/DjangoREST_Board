from django.contrib.auth.models import User #User model
from django.contrib.auth.password_validation import validate_password   # Django 기본 pw validation tool
from django.contrib.auth import authenticate    # basic authentication function in Django.

from rest_framework import serializers
from rest_framework.authtoken.models import Token   # Token model
from rest_framework.validators import UniqueValidator   # prevent using same e-mail address.

from .models import Profile

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],   # check if the email already exists
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password], # password validation
    )
    password2 = serializers.CharField(write_only=True, required=True)   # password checking

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email')

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match/."})

        return data

    def create(self, validated_data):
        # CREATE request -> overriding "create" method, creating user and token
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
        )

        user.set_password(validated_data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    # write_only option: client->server deserializing (O) / server -> client serializing (X)

    def validation(self, data):
        user = authenticate(**data)
        if user:
            token = Token.objects.get(user=user)    #find user through token
            return token
        raise serializers.ValidationError(
            {"error": "Unable to log in with provided credentials"}
        )

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ("nickname", "position", "subjects", "image")