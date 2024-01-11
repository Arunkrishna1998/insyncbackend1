import os
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import AuthenticationFailed
from post.serializers import FollowSerializer

class InvalidToken(AuthenticationFailed):
    status_code = 400
    default_detail = "Invalid token"
    default_code = 'invalid'

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        if user.is_active:
            token = super().get_token(user)
            return token
        else:
            if user.is_online:
                # User is not online, customize the response or raise an exception
                raise InvalidToken("Your account has been blocked.")
            else:
                raise InvalidToken("Please verify your email id.")
        

User = get_user_model()

class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'age', 'password']

    def validate(self, data):
        user = User(**data)
        password = data.get('password')
        try:
            validate_password(password, user)
        except exceptions.ValidationError as e:
            serializer_errors = serializers.as_serializer_error(e)
            raise exceptions.ValidationError(
                {'password': serializer_errors['non_field_errors']}
            )
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            email = validated_data['email'],
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            age = validated_data['age'],
            password = validated_data['password'],
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    follower_count = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()
    followers = serializers.SerializerMethodField()
    following = serializers.SerializerMethodField()
    reported_posts_count = serializers.SerializerMethodField()

    def get_follower_count(self, obj):
        return obj.get_follower_count()

    def get_following_count(self, obj):
        return obj.get_following_count()

    def get_followers(self, obj):
        followers = obj.followers.all()
        follower_serializer = FollowSerializer(followers, many=True)
        return follower_serializer.data

    def get_following(self, obj):
        following = obj.following.all()
        following_serializer = FollowSerializer(following, many=True)
        return following_serializer.data
    
    def get_reported_posts_count(self, obj):
        return obj.reported_posts.count()
    
    def validate_profile_image(self, value):
        max_size = 1.5 * 1024 * 1024  # 1.5 MB in bytes

        if value.size > max_size:
            raise serializers.ValidationError('The image size should not exceed 1.5 MB.')

        valid_extensions = ['.jpg', '.jpeg', '.png', '.svg']
        ext = os.path.splitext(value.name)[1].lower()

        if ext not in valid_extensions:
            raise serializers.ValidationError('Invalid image file type. Supported formats: jpg, jpeg, png, svg.')

        return value

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'age', 'is_superuser', 'is_active', 'is_online', 
                  'gender', 'profile_image', 'follower_count', 'following_count', 'followers', 'following', 
                  'country', 'education', 'work', 'reported_posts_count', 'set_interest']
       


class UserAdminSerializer(serializers.ModelSerializer):
    follower_count = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()
    reported_posts_count = serializers.SerializerMethodField()

    def get_follower_count(self, obj):
        return obj.get_follower_count()

    def get_following_count(self, obj):
        return obj.get_following_count()
    
    def get_reported_posts_count(self, obj):
        return obj.reported_posts.count()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'age', 'is_superuser', 'is_active',
                  'profile_image', 'follower_count', 'following_count', 'reported_posts_count']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )
    confirm_new_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )

    def validate(self, data):
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')

        if new_password != confirm_new_password:
            raise serializers.ValidationError("Passwords do not match.")

        if len(new_password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")

        if ' ' in new_password:
            raise serializers.ValidationError("Password cannot contain spaces.")

        return data