from rest_framework import serializers
from taggit.serializers import TaggitSerializer, TagListSerializerField
from .models import Post, Comment, Follow, Notification, Interest
from users.models import User
from taggit.models import Tag
from django.forms.models import model_to_dict
from django.utils.timesince import timesince
import os

class UserSerializer(serializers.ModelSerializer):
    follower_count = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()
    followers = serializers.SerializerMethodField()
    following = serializers.SerializerMethodField()
    total_posts = serializers.SerializerMethodField()

    def get_follower_count(self, obj):
        return obj.followers.count()

    def get_following_count(self, obj):
        return obj.following.count()

    def get_followers(self, obj):
        followers = obj.followers.all()
        follower_serializer = FollowSerializer(followers, many=True)
        return follower_serializer.data

    def get_following(self, obj):
        following = obj.following.all()
        following_serializer = FollowSerializer(following, many=True)
        return following_serializer.data

    def get_total_posts(self, obj):
        return obj.post_set.filter(is_deleted=False).count()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'age', 'is_superuser', 'is_active', 'is_online', 
                  'gender', 'profile_image', 'follower_count', 'following_count', 'followers', 'following', 
                  'total_posts', 'country', 'education', 'work']


class UserNotifySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email')


class CommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    created = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Comment
        fields = [ 'id','user', 'body', 'created' ]
    
    def get_created(self, obj):
        return timesince(obj.created)


class FollowSerializer(serializers.ModelSerializer):
    following = serializers.SlugRelatedField(slug_field='email', queryset=User.objects.all())
    follower = serializers.SlugRelatedField(slug_field='email', queryset=User.objects.all())

    class Meta:
        model = Follow
        fields = ['following', 'follower']


class PostSerializer(TaggitSerializer, serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    likes_count = serializers.SerializerMethodField()
    reports_count = serializers.SerializerMethodField()
    comments = CommentSerializer(many=True, read_only=True)
    followers = serializers.SerializerMethodField()
    tags = TagListSerializerField()

    def get_likes_count(self, obj):
        return obj.total_likes()
    
    def get_reports_count(self, obj):
        return obj.total_reports()

    def get_followers(self, obj):
        followers = Follow.objects.filter(following=obj.author).select_related('follower')
        follower_serializer = FollowSerializer(instance=followers, many=True, context=self.context)
        return follower_serializer.data
    
    def validate_post_img(self, value):
        max_size = 1.5 * 1024 * 1024  # 1.5 MB in bytes

        if value.size > max_size:
            raise serializers.ValidationError('The image size should not exceed 1.5 MB.')

        valid_extensions = ['.jpg', '.jpeg', '.png', '.svg']
        ext = os.path.splitext(value.name)[1].lower()

        if ext not in valid_extensions:
            raise serializers.ValidationError('Invalid image file type. Supported formats: jpg, jpeg, png, svg.')

        return value

    class Meta:
        model = Post
        fields = ['id', 'post_img', 'content', 'created_at', 'updated_at', 'likes', 'likes_count', 'author', 
                  'comments', 'followers', 'reports_count', 'tags', 'is_deleted', 'is_blocked']


class NotificationSerializer(serializers.ModelSerializer):
    from_user = UserNotifySerializer(read_only=True)

    class Meta:
        model = Notification
        fields = '__all__'
        read_only_fields = ('notification_type',)

    def validate_notification_type(self, value):
        choices = dict(Notification.NOTIFICATION_TYPES)
        if value not in choices:
            raise serializers.ValidationError("Invalid notification type.")
        return value


class InterestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Interest
        fields = ('interests',)


class TagsSerializer(TaggitSerializer, serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = '__all__'