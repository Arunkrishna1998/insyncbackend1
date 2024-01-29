from rest_framework.views import APIView
from rest_framework import permissions, status, generics
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from django.db.models import Q, Count
from django.db import transaction

from .serializers import ( PostSerializer, CommentSerializer, UserSerializer, NotificationSerializer, 
                          TagsSerializer, InterestSerializer )
from .models import Post, Comment, Follow, Notification, Interest
from taggit.models import Tag
from users.models import User


class PostListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PostSerializer
    
    def get_queryset(self):
        user = self.request.user
        queryset = Post.objects.filter(Q(is_deleted=False) & Q(is_blocked=False))
        try:
            user_tags = Interest.objects.get(user=user).interests.all()
            queryset = queryset.annotate(
                shared_tags=Count(
                    'tags',
                    filter=Q(tags__in=user_tags)
                )
            )
            queryset = queryset.order_by('-shared_tags', '-created_at')
            return queryset
        except:
            queryset = queryset.order_by('-created_at')
            return queryset


class UserPostListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PostSerializer
    
    def get_queryset(self):
        user = self.request.user
        queryset = Post.objects.filter(author=user)
        return queryset


class PostSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tag_name = request.query_params.get('tags')
        if not tag_name:
            return Response({"error": "Please provide at least one tag."}, status=status.HTTP_400_BAD_REQUEST)
        queryset = Post.objects.filter(tags__name__icontains=tag_name, is_deleted=False, is_blocked=False)
        serializer = PostSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
class UserSearchView(generics.ListAPIView):
    # permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request):
        query = request.query_params.get('query', '').strip().lower()
        queryset = User.objects.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        )
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)


class PostBlockedListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Post.objects.filter(is_blocked=True).order_by('-created_at')
    serializer_class = PostSerializer


class PostReportedListView(generics.ListAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Post.objects.filter(is_blocked=False, reported_by_users__isnull=False).order_by('-created_at')
    serializer_class = PostSerializer


class PostDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = Post.objects.all()
    serializer_class = PostSerializer


class CreatePostView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PostSerializer
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        try:
            user = request.user
            post_img = request.data['post_img']
            content = request.data['content']
            tags = request.data.getlist('tags')
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                post = serializer.save(author=user, post_img=post_img, content=content, tags=tags)
                for follower in user.followers.all():
                    Notification.objects.create(
                        from_user=user,
                        to_user=follower.follower,
                        post=post,
                        notification_type=Notification.NOTIFICATION_TYPES[1][0],
                    )
                
                # Serialize the created post instance
                serialized_post = self.serializer_class(instance=post)
            
                return Response(serialized_post.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)            
        except Exception as e:
            return Response(status=status.HTTP_503_SERVICE_UNAVAILABLE)


class DeletePostView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            post.is_deleted = True
            post.save()
            return Response(status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response("Not found in database", status=status.HTTP_404_NOT_FOUND)
        

class RePostView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            post.is_deleted = False
            post.save()
            return Response(status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response("Not found in database", status=status.HTTP_404_NOT_FOUND)
        

class BlockPostView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def delete(self, request, pk):
        try:
            user = request.user
            post = Post.objects.get(pk=pk)
            post.is_blocked = True
            post.save()
            Notification.objects.create(
                        from_user=user,
                        to_user=post.author,
                        post=post,
                        notification_type=Notification.NOTIFICATION_TYPES[4][0],
                    )
            return Response(status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response("Not found in database", status=status.HTTP_404_NOT_FOUND)
        

class UnBlockPostView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, pk):
        try:
            user = request.user
            post = Post.objects.get(pk=pk)
            post.is_blocked = False
            post.save()
            return Response("Post unblocked successfully", status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response("Not found in database", status=status.HTTP_404_NOT_FOUND)
        

class UpdatePostView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PostSerializer

    def post(self, request, pk):
        try:
            post_obj = Post.objects.get(pk=pk)
            serializer = self.serializer_class(post_obj, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(status=status.HTTP_200_OK)
            return Response(serializer.errors)
        
        except Post.DoesNotExist:
            return Response("Not found in the database.")


class LikeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            user = request.user
            if user in post.likes.all():
                post.likes.remove(user)
                return Response("Like removed", status=status.HTTP_200_OK)
            else:
                post.likes.add(user)
                if not post.author == user:
                    Notification.objects.create(
                        from_user=user,
                        to_user=post.author,
                        post=post,
                        notification_type=Notification.NOTIFICATION_TYPES[0][0],
                    )                   
                return Response("Like added", status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response("Post not found", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ReportPostView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            user = request.user

            if user in post.reported_by_users.all():
                return Response("You have already reported this post.", status=status.HTTP_400_BAD_REQUEST)

            post.reported_by_users.add(user)                  
            return Response("Post Reported", status=status.HTTP_200_OK)
                
        except Post.DoesNotExist:
            return Response("Post not found", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        
class FollowView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            following = User.objects.get(pk=pk)
            follower = request.user
            follow_instance = Follow.objects.filter(following=following, follower=follower).first()
            print(following)
            print(follower)
            if follow_instance:
                # Unfollow logic
                with transaction.atomic():
                    follow_instance.delete()
                    # Check if the chat room exists and delete it
                return Response("Unfollowed", status=status.HTTP_200_OK)
            else:
                # Follow logic
                with transaction.atomic():
                    follow = Follow(following=following, follower=follower)
                    follow.save()
                    Notification.objects.create(
                        from_user=follower,
                        to_user=following,
                        notification_type=Notification.NOTIFICATION_TYPES[2][0],
                    ) 
                return Response("Followed", status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NetworkListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        current_user = self.request.user
        queryset = User.objects.exclude(Q(id=current_user.id) | Q(followers__follower=current_user))
        return queryset
    

class FollowListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        current_user = self.request.user
        queryset = User.objects.filter(Q(followers__follower=current_user) & ~Q(id=current_user.id))
        return queryset
    
    
class FollowerListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        current_user = self.request.user
        queryset = User.objects.filter(Q(following__following=current_user) & ~Q(id=current_user.id))
        return queryset
    


class ContactListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        current_user = self.request.user
        following_query = Q(followers__follower=current_user)
        followers_query = Q(following__following=current_user)
        queryset = User.objects.filter(following_query | followers_query).exclude(id=current_user.id).distinct()
        return queryset


class CreateCommentView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CommentSerializer

    def post(self, request, pk, *args, **kwargs):
        try:
            user = request.user
            body = request.data.get('body')
            print(request.data, body)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save(user=user, post_id=pk, body=body)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                print(serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(status=status.HTTP_503_SERVICE_UNAVAILABLE)


class DeleteCommentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        try:
            comment = Comment.objects.get(pk=pk, user=request.user)
            comment.delete()                        
            return Response(status=status.HTTP_200_OK)
        except Comment.DoesNotExist:
            return Response("Not found in database", status=status.HTTP_404_NOT_FOUND)


class NotificationsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        user = self.request.user
        return Notification.objects.filter(to_user=user).exclude(is_seen=True).order_by('-created')

    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NotificationsSeenView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationSerializer

    def post(self, request, pk, *args, **kwargs):
        try:
            notification = Notification.objects.get(pk=pk)
            notification.is_seen = True
            notification.save()
            return Response(status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response("Not found in database", status=status.HTTP_404_NOT_FOUND)


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, email, *args, **kwargs):
        try:
            profile = User.objects.get(email=email)
            profile_posts = Post.objects.filter(author=profile, is_deleted=False, is_blocked=False).order_by('-updated_at')
            profile_serializer = UserSerializer(profile)
            post_serializer = PostSerializer(profile_posts, many=True)

            context = {
                'profile_user': profile_serializer.data,
                'profile_posts': post_serializer.data
            }
            return Response(context, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response("User not found in the database", status=status.HTTP_404_NOT_FOUND)


class CreateInterestAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        interests_data = request.data.get('interests')
        print(interests_data)

        if not interests_data:
            return Response({"message": "Please provide interests data"}, status=status.HTTP_400_BAD_REQUEST)
        interest_instance, created = Interest.objects.get_or_create(user=user)

        for interest in interests_data:
            try:
                interest = Tag.objects.get(name=interest)
                interest_instance.interests.add(interest)
            except Tag.DoesNotExist:
                # Handle the case where the Tag with the provided ID does not exist.
                return Response({"message": f"Tag with ID {interest} does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            except ValueError:
                # Handle the case where interests_data contains invalid data.
                return Response({"message": "Invalid interest data"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_interest = True
        user.save()
        return Response({"message": "Interests added successfully"}, status=status.HTTP_201_CREATED)
    

class UpdateInterestAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = request.user
        interests_data = request.data.get('interests')
        print(interests_data)

        if not interests_data:
            return Response({"message": "Please provide interests data"}, status=status.HTTP_400_BAD_REQUEST)

        interest_instance, created = Interest.objects.get_or_create(user=user)

        # Clear existing interests
        interest_instance.interests.clear()

        for interest_name in interests_data:
            try:
                interest = Tag.objects.get(name=interest_name)
                interest_instance.interests.add(interest)
            except Tag.DoesNotExist:
                # Handle the case where the Tag with the provided name does not exist.
                return Response({"message": f"Tag with name '{interest_name}' does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            except ValueError:
                # Handle the case where interests_data contains invalid data.
                return Response({"message": "Invalid interest data"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_interest = True
        user.save()
        return Response({"message": "Interests updated successfully"}, status=status.HTTP_200_OK)


class ListTagsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        interest = Interest.objects.filter(user=user)
        serialized_interests = InterestSerializer(interest, many=True).data
        tags = Tag.objects.all().distinct()
        serialized_tags = TagsSerializer(tags, many=True).data

        return Response({"tags": serialized_tags, "interests": serialized_interests}, status=status.HTTP_200_OK)
    
