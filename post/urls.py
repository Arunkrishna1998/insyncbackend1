from django.urls import path
from .views import ( PostListView, CreatePostView, DeletePostView, UpdatePostView, LikeView, BlockPostView,
                    CreateCommentView, DeleteCommentView, FollowView, NetworkListView, FollowListView, 
                    PostDetailView, NotificationsView, NotificationsSeenView, ProfileView, ReportPostView, 
                    PostBlockedListView, PostReportedListView, ContactListView, PostSearchView, ListTagsAPIView,
                    CreateInterestAPIView, UserPostListView, UpdateInterestAPIView, RePostView, UnBlockPostView, UserSearchView )

# app_name = 'post'

urlpatterns = [
    path('', PostListView.as_view(), name='posts'),
    path('user-posts/', UserPostListView.as_view(), name='user-posts'),
    path('search/', PostSearchView.as_view(), name='post-search'),
    path('user-search/', UserSearchView.as_view(), name='user-search'),
    path('tags/', ListTagsAPIView.as_view(), name='list-tags'),
    path('interests/', CreateInterestAPIView.as_view(), name='interests'),
    path('update-interests/', UpdateInterestAPIView.as_view(), name='update-interests'),
    path('view/<int:pk>/', PostDetailView.as_view(), name='view-post'),
    path('create-post/', CreatePostView.as_view(), name='create-post'),
    path('blocked/', PostBlockedListView.as_view(), name='blocked'),
    path('reported/', PostReportedListView.as_view(), name='reported'),
    path('network/', NetworkListView.as_view(), name='to-network'),
    path('following/', FollowListView.as_view(), name='following'),
    path('followers/', ContactListView.as_view(), name='followers'),
    path('contacts/', ContactListView.as_view(), name='contacts'),
    path('notifications/', NotificationsView.as_view(), name='notifications'),
    path('notifications-seen/<int:pk>/', NotificationsSeenView.as_view(), name='notifications-seen'),
    path('profile/<str:email>/', ProfileView.as_view(), name='profile'),
    path('update-post/<int:pk>/', UpdatePostView.as_view(), name='update-post'),
    path('delete-post/<int:pk>/', DeletePostView.as_view(), name='delete-post'),
    path('re-post/<int:pk>/', RePostView.as_view(), name='re-post'),
    path('block-post/<int:pk>/', BlockPostView.as_view(), name='block-post'),
    path('unblock-post/<int:pk>/', UnBlockPostView.as_view(), name='unblock-post'),
    path('like/<int:pk>/', LikeView.as_view(), name='like-post'),
    path('report/<int:pk>/', ReportPostView.as_view(), name='report-post'),
    path('follow/<int:pk>/', FollowView.as_view(), name='follow'),
    path('<int:pk>/comment/', CreateCommentView.as_view(), name='comment-post'),
    path('<int:pk>/delete-comment/', DeleteCommentView.as_view(), name='delete-comment'),
]