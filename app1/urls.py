from django.urls import path

from . import views
urlpatterns = [
    path('auth/signup/', views.SignupView.as_view()),
    path('auth/login/', views.LoginView.as_view()),
    path('groups/', views.GroupsView.as_view()),
    path('groups/my/', views.MyGroupView.as_view()),
    path('join_requests/', views.RequestsView.as_view()),
    path('join_requests/group/', views.SeeGroupRequestsView.as_view()),
    path('join_requests/accept/', views.AcceptRequestView.as_view()),
    path('connection_requests/', views.ConnectionRequestsView.as_view()),
    path('connection_requests/accept/', views.AcceptConnectionView.as_view()),
    path('chats/',views.GetChatsViews.as_view()),
    path('chats/<int:user_id>', views.MessagingView.as_view())
]