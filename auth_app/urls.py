from django.urls import path
from .views import AuthenticationView, TrustedRequestsView, ConfirmTrustedView, CheckTrustedRequestView

urlpatterns = [
    path('authenticate/', AuthenticationView.as_view(), name='authenticate'),
    path('trusted_requests/', TrustedRequestsView.as_view(), name='trusted_requests'),
    path('confirm_trusted/', ConfirmTrustedView.as_view(), name='confirm_trusted'),
    path('check_trusted_request/', CheckTrustedRequestView.as_view(), name='check_trusted_request'),
]
