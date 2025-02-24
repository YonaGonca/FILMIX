from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api import UserViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet, 'users')

urlpatterns = router.urls
