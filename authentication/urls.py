from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import GroupList, UserApiViewSet, signin, log_out, signup

# Setup the URLs and include login URLs for the browsable API.
router = DefaultRouter()
router.register(r'users', UserApiViewSet)


class Google_login:
    pass


urlpatterns = [
    path(r'users/', include(router.urls)),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    path('social/', include('rest_framework_social_oauth2.urls')),
    path('groups/', GroupList.as_view()),
    path('login/', signin),
    path('logout/', log_out),
    path('signup/', signup),
    path('google-login/', Google_login),

]
