from django.contrib.auth.models import User, Group
from oauth2_provider.contrib.rest_framework import TokenHasScope, OAuth2Authentication
from rest_framework import viewsets, generics, permissions
from rest_framework.decorators import action

from .models import Tokens
from rest_framework_social_oauth2.authentication import SocialAuthentication
from .authentication import CsrfExemptSessionAuthentication
from .permissions import IsOwner
from .serializer import UserSerializer, GroupSerializer, GetTokensSerializer


class UserApiViewSet(viewsets.ModelViewSet):
    permission_classes = [IsOwner]
    serializer_class = UserSerializer
    authentication_classes = [CsrfExemptSessionAuthentication, SocialAuthentication, OAuth2Authentication]
    queryset = User.objects.all()
    http_method_names = ['get', "patch", "options", 'put']

    def get_queryset(self):
        try:
            return User.objects.filter(id=self.request.user.id)
        except User.DoesNotExist:
            return User.objects.none()
        except Exception:
            return User.objects.none()

    def list(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            self.queryset = self.queryset.filter(pk=request.user.pk)
        return viewsets.ModelViewSet.list(self, request, *args, **kwargs)

    @action(detail=False, methods=["get", "post", 'patch', 'put'], url_path='me')
    def me(self, request, *args, **kwargs):
        print(request.method)
        if request.method == "PATCH" or request.method == "PUT":
            print("patch is called")
            try:
                print(request.data)
                token_data = request.data.get("tokens")
                print(token_data)
                token = Tokens.objects.get(user=request.user)
                print(token)
                serializer = GetTokensSerializer(token, data=token_data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
            except KeyError:
                pass
        else:
            self.queryset = self.queryset.filter(id=request.user.id)
            return viewsets.ModelViewSet.list(self, request, *args, **kwargs)
        return viewsets.ModelViewSet.list(self, request, *args, **kwargs)


class GroupList(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


import json
import logging
from pprint import pprint
from urllib import parse

import django
import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from oauth2_provider.models import AccessToken, Application

from authentication.models import Tokens

logger = logging.getLogger('auth')


def parse_url_next(next_loc):
    parsed = parse.parse_qs(next_loc)
    try:
        next_loc = dict(parsed)
        return next_loc
    except Exception as e:
        logger.exception("Parser")
        return False


def get_item_from_list_dict(parsed_loc, key):
    try:
        invite = parsed_loc[key][0]
    except (IndexError, KeyError) as e:
        logger.error('item not in list ' + str(e))
        invite = ''
    return invite


def get_item_from_url(url_params, key, default=''):
    parsed_loc = parse_url_next(url_params)
    if parsed_loc:
        return get_item_from_list_dict(parsed_loc, key)
    else:
        return default


def get_client_id(next_string):
    client_id = settings.DEFAULT_CLIENT
    if next_string:
        try:
            search_query = next_string.split('?')[1]
            logger.info('search string is ' + search_query)
            client_id = get_item_from_url(search_query, 'client_id')
        except IndexError:
            logger.debug('client id was not provided')
    return client_id


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    print(x_forwarded_for)
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip


@ensure_csrf_cookie
def signin(request):
    context1 = {}
    pprint(request.META['QUERY_STRING'])
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]
        if not email or not password:
            context1['pswderr'] = "Text fields cannot be empty"
        try:
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                # Redirect to a success page.
                redirect_location = request.GET.get('next', '/') + '?' + request.META['QUERY_STRING']
                return HttpResponseRedirect(redirect_location)
        except User.DoesNotExist:
            context1['pswderr'] = "user does not exist"

    context1['sign_text'] = 'Sign In'
    context1['GOOGLE_CLIENT_ID'] = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
    context1['google_redirect_uri'] = settings.DEPLOYMENT_URL + '/google-login'

    return render(request, template_name='login.html', context=context1)


@ensure_csrf_cookie
def signup(request):
    context1 = {}
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        passwrd2 = request.POST.get("password retype")
        username = request.POST.get("username", '')
        logger.info(f"{email = } {password = } {passwrd2} {username = }")
        if not email:
            context1['pswderr'] = 'Email cannot be empty'
            logger.info('Email was empty')
        elif not password or not passwrd2:
            context1['pswderr'] = 'Password cannot be empty'
            logger.info('Password was empty')
        elif not username:
            context1['pswderr'] = 'Username cannot be empty'
            logger.info('Username was empty')
        else:
            if passwrd2 == password:
                try:
                    logger.info("everything is okey creating user ")
                    user = User.objects.create_user(email=email, password=password, username=username,
                                                    first_name=username)
                    logger.info(f"created user {user.username} ")
                    token, _ = Tokens.objects.get_or_create(user=user)
                    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                    redirect_location = request.GET.get('next', '/') + '?' + request.META['QUERY_STRING']
                    return HttpResponseRedirect(redirect_location)

                except IntegrityError as e:
                    logger.error(e)
                    logger.info('User already exist')
                    context1['pswderr'] = 'User already exists'

            else:
                logger.info('Password Does not match')
                context1['pswderr'] = 'Password Does not match'

    next_loc = request.GET.get('next', '')
    context1['sign_text'] = "Register"
    # context1['invite'] = get_item_from_url(next_loc, 'invite')
    context1['redirect_uri'] = settings.DEPLOYMENT_URL + '/google-login'
    context1['GOOGLE_CLIENT_ID'] = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
    return render(request, template_name="signup.html", context=context1)


@login_required
def log_out(request):
    logout(request)
    url = '/?' + request.META['QUERY_STRING']
    return HttpResponseRedirect(url)
