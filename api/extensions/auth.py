'''
认证组件
'''
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from jwt import exceptions


class JwtQueryParamsAuthentication(BaseAuthentication):

    def authenticate(self, request):
        # 校验步骤：
        # 1、切割
        # 2、解密第二段，并判断是否过期
        # 3、验证第三段合法性
        token = request.query_params.get('token')
        salt = settings.SECRET_KEY
        try:
            # 从token中获取payload【不校验合法性】
            # unverified_payload = jwt.decode(token, None, False)

            # 从token中获取payload【校验合法性】
            payload = jwt.decode(token, salt, True)
        except exceptions.ExpiredSignatureError:
            raise AuthenticationFailed({'code': 1003, 'error': "token已失效"})
        except jwt.DecodeError:
            raise AuthenticationFailed({'code': 1003, 'error': "token认证失败"})
        except jwt.InvalidTokenError:
            raise AuthenticationFailed({'code': 1003, 'error': "非法的token"})

        # 三种情况：
        # 1、抛出异常
        # 2、返回元组
        # 3、返回None

        return (payload, token)

