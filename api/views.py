import uuid
from rest_framework.views import APIView
from rest_framework.response import Response

from api.models import UserInfo


class LoginView(APIView):
    '''
    传统token方式，用户登录
    '''
    def post(self, request, *args, **kwargs):
        user = request.data.get('username')
        pwd = request.data.get("password")

        user_object = UserInfo.objects.filter(username=user, password=pwd).first()
        if not user_object:
            return Response({'code': 1000, 'error': '用户名密码错误'})

        random_string = str(uuid.uuid4())

        user_object.token = random_string
        user_object.save()
        return Response({'code': 1001, 'data': random_string})


class OrderView(APIView):
    def get(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        if not token:
            return Response({'code': 2000, 'error': '登录成功才能访问'})
        usr_object = UserInfo.objects.filter(token=token).first()
        if not usr_object:
            return Response({'code': 2001, 'error': 'token无效'})
        return Response('订单列表')


class JwtLoginView(APIView):
    '''
    基于Python的pyjwt模块创建jwt的token。
    '''
    def post(self, request, *args, **kwargs):
        user = request.data.get('username')
        pwd = request.data.get("password")

        user_object = UserInfo.objects.filter(username=user, password=pwd).first()
        if not user_object:
            return Response({'code': 1000, 'error': '用户名密码错误'})

        import jwt
        import datetime

        salt = 'adakjdaksjajcskjdfeoiwkmaflkdwkdajhd'
        # 构造header
        headers = {
            'typ': 'jwt',
            'alg': 'HS256'
        }
        # 构造payload
        payload = {
            'user_id': user_object.id,  # 自定义用户ID
            'username': user_object.username,  # 自定义用户名
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  # 超时时间
        }

        token = jwt.encode(payload=payload, key=salt, algorithm="HS256", headers=headers).decode('utf-8')

        return Response({'code': 1001, 'data': token})


class JwtOrderView(APIView):
    def get(self, request, *args, **kwargs):
        '''
        获取token并判断合法性
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        token = request.query_params.get('token')
        # 校验步骤：
        # 1、切割
        # 2、解密第二段，并判断是否过期
        # 3、验证第三段合法性
        import jwt
        from jwt import exceptions

        salt = 'adakjdaksjajcskjdfeoiwkmaflkdwkdajhd'
        payload = None
        msg = None
        try:
            # 从token中获取payload【不校验合法性】
            # unverified_payload = jwt.decode(token, None, False)

            # 从token中获取payload【校验合法性】
            payload = jwt.decode(token, salt, True)
        except exceptions.ExpiredSignatureError:
            msg= 'token已失效'
        except jwt.DecodeError:
            msg = 'token认证失败'
        except jwt.InvalidTokenError:
            msg = '非法的token'

        if not payload:
            return Response({'code': 1003, 'error': msg})

        print(payload['user_id'], payload['username'])
        return Response('订单列表')


from api.utils.jwt_auth import create_token


class ProLoginView(APIView):
    '''
    基于Python的pyjwt模块创建jwt的token。
    '''
    def post(self, request, *args, **kwargs):
        user = request.data.get('username')
        pwd = request.data.get("password")

        user_object = UserInfo.objects.filter(username=user, password=pwd).first()
        if not user_object:
            return Response({'code': 1000, 'error': '用户名密码错误'})

        # 构造payload
        payload = {
            'user_id': user_object.id,  # 自定义用户ID
            'username': user_object.username,  # 自定义用户名
        }

        token = create_token(payload)

        return Response({'code': 1001, 'data': token})


from api.extensions.auth import JwtQueryParamsAuthentication


class ProOrderView(APIView):
    authentication_classes = [JwtQueryParamsAuthentication, ]

    def get(self, request, *args, **kwargs):
        print(request.user)
        return Response('订单列表')
