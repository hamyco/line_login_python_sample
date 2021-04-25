# coding: utf-8

from flask import Flask, render_template, redirect, request, abort, make_response
import token_manager
import urllib.parse
import requests
import json
import jwt
import os
from argparse import ArgumentParser
from werkzeug.middleware.proxy_fix import ProxyFix
from meta_data_manager import UserMetaDataManager


# Cookies
SESSION_COOKIE_SECURE = True  # https only
SESSION_HTTPONLY = True   # httponly
SESSION_KEY_COOKIE_NAME = '__session_key'
LOGGED_IN_COOKIE_NAME = '__logged_in'
COOKIE_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


# web page contents
DEFAULT_USERNAME = 'User'

app = Flask(__name__)


# Server setting
# Reference:  https://flask.palletsprojects.com/en/1.1.x/config/
app.config['SECRET_KEY'] = 'd25Pu2LLrBdFfGtNe16v5Q'

# If using proxy(like nginx, ngrok), the http will request.url_root will return http (not https)
# In this case, we need to fix the proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
app.secret_key = token_manager.generate()
app.code_challenge_method = 'S256'
app.line_api_domain = 'https://access.line.me/'
app.redirect_url_dir = '/callback'
app.authorize_api = urllib.parse.urljoin(app.line_api_domain, 'oauth2/v2.1/authorize')
app.token_api = urllib.parse.urljoin(app.line_api_domain, 'oauth2/v2.1/token')
app.meta_data_manager = UserMetaDataManager()


@app.before_request
def before_request():
    cookies = request.cookies.to_dict()
    if request.path == '/result' and SESSION_KEY_COOKIE_NAME in cookies and LOGGED_IN_COOKIE_NAME in cookies:
        return

    if request.path == '/error_result' and SESSION_KEY_COOKIE_NAME in cookies:
        return

    # Don't need to check if do not request result page.
    return


@app.route('/')
def homepage():

    title = 'Line Login Sample'
    page = 'index.html'
    previous_data = {}
    cookies = request.cookies.to_dict()
    if SESSION_KEY_COOKIE_NAME in cookies and LOGGED_IN_COOKIE_NAME in cookies:
        session_key = cookies[SESSION_KEY_COOKIE_NAME]
        server_data = app.meta_data_manager.get_user_meta_data(session_key)
        if server_data and server_data.user_name:
            for p in server_data.__dict__.keys():
                previous_data[p] = server_data.__dict__[p]
            previous_data[SESSION_KEY_COOKIE_NAME] = session_key
            return render_template(
                page, title=title,
                name=server_data.user_name,
                picture_url=server_data.user_picture_url,
                data=previous_data,
                logged_in=True
            )

    # return to default value ( delete cookies if exist)
    response = make_response(render_template(page, title=title, name=DEFAULT_USERNAME, logged_in=False, data={}))
    response.set_cookie(SESSION_KEY_COOKIE_NAME, 'null', max_age=0)
    response.set_cookie(LOGGED_IN_COOKIE_NAME, 'null', max_age=0)
    return response


@app.route('/login', methods=["GET"])
def login():
    # session key allocated
    session_key = token_manager.generate()
    response = make_response(redirect('/gotoauth?' + SESSION_KEY_COOKIE_NAME + '=' + session_key))
    response.set_cookie(key=SESSION_KEY_COOKIE_NAME, value=session_key,
                        max_age=COOKIE_MAX_AGE, httponly=SESSION_HTTPONLY, secure=SESSION_COOKIE_SECURE)
    app.meta_data_manager.append_user_meta_data(
        session_key,
        None
    )
    return response


@app.route('/gotoauth', methods=["GET"])
def goto_authorization():
    session_key = request.args[SESSION_KEY_COOKIE_NAME]

    login_params = refresh_login_parameters()
    print("login params :")
    print(login_params)
    meta_data = app.meta_data_manager.get_user_meta_data(session_key)

    # if state is not null, that means same request called more than once.
    # At this case, this request will be discarded.
    if 'state' in meta_data.__dict__.keys():
        if meta_data.state is not None:
            return

    meta_data.state = login_params['state']
    meta_data.nonce = login_params['nonce']
    meta_data.code_verifier = login_params['code_verifier']
    meta_data.code_challenge = login_params['code_challenge']

    print('---------\n[Meta data]\n')
    for p in meta_data.__dict__.keys():
        print(meta_data.__dict__[p])

    scope_list = ['openid', 'profile']
    params = {
        'response_type': 'code',
        'client_id': app.line_channel_id,
        'redirect_uri': urllib.parse.quote(
            urllib.parse.urljoin(request.url_root, app.redirect_url_dir), safe=''),
        'scope': '%20'.join(scope_list),
        # PKCE support
        'code_challenge_method': app.code_challenge_method,
        'code_challenge': login_params['code_challenge'],
        # state and nonce
        'state': login_params['state'],
        'nonce': login_params['nonce']
    }
    url_params = []
    for k in list(params.keys()):
        p_str = k + '=' + params[k]
        url_params.append(p_str)

    print('Goto authorization : ' + app.authorize_api + '?' + '&'.join(url_params))
    return redirect(app.authorize_api + '?' + '&'.join(url_params))


@app.route(app.redirect_url_dir, methods=['GET', 'POST'])
def callback():
    print(request)
    if 'state' not in request.args.keys():
        print("No state from login server")
        abort(400)

    if 'code' not in request.args.keys():
        print("No state from login server")
        abort(400)

    state = request.args['state']
    meta_data = app.meta_data_manager.get_user_meta_data_by_state(state)
    if not meta_data:
        print("Meta data not found!")
        abort(401)

    code = request.args['code']

    # request access token by authentication code and code_verifier(PKCE)
    result_json_data = request_access_token(code, meta_data.code_verifier)
    if 'error' in result_json_data.keys():
        meta_data.error_data = json.dumps(result_json_data, indent=4)
        return redirect('/error_result')

    print(result_json_data)
    decoded_id_token = verify_id_token(
        result_json_data['id_token'],
        app.line_channel_secret,
        app.line_channel_id,
        meta_data.nonce
    )

    meta_data.user_picture_url = decoded_id_token.get('picture')
    meta_data.username = decoded_id_token.get('name')
    meta_data.access_token = result_json_data
    meta_data.id_token = decoded_id_token
    meta_data.user_name = decoded_id_token.get('name')

    response = make_response(redirect(urllib.parse.urljoin(request.url_root, '/result')))
    response.set_cookie(key=LOGGED_IN_COOKIE_NAME, value='1', max_age=COOKIE_MAX_AGE,
                        httponly=SESSION_HTTPONLY, secure=SESSION_COOKIE_SECURE)
    return response


@app.route('/error_result', methods=['GET'])
def error_result():

    session_key = request.cookies.to_dict()[SESSION_KEY_COOKIE_NAME]
    error_data = None
    meta_data = app.meta_data_manager.get_user_meta_data(session_key)
    if 'error_data' in meta_data.__dict__.keys():
        error_data = meta_data.error_data
    app.meta_data_manager.remove_user_meta_data(session_key)

    response = make_response(render_template('error_result.html', result=error_data))
    response.set_cookie(key=SESSION_KEY_COOKIE_NAME, value='null', max_age=0)
    return response


@app.route('/result', methods=['GET'])
def result():
    cookies = request.cookies.to_dict()
    session_key = cookies[SESSION_KEY_COOKIE_NAME]
    meta_data = app.meta_data_manager.get_user_meta_data(session_key)

    return render_template('result.html',
                           title='Login Result',
                           result=json.dumps(meta_data.access_token, indent=4),
                           id_token=json.dumps(meta_data.id_token, indent=4),
                           code_challenge=meta_data.code_challenge,
                           code_verifier=meta_data.code_verifier,
                           nonce=meta_data.nonce,
                           state=meta_data.state,
                           picture_url=meta_data.user_picture_url)


@app.route('/logout')
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie(SESSION_KEY_COOKIE_NAME)
    response.delete_cookie(LOGGED_IN_COOKIE_NAME)
    return response


def request_access_token(code, code_verifier):
    uri_access_token = "https://api.line.me/oauth2/v2.1/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    data_params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": urllib.parse.urljoin(request.url_root, app.redirect_url_dir),
        "client_id": app.line_channel_id,
        "code_verifier": code_verifier,
        "client_secret": app.line_channel_secret
    }

    # トークンを取得するためにリクエストを送る
    response_post = requests.post(uri_access_token, headers=headers, data=data_params)
    return json.loads(response_post.text)


def verify_id_token(id_token, channel_secret, channel_id, nonce):
    decoded_id_token = jwt.decode(id_token,
                                  channel_secret,
                                  audience=channel_id,
                                  issuer='https://access.line.me',
                                  algorithms=['HS256'])

    # check nonce (Optional. But strongly recommended)
    if nonce != decoded_id_token.get('nonce'):
        raise RuntimeError('invalid nonce')
    return decoded_id_token


def refresh_login_parameters():
    state = token_manager.generate()
    nonce = token_manager.generate()
    code_verifier = token_manager.generate(43)
    code_challenge = token_manager.convert2sha256(code_verifier)
    return {
        'state': state,
        'nonce': nonce,
        'code_verifier': code_verifier,
        'code_challenge': code_challenge
    }


if __name__ == "__main__":
    arg_parser = ArgumentParser(
        usage='Usage: python ' + __file__ + ' [--port <port>] [--help]'
    )
    arg_parser.add_argument('-p', '--port', type=int, default=5000, help='port')
    arg_parser.add_argument('-d', '--debug', default=False, help='debug')
    arg_parser.add_argument('-s', '--channelsecret', type=str, help='your channel secret')
    arg_parser.add_argument('-c', '--channelid', type=str, help='your channel id')
    # If executing program on remote (not localhost), the host needs to be set 0.0.0.0
    arg_parser.add_argument('-o', '--host', type=str, default='0.0.0.0', help='your host')
    options = arg_parser.parse_args()

    if options.channelid:
        app.line_channel_id = options.channelid
    else:
        if os.getenv('LINE_LOGIN_CHANNEL_ID'):
            app.line_channel_id = os.environ['LINE_LOGIN_CHANNEL_ID']
        else:
            print('Please set up Channel ID by environment parameter(LINE_LOGIN_CHANNEL_ID) or use --channelid option')
            exit(1)

    if options.channelsecret:
        app.line_channel_secret = options.channelsecret
    else:
        if os.getenv('LINE_LOGIN_CHANNEL_SECRET'):
            app.line_channel_secret = os.environ['LINE_LOGIN_CHANNEL_SECRET']
        else:
            print('Please set up Channel Secret by environment parameter(LINE_LOGIN_CHANNEL_SECRET) or'
                  ' use --channelsecret option')
            exit(1)

    app.run(debug=options.debug, port=options.port, host=options.host)
