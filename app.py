# coding: utf-8

from flask import Flask, render_template, redirect, request, abort, session
import token_manager
import urllib.parse
import requests
import json
import jwt
import os
from argparse import ArgumentParser
from werkzeug.middleware.proxy_fix import ProxyFix
from meta_data_manager import UserMetaDataManager

app = Flask(__name__)

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


@app.route('/')
def homepage():
    name = 'User'
    picture_url = None
    previous_data = {}
    logged_in = False

    if "session_id" in session and session["session_id"]:
        session_id = session["session_id"]
        server_data = app.meta_data_manager.get_user_meta_data(session_id)
        if server_data:
            logged_in = True
            name = server_data.user_name
            picture_url = server_data.user_picture_url
            for p in server_data.__dict__.keys():
                previous_data[p] = server_data.__dict__[p]
            previous_data['session_id'] = session_id

    return render_template(
        'index.html',
        title='Line Login Sample',
        name=name,
        picture_url=picture_url,
        data=previous_data,
        logged_in=logged_in
    )


@app.route('/login', methods=["GET"])
def login():
    session_id = ''
    # template session register
    if not ("session_id" in session and session["session_id"]):
        session_id = token_manager.generate()
        session["session_id"] = session_id
        app.meta_data_manager.append_user_meta_data(
            session_id,
            None
        )
    else:
        session_id = session["session_id"]
    return redirect('/gotoauth?' + 'session_id=' + session_id)


@app.route('/gotoauth', methods=["GET"])
def goto_authorization():
    session_id = request.args['session_id']

    login_params = refresh_login_parameters()
    print("login params :")
    print(login_params)
    meta_data = app.meta_data_manager.get_user_meta_data(session_id)
    print(meta_data)
    meta_data.state = login_params['state']
    meta_data.nonce = login_params['nonce']
    meta_data.code_verifier = login_params['code_verifier']
    meta_data.code_challenge = login_params['code_challenge']

    print('---------')
    for p in meta_data.__dict__.keys():
        print(p + " : " + meta_data.__dict__[p])
    print('---------')
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
    state = ''
    meta_data = None

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

    return redirect(urllib.parse.urljoin(request.url_root, '/result'))


@app.route('/error_result', methods=['GET'])
def error_result():
    if not ("session_id" in session and session["session_id"]):
        return render_template('error_result.html')

    session_id = session['session_id']
    error_data = None
    meta_data = app.meta_data_manager.get_user_meta_data(session_id)
    if 'error_data' in meta_data.__dict__.keys():
        error_data = meta_data.error_data
    app.meta_data_manager.remove_user_meta_data(session_id)
    return render_template('error_result.html', result=error_data)


@app.route('/result', methods=['GET'])
def result():
    if not ('session_id' in session and session['session_id']):
        return render_template('error_result.html', result='Session Not Found')
    session_id = session['session_id']
    meta_data = app.meta_data_manager.get_user_meta_data(session_id)

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
    session.pop('session_id', None)
    return redirect("/")


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
    arg_parser.add_argument('-t', '--host', type=str, default='0.0.0.0', help='your channel id')
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
