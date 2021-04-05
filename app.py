from flask import Flask, render_template, redirect, request, abort
import token_manager
import urllib.parse
import requests
import json
import jwt
import os
from argparse import ArgumentParser

app = Flask(__name__)

app.state = token_manager.generate()
app.nonce = token_manager.generate()
app.code_verifier = token_manager.generate(43)
app.code_challenge = token_manager.convert2sha256(app.code_verifier)
app.code_challenge_method = 'S256'
app.line_api_domain = 'https://access.line.me/'
app.redirect_ur_name = '/callback'
app.authorize_api = urllib.parse.urljoin(app.line_api_domain, 'oauth2/v2.1/authorize')
app.token_api = urllib.parse.urljoin(app.line_api_domain, 'oauth2/v2.1/token')
app.result_for_dump = None

@app.route('/')
def homepage():
    name = "Hello World"
    return render_template('index.html', title='flask test', name=name)


@app.route('/gotoauthpage', methods=["GET"])
def goto_authorization():
    scope_list = ['openid', 'profile']
    params = {
        'response_type': 'code',
        'client_id': app.line_channel_id,
        'redirect_uri': urllib.parse.quote(
            urllib.parse.urljoin(request.url_root, app.redirect_ur_name), safe='').replace('http%3A', 'https%3A'),
        'scope': '%20'.join(scope_list),
        # PKCE support
        'code_challenge_method': app.code_challenge_method,
        'code_challenge': app.code_challenge,
        # state and nonce
        'state': app.state,
        'nonce': app.nonce
    }
    url_params = []
    for k in list(params.keys()):
        p_str = k + '=' + params[k]
        url_params.append(p_str)

    print('Goto authorization : ' + app.authorize_api + '?' + '&'.join(url_params))
    return redirect(app.authorize_api + '?' + '&'.join(url_params))


@app.route(app.redirect_ur_name, methods=['GET', 'POST'])
def callback():
    print(request)
    state = ''
    try:
        state = request.args['state']
    except Exception:
        abort(400)

    if state != app.state:
        abort(401)

    code = ''
    try:
        code = request.args['code']
    except Exception:
        abort(400)

    result_json_data = get_access_token(code)

    decoded_id_token = check_id_token(result_json_data['id_token'], app.line_channel_secret, app.line_channel_id)
    app.result_for_dump = json.dumps(result_json_data, indent=2)
    app.decoded_id_token = decoded_id_token

    return redirect(urllib.parse.urljoin(request.url_root, '/result').replace('http://', 'https://'))


@app.route('/result', methods=['GET'])
def result():
    if app.result_for_dump is None:
        abort(400)
    return render_template('result.html',
                           title='result',
                           result=app.result_for_dump,
                           id_token=app.decoded_id_token,
                           code_challenge = app.code_challenge,
                           code_verifier = app.code_verifier,
                           nonce=app.nonce,
                           state=app.state)


def get_access_token(code):
    uri_access_token = "https://api.line.me/oauth2/v2.1/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    data_params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": urllib.parse.urljoin(request.url_root, app.redirect_ur_name).replace('http:', 'https:'),
        "client_id": app.line_channel_id,
        "code_verifier": app.code_verifier,
        "client_secret": app.line_channel_secret
    }

    # トークンを取得するためにリクエストを送る
    response_post = requests.post(uri_access_token, headers=headers, data=data_params)
    return json.loads(response_post.text)


def check_id_token(id_token, channel_secret, channel_id):
    decoded_id_token = jwt.decode(id_token,
                                  channel_secret,
                                  audience=channel_id,
                                  issuer='https://access.line.me',
                                  algorithms=['HS256'])

    # check nonce (Optional. But strongly recommended)
    nonce = app.nonce
    expected_nonce = decoded_id_token.get('nonce')
    if nonce != decoded_id_token.get('nonce'):
        raise RuntimeError('invalid nonce')
    return decoded_id_token


if __name__ == "__main__":
    arg_parser = ArgumentParser(
        usage='Usage: python ' + __file__ + ' [--port <port>] [--help]'
    )
    arg_parser.add_argument('-p', '--port', type=int, default=5000, help='port')
    arg_parser.add_argument('-d', '--debug', default=True, help='debug')
    arg_parser.add_argument('-s', '--channelsecret', type=str, help='your channel secret')
    arg_parser.add_argument('-c', '--channelid', type=str, help='your channel id')
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

    app.run(debug=options.debug, port=options.port)