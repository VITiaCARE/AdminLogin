import json
import os
import identity.web
import requests
from flask import Flask, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from flask_cors import CORS

import app_config


app = Flask(__name__)
app.config.from_object(app_config)
assert app.config["REDIRECT_PATH"] != "/", "REDIRECT_PATH must not be /"
Session(app)
CORS(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/2.2.x/deploying/proxy_fix/
# from werkzeug.middleware.proxy_fix import ProxyFix
# app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.jinja_env.globals.update(Auth=identity.web.Auth)  # Useful in template for B2C
auth = identity.web.Auth(
    session=session,
    authority=app.config["AUTHORITY"],
    client_id=app.config["CLIENT_ID"],
    client_credential=app.config["CLIENT_SECRET"], 
)

import azure.cosmos.cosmos_client as cosmos_client
client = cosmos_client.CosmosClient(os.environ['COSMOS_STATIC_CATALOGUES_HOST'], {'masterKey': os.environ['COSMOS_STATIC_CATALOGUES_MASTER_KEY']} )
db_id = os.environ['COSMOS_STATIC_CATALOGUES_DATABASE_ID']
db = client.get_database_client('admin')
db.read()
container = db.get_container_client('access')
container.read()


@app.route("/login")
def login():
    if not (app.config["CLIENT_ID"] and app.config["CLIENT_SECRET"]):
        # This check is not strictly necessary.
        # You can remove this check from your production code.
        return render_template('config_error.html')
    acceptable_redir = json.loads(os.getenv('ACCEPTED_REDIR_URIS', []))
    redir_dict = { 'redir_uri' : ''}
    if request.args.get('redir_uri', '') != '' and max([request.args.get('redir_uri').find(uri) for uri in acceptable_redir]) == 0:
        redir_dict = dict(id=f"{session.sid}", redir_uri=request.args.get('redir_uri'), user_id='anon')
        container.upsert_item(
                body=redir_dict
            )
    if not auth.get_user():
        user_auth = auth.log_in(
            scopes=app_config.SCOPE, # Have user consent to scopes during log-in
            redirect_uri= url_for("auth_response", _external=True), # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
            prompt="select_account",  # Optional. More values defined in  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            )
        return render_template("login.html", **user_auth)
    return redirect(url_for("index") + f"?redir_uri={request.args.get('redir_uri', '')}")


@app.route(app_config.REDIRECT_PATH)
def auth_response():
    result = auth.complete_log_in(request.args)
    if "error" in result:
        return render_template("auth_error.html", result=result)
    return redirect(url_for("index"))
        


@app.route("/logout")
def logout():
    for item in container.query_items(query=f'SELECT * FROM access a WHERE a.id = "{session.sid}"', enable_cross_partition_query=True):
        container.delete_item(item, partition_key=item.get('user_id'))
    return redirect(auth.log_out(url_for("index", _external=True)))


@app.route("/")
def index():
    if not (app.config["CLIENT_ID"] and app.config["CLIENT_SECRET"]):
        # This check is not strictly necessary.
        # You can remove this check from your production code.
        return render_template('config_error.html')
    acceptable_redir = json.loads(os.getenv('ACCEPTED_REDIR_URIS', []))
    redir_dict = { 'redir_uri' : ''}
    if request.args.get('redir_uri', '') != '' and max([request.args.get('redir_uri').find(uri) for uri in acceptable_redir]) == 0:
        redir_dict = dict(id=f"{session.sid}", redir_uri=request.args.get('redir_uri'), user_id='anon')
        container.upsert_item(
                body=redir_dict
            )
    if not auth.get_user():
        return redirect(url_for("login"))
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    api_result = requests.get(
        f"https://graph.microsoft.com/v1.0/me",
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    import datetime
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=token['expires_in'])
    redir_uri= ''
    for item in container.query_items(query=f'SELECT * FROM access a WHERE a.id = "{session.sid}" and a.user_id="anon"', enable_cross_partition_query=True):
        if item.get('redir_uri', '') != '':
            redir_uri=item.get('redir_uri', '')
        try:
            container.delete_item(item, partition_key="anon")
        except:
            print(f"No anon for {session.sid} to delete")
    token_dict = dict(id=f"{session.sid}", user_id=api_result.get('id'), token=token['access_token'], expires=expires.isoformat(), token_type=token['token_type'], redir_uri=redir_uri)
    container.upsert_item(
            body=token_dict
        )
    
    if token_dict.get('redir_uri', '') != '' and max([token_dict.get('redir_uri').find(uri) for uri in acceptable_redir]) == 0:
        return redirect(token_dict.get('redir_uri', '') + f"?access_token={session.sid}")
    

    api_result = requests.get(
        f"https://graph.microsoft.com/v1.0/me/memberOf",
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    permissions = [g.get('id') for g in api_result.get('value')]
    return render_template('index.html', user=auth.get_user(), permissions=permissions, access_token=session.sid)


@app.route("/call_downstream_api")
def call_downstream_api():
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login")) 
    # Use access token to call downstream api
    api_result = requests.get(
        app_config.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    api_result = requests.get(
        f"https://graph.microsoft.com/v1.0/me/memberOf",
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    for g in api_result.get('value'):
        print(f"{g.get('id')} | {g.get('displayName')}")

    return render_template('display.html', result=api_result)


@app.route("/token/<token_id>")
def user_token(token_id):
    request_origin = request.headers.get('Origin', '')
    values = list(container.query_items(
            query=f"SELECT * FROM access z WHERE z.id = @val AND (z.redir_uri = @source or z.redir_uri like '{request_origin}/%')",
            parameters=[
                {"name": "@val", "value": token_id},
                {"name": "@source", "value": request_origin}
            ],
            enable_cross_partition_query=True))
    if len(values) < 1:
        return jsonify({'error' : True, 'error_code': 404, 'error_desc': "Not Found"}), 404
    for v in values:
        v.pop('_self', None)
        v.pop('_ts', None)
        v.pop('_rid', None)
        v.pop('_ts', None)
        v.pop('_attachments', None)
        v.pop('_etag', None)
    return jsonify(values)  


@app.route("/healthcoachtoken/<token_id>")
def ep_hc_token(token_id):
    request_origin = request.headers.get('Origin', '')
    values = list(container.query_items(
            query=f"SELECT * FROM access z WHERE z.id = @val AND (z.redir_uri = @source or z.redir_uri like '{request_origin}/%')",
            parameters=[
                {"name": "@val", "value": token_id},
                {"name": "@source", "value": request_origin}
            ],
            enable_cross_partition_query=True))
    if len(values) < 1:
        return jsonify({'error' : True, 'error_code': 404, 'error_desc': "Not Found"}), 404
    from helpers import User
    user = User()
    user.authenticate(username=os.environ['HC_LOGIN'], password=os.environ['HC_SECRET'])
    user.get_user_info()
    return jsonify({'userToken':user.get_user_token(), 'userId': user.get_user_id()})  

if __name__ == "__main__":
    app.run(debug=True)
 