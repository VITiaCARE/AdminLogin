import uuid
import json
import requests

data = {
  "name": "vitiacare-sdk",
  "version": "0.0.1",
  "description": "SDK to connect python-based apps to Vitia's Health API",
}

def make_url(base, path=[], query={}):
    url_base = base
    url_path = ''
    url_query = ''
    if path != None and isinstance(path, list) and len(path) > 0: 
        url_path = '/'.join(path)
    elif path != None and isinstance(path, str): 
        url_path = path
    else:
        path = ''
    if url_base.endswith('/'): 
        url_base = url_base[0:len(url_base)-1] 
    if url_path.startswith('/'): 
        url_path = url_path[1:len(url_path)]
    if query != None and query != {}:
        try:
            query_array = [f'{k}={v}' for (k,v) in list(query.items()) if k != None and v != None]
            url_query = '&'.join(query_array) 
        except: 
            url_query = '' 
    url = f"{url_base}/{url_path}"
    if url_query != '':
        url = f"{url}?{url_query}"
    return url

def make_request(url = '', path='', query={}, method= 'GET', payload=None, headers={}, send_as_form = False):
    
    id = uuid.uuid4()
    headers.update({'REQUEST-ID':f"{id}"})
    options = {"headers":headers}
    if method not in ['GET','HEAD']:
        if send_as_form:
             options['data']= payload
        else:
            options['json'] = payload
    if method.upper() == 'GET':
        response = requests.get(make_url(url, path, query))
    elif method.upper() == 'POST':
        response = requests.post(make_url(url, path, query), **options)
    elif method.upper() == 'PUT':
        response = requests.put(make_url(url, path, query), **options)
    elif method.upper() == 'PATCH':
        response = requests.patch(make_url(url, path, query), **options)
    elif method.upper() == 'DELETE':
        response = requests.delete(make_url(url, path, query), **options)
    return response

class Interface():
    def __init__(self, host, auth) -> None:
        self.auth = auth
        self.host = host
        self.version = data.get("version")
        self.useragent = f"vitiaSDK/{self.version}/python"
        self._default_headers()

    def _default_headers(self):
        self.headers = {
            "Authorization": self.auth,
            "User-Agent": self.useragent,
            "Origin": 'adminbackoffice',
            "Content-Type": 'application/json'
        }
    
    def update_headers(self, new_headers, replace=False):
        if replace == True:
            self.headers = new_headers
        else:
            self.headers.update(new_headers)
        

    def send_request(self, method='GET', path='', json=None, params={}, timeout=None, send_as_form=False):
        self.method = method
        self.path = path
        self.json = json
        self.params = params
        self.timeout = timeout
        self.response = make_request(self.host, self.path, self.params, self.method, self.json, self.headers, send_as_form) 
    
import os

class VitiaObject(Interface):
    
    def __init__(self, api_url=None, api_key=None):
        if api_url==None:
            try:
                api_url=os.environ["VITIA_API_ENDPOINT"]
            except:
                api_url=""
        if api_key==None:
            try:
                api_key=os.environ["VITIA_API_TOKEN"]
            except:
                api_key=""
        super().__init__(api_url,  f"Bearer {api_key}")
        self.api_key = api_key
        self.api_url = api_url
        self.initialize()
        self.ready = True

    def initialize (self):
        self.error_codes = {
            "NOT_READY": 1,
            "REQUEST_ERROR": 2,
            "ATTRIBUTE_LOAD_ERROR": 3,
            "NO_FILE_SPECIFIED": 4,
            "MISSING_SEARCH_ID": 5,
            "INVALID_STATE": 6,
            "SINGLE_UPDATE_ON_MULTIPLE": 7,
            "OBJECT_NOT_FOUND": 8,
            "SINGLE_CREATE_ON_MULTIPLE": 9,
            "CREATE_EXISTING_OBJECT": 10,
        }
        self.value = {}
        self.holder = {}
        self.schema = []
        self.schema_options = {}
        self.response = {}
        self.status = {}
        self.attributes = {}
        self.staged_changes = {}
        self.stagging = False
        self.multi = False

    def set_user_id(self, user_id):
        self.user_id = user_id
        self.update_headers({'UserId':user_id})

    def set_type(self, obj_type):
        self.obj_type = obj_type
        
    def set_id(self, obj_id):
        self.obj_id = obj_id
        self.value._key = obj_id

    def set_access_token(self, access_token):
        self.access_token = {'Access-Token':access_token}
        self.update_headers({'Access-Token':access_token})
    
    def get_access_token(self):
        return self.access_token

    def set_user_token(self, user_token):
        self.user_token = user_token
        self.update_headers({'UserToken':user_token})
    
    def get_user_token(self):
        return self.user_token
  
  

class User(VitiaObject):
    
    def __init__(self, api_url=None, api_key=None, user_id=None, user_token=None):
        super().__init__(api_url=api_url, api_key=api_key)
        self.set_type('user')
        self.user_token = None
        self.user_id = None
        if user_id!=None:
            self.set_user_id(user_id)
        
        if user_token!=None:
            self.set_user_token(user_token)

    def get_user_info(self):
        self.send_request('GET', "oauth/userinfo")    
        if self.response.status_code == 200:
            self.response.error = False
            data = self.response.json()
            self.holder.update(data) 
            self.value.update(data)
            self.set_user_id(self.value.get('_key'))
        else:
            self.response.error = True

    def authenticate(self, username, password):
        self.send_request('POST', "/api/v2/authuser", json={'username':username, 'password':password}) 
        if self.response.status_code == 200:
            self.response.error = False
            data = self.response.json()
            self.set_user_token(data.get('auth_token'))
        else:
            self.response.error = True