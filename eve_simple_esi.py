# Thanks Qandra-Si (https://github.com/Qandra-Si) for help and basis of implementation
import urllib
import requests
import base64
import hashlib
import secrets
import sys
import time
import json
import webview
from http.server import HTTPServer, CGIHTTPRequestHandler, BaseHTTPRequestHandler
import threading
import re
import os
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError, JWTClaimsError
import shelve
import hashlib
import win32gui

class ESICacheServer:
	def __init__(self,file_name='cache.db'):
		self.db_file=file_name
		self.db=shelve.open(self.db_file)

	def Get(self,key):
		if key in self.db:
			return self.db[key]
		return None

	def Del(self,key):
		del self.db[key]

	def Set(self,key,data):
		self.db[key]=data

	def Clear(self,force=False):
		if force:
			self.db.close()
			exts=['bak','dat','dir']
			for ext in exts:
				os.remove(self.db_file+"."+ext)
			self.db=shelve.open(self.db_file)
		else:
			self.db.clear()

	def Close(self):
		self.db.close()

	def Sync(self):
		self.db.sync()

class ESIAuthWebServerRequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
		if not 'state' in query:
			return
		state=query['state'][0]
		if not state in self.server.parent.on_success:
			return
		if 'code' in query:
			self.server.parent.on_success[state](query)
		else:
			self.server.parent.on_error[state](self.path)
		del self.server.parent.on_success[state]
		del self.server.parent.on_error[state]
		if ((len(self.server.parent.on_success) == 0 ) and ( len(self.server.parent.on_error) == 0 )):
			self.server.shutdown()

class ESIAuthWebServer:
	def __init__(self, local_address='localhost', port=8635):
		self.local_address=local_address
		self.port=port
		self.on_success={}
		self.on_error={}
		self.WebServer=None
		self.daemon=None

	def reg_callback(self,state,on_success,on_error):
		server_need_start=False
		if ((len(self.on_success) == 0 ) and ( len(self.on_error) == 0 )):
			server_need_start=True
		self.on_success[state]=on_success
		self.on_error[state]=on_error
		if server_need_start:
			self.start()

	def start_server(self, local_address, port, parent):
		self.WebServer = HTTPServer((local_address, port), ESIAuthWebServerRequestHandler)
		self.WebServer.parent=parent
		self.WebServer.serve_forever()

	def start(self):
		self.daemon = threading.Thread(name='daemon_server', target=self.start_server, args=(self.local_address, self.port, self))
		self.daemon.setDaemon(True) # Set as a daemon so it will be killed once the main thread is dead.
		self.daemon.start()

	def stop(self):
		self.WebServer.shutdown()

class ESIUserDataStorage:
	def __init__(self,work_dir='.',file_pattern='User_Data_%.json',indent="\t"):
		self.work_dir=work_dir
		self.file_pattern=file_pattern
		self.indent=indent

	def open(self,char_name):
		file_name=os.path.join(self.work_dir,self.file_pattern.replace('%',char_name))
		return file_name

	def read(self,char_name):
		file_name=self.open(char_name)
		if not os.path.exists(file_name):
			return None
		with open(file_name, "r") as f:
			data = json.load(f)
		return data
		

	def write(self,char_name,data):
		file_name=self.open(char_name)
		with open(file_name, "w+") as f:
			json.dump(data,f,indent=self.indent)

class ESIGUIWindow:
	def __init__(self):
		self.guilib = webview.initialize(None)
	
	def show(self,title, url=None, html=None, js_api=None, width=580, height=1024, x=None, y=None, resizable=True, fullscreen=False, min_size=(200, 100), hidden=False, frameless=False, easy_drag=True, minimized=False, on_top=True, confirm_close=False, background_color='#FFFFFF', transparent=False, text_select=False):
		self.window=webview.create_window(title,url=url, html=html, js_api=js_api, width=width, height=height, x=x, y=y, resizable=resizable, fullscreen=fullscreen, min_size=min_size, hidden=hidden, frameless=frameless, easy_drag=easy_drag, minimized=minimized, on_top=on_top, confirm_close=confirm_close, background_color=background_color, transparent=transparent, text_select=text_select) #580 x 1024
		self.window._initialize(self.guilib, False, False)
		self.guilib.create_window(self.window)

	def destroy(self):
		self.window.destroy()

class ESI:
	def __init__(self,
		settings,
		name=None,
		gui=True,
		use_cache=True,
		max_consistent_try=20,
		debug=False,
		callback_print=None,
		callback_input=None,
		callback_web_server=None,
		callback_saved_data=None,
		callback_cache_server=None,
		callback_gui_window_class=None
		):
		"""Prints the URL to redirect users to.
		Args:
			settings: (Required) settings object with client_id, client_secret etc..
			name: (None) string with name for autoauth storred user
			gui: (True) bool for prefer auth method
			use_cache: (True) bool for use cache for requests
			max_consistent_try: (20) int max try to get consistent list of pages
			debug: (False) bool for print more data
			callback_print: (Optional)
							def callback_print(string):
								...
			callback_input: (Optional)
							def callback_input(string_promt):
								...
								return str(auth_code)
			callback_web_server: (Optional)
							class callback_web_server(address, port):
								def reg_callback(state_string, on_success_function, on_error_function):
									...

			callback_saved_data: (Optional)
							class callback_saved_data:
								def read(char_name):
									...
									return json.loads(saved_data)

								def write(char_name,data):
									saved_data=json.dumps(data)
									...
			callback_cache_server: (Optional)
							class callback_cache_server:
								def Get(key):
									...
									return cache[key]
								def Set(key,data):
									...
									cache[key]=data
								def Del(key):
									...
								def Clear():
									...
								def Sync():
									...
								def Close():
									...
			callback_gui_window_class:
							class callback_gui_window_class:
								def show(title,url):
									...
								def destroy()
									...

		"""
		self.settings=self.configure(settings)

		self.gui = gui
		self.use_cache = use_cache
		
		self.max_consistent_try = max_consistent_try

		self.force_cache = False
		self.repeat_max_try = 5

		self.user_auth={}

		self.refresh_token = ''
		self.access_token = ''
		self.expired = -1

		self.auth_code = ''
		self.random = ''
		self.unique_state = ''

		self.last_map_action=None
		self.last_map_action_priority=['stop','skip']
		self.window = None
		self.WebServer = None

		self.session = requests.Session()

		self.debug = debug

		self.p=print
		self.i=input
		
		if callable(callback_print):
			self.p=callback_print
		if callable(callback_input):
			self.i=callback_input
		if callable(callback_web_server):
			self.web_server=callback_web_server(local_address=self.settings['local_address'], port=self.settings['port'])
		else:
			self.web_server=ESIAuthWebServer(local_address=self.settings['local_address'], port=self.settings['port'])

		if callable(callback_cache_server):
			self.cache=callback_cache_server()
		else:
			self.cache=ESICacheServer()

		if callable(callback_saved_data):
			self.storage=callback_saved_data
		else:
			self.storage=ESIUserDataStorage()

		if callable(callback_gui_window_class):
			self.window=callback_gui_window_class
		else:
			self.window=ESIGUIWindow()

		if type(name) == str:
			self.get(name)

	def dbg(self,data,data2=None):
		if self.debug:
			if data2==None:
				self.p(data)
			else:
				self.p(data,data2)

	def validate_eve_jwt(self):
		
		"""Validate a JWT token retrieved from the EVE SSO.
		Args:
		Returns
			dict: The contents of the validated JWT token if there are no
				validation errors
		"""

		res = self.session.get(self.settings['jwks_url'])
		res.raise_for_status()

		data = res.json()

		try:
			jwk_sets = data["keys"]
		except KeyError as e:
			self.p("Something went wrong when retrieving the JWK set. The returned "
				"payload did not have the expected key {}. \nPayload returned "
				"from the SSO looks like: {}".format(e, data))
			return None

		jwk_set = next((item for item in jwk_sets if item["alg"] == "RS256"))

		try:
			return jwt.decode(
				self.access_token,
				jwk_set,
				algorithms=jwk_set["alg"],
				issuer=self.settings['login_host']
			)
		except ExpiredSignatureError:
			self.p("The JWT token has expired: {}")
			return None
		except JWTError as e:
			self.p("The JWT signature was invalid: {}").format(str(e))
			return None
		except JWTClaimsError as e:
			try:
				return jwt.decode(
							self.access_token,
							jwk_set,
							algorithms=jwk_set["alg"],
							issuer=urllib.parse.urlunparse([self.settings['esi_proto'],self.settings['login_host'],'','','',''])
						)
			except JWTClaimsError as e:
				self.p("The issuer claim was not from login.eveonline.com or "
					"https://login.eveonline.com: {}".format(str(e)))
				return None

	def configure(self,settings):
		default_settings={
				'content_type':"application/x-www-form-urlencoded",
				'login_host':"login.eveonline.com",
				'base_auth_url':"https://login.eveonline.com/v2/oauth/authorize/",
				'token_req_url':"https://login.eveonline.com/v2/oauth/token",
				'jwks_url':'https://login.eveonline.com/oauth/jwks',
				'gui_auth_window_name':'Login in EVE',
				'user_agent':"eve-simple-esi library",
				'esi_url':"esi.evetech.net/latest",
				'esi_proto':"https",
				'scopes':[],
				'port':8635,
				'local_address':'localhost'
			}
		default_settings.update(settings)
		default_settings['scopes']=self.combine_client_scopes(default_settings['scopes'])
		return default_settings

	def combine_client_scopes(self,scopes):
		return " ".join(scopes)

	def auth_url(self,code_challenge=None):
		"""Prints the URL to redirect users to.
		Args:
			code_challenge: A PKCE code challenge
		"""
		self.unique_state = base64.urlsafe_b64encode(secrets.token_bytes(8)).decode().replace("=", "")
		params = {
			"response_type": "code",
			"redirect_uri": self.settings['client_callback_url'],
			"client_id": self.settings['client_id'],
			"scope": self.settings['scopes'],
			"state": self.unique_state
		}

		if code_challenge:
			params.update({
				"code_challenge": code_challenge,
				"code_challenge_method": "S256"
			})

		string_params = urllib.parse.urlencode(params)
		full_auth_url = "{}?{}".format(self.settings['base_auth_url'], string_params)
		self.full_auth_url = full_auth_url
		return full_auth_url

	def send_token_request(self,form_values, add_headers={}):
		"""Sends a request for an authorization token to the EVE SSO.
		Args:
			form_values: A dict containing the form encoded values that should be
						sent with the request
			add_headers: A dict containing additional headers to send
		Returns:
			requests.Response: A requests Response object
		"""

		headers = {
			"Content-Type": self.settings['content_type'],
			"Host": self.settings['login_host']
		}
		if self.settings['user_agent']:
			headers.update({"User-Agent": self.settings['user_agent']})

		if add_headers:
			headers.update(add_headers)

		res = self.session.post(
			self.settings['token_req_url'],
			data=form_values,
			headers=headers,
		)

		self.p("Request sent to URL {} with headers {} and form values: "
			"{}\n".format(res.url, headers, form_values))
		res.raise_for_status()

		return res

	def send_token_refresh(self):
		headers = {
			"Content-Type": self.settings['content_type'],
			"Host": self.settings['login_host'],
		}
		if self.settings['user_agent']:
			headers.update({"User-Agent": self.settings['user_agent']})

		form_values = {
			"grant_type": "refresh_token",
			"refresh_token": self.refresh_token,
			"client_id": self.settings['client_id'],
			"scope": self.settings['scopes']  # OPTIONAL
		}

		self.dbg(form_values)

		res = self.session.post(
			self.settings['token_req_url'],
			data=form_values,
			headers=headers,
		)

		self.dbg("Request sent to URL {} with headers {} and form values: "
			"{}\n".format(res.url, headers, form_values))
		res.raise_for_status()

		return res

	def uri_hash(self,uri): # Hash based by user and uri
		character_name='Unregistered'
		if 'character_name' in self.user_auth:
			character_name=self.user_auth['character_name']
		url=list(urllib.parse.urlsplit(uri))
		query=urllib.parse.parse_qs(url[3])
		if 'token' in query:
			del query['token']
		url[3]=urllib.parse.urlencode(query)
		url=urllib.parse.urlunsplit(url)
		text=character_name + url# + str(hash(str(body)))
		text = hashlib.md5(text.encode('utf-8')).hexdigest()
		return str(text)

	def http_return_obj(self,cached,status_code,data,headers,validated_headers):
		res={
			'cached':cached,
			'data':data,
			'headers':dict(headers),
			'status_code':status_code,
			'consistent':False,
			'error':False,
			'validated_headers':validated_headers
		}
		if ((status_code==304) and (validated_headers)) :
			res['consistent']=True
		elif not status_code==200:
			res['error']=True
		return res

	def validate_headers(self,headers,validate_array):
		if validate_array == None:
			return True
		responce=True
		for field in validate_array:
			if validate_array[field] is None:
				continue
			if not field in headers:
				continue
			if not validate_array[field] == headers[field]:
				self.dbg('validate error',[field,validate_array[field],headers[field]])
				responce=False
				break
		return responce

	def set_cache_data(self,uri_hash,content,headers):
		if self.use_cache:
			json_content=self.json(content)
			if json_content:
				self.cache.Set(uri_hash,{'header':headers,'data':json_content})
				return True
		return False

	def get_etag(self,etag,uri_cache):
		if etag is None:
			if 'Etag' in uri_cache['header']:
				etag=uri_cache['header']['Etag']
		return etag

	def send_cached_data(self, uri, body=None, etag=None, method='GET', validate_array=None):
		cached=False
		uri_cache=False
		uri_hash=self.uri_hash(uri)

		if (not ((body is None) and (method=='GET'))): # For POST/DELETE/PUT requests and if no cache
			data=self.send_esi_request_http(uri, etag=etag, body=body, method=method)
			content=data.content
			headers=data.headers
			status_code=data.status_code
			return self.http_return_obj(False,status_code,content,headers,True)

		if self.use_cache:	#Initialize Cache
			uri_cache=self.cache.Get(uri_hash)
			validated_headers=False
			if not uri_cache is None:
				self.dbg('validating cache data for',uri)
				validated_headers=self.validate_headers(uri_cache['header'],validate_array)
			if not validated_headers:
				uri_cache=False


		if not uri_cache:	# Request without cache data
			data=self.send_esi_request_http(uri, etag=etag, body=body, method=method)
			content=data.content
			headers=data.headers
			status_code=data.status_code
			self.dbg('validating request data for',uri)
			validated_headers=self.validate_headers(headers,validate_array)
			if ((status_code in [200]) and (validated_headers) and (self.set_cache_data(uri_hash,content,headers)) ):
				self.dbg('Add to cache',uri)

		elif self.force_cache:	# Return data from cache without check
			status_code=304
			cached=True
			content=json.dumps(uri_cache['data'])
			headers=uri_cache['header']

		else: # Request with cache data
			etag=self.get_etag(etag,uri_cache)
			data=self.send_esi_request_http(uri, etag=etag, body=body, method=method)
			headers=data.headers
			content=data.content
			status_code=data.status_code
			self.dbg('validating etag data for',uri)
			validated_headers=self.validate_headers(headers,validate_array)

			if status_code == 304:
				cached=True
				content=json.dumps(uri_cache['data'])

			if ((status_code in [200]) and (validated_headers) and (self.set_cache_data(uri_hash,content,headers)) ):
				self.dbg('Add to cache',uri)

		return self.http_return_obj(cached,status_code,content,headers,validated_headers)

	def send_cached_json(self, uri, body=None, etag=None, method='GET', validate_array=None):
		data=self.send_cached_data(uri, body=body, etag=None, method=method, validate_array=validate_array)
		d=self.json(data['data'])
		if type(d) is None:
			return None
		return self.json(data['data'])

	def json(self,data):
		if data == b'':
			return {}
		else:
			try:
				res=json.loads(data)
			except:
				return ('json_error',data.decode('utf-8'))
			return res

	def send_esi_request_http(self, uri, etag, body=None, method='GET'):
		headers = {
			"Authorization": "Bearer {}".format(self.access_token),
		}

		if etag:
			headers.update({"If-None-Match": etag})
		if self.settings['user_agent']:
			headers.update({"User-Agent": self.settings['user_agent']})
		if ((body) and (method=='GET')):
			method='POST'

		try:
			if method=='GET':
				res = self.session.get(uri, headers=headers)
			elif method=='POST':
				headers.update({"Content-Type": "application/json"})
				res = self.session.post(uri, data=body, headers=headers)
			elif method=='PUT':
				headers.update({"Content-Type": "application/json"})
				res = self.session.put(uri, data=body, headers=headers)
			elif method=='DELETE':
				res = self.session.delete(uri, headers=headers)
			if res.status_code==401:
				self.re_auth()
				res=self.send_esi_request_http(uri, etag, body, method)
			#if body is None:
			#	res = self.session.get(uri, headers=headers)
			return res
		except:
			self.p(sys.exc_info())
			raise 

	def print_sso_failure(self, sso_response):
		self.p("\nSomething went wrong! Here's some debug info to help you out:")
		self.p("\nSent request with url: {} \nbody: {} \nheaders: {}".format(
			sso_response.request.url,
			sso_response.request.body,
			sso_response.request.headers
		))
		self.p("\nSSO response code is: {}".format(sso_response.status_code))
		self.p("\nSSO response JSON is: {}".format(sso_response.json()))

	def auth(self):
		self.p("Follow the prompts and enter the info asked for.")
		url=self.auth_url(code_challenge=self.create_code_challenge())
		self.auth_code = self.i(url+"\nCopy the \"code\" query parameter and enter it here: ")
		return self.auth_part2()

	def create_code_challenge(self):
		self.random = base64.urlsafe_b64encode(secrets.token_bytes(32))
		m = hashlib.sha256()
		m.update(self.random)
		d = m.digest()
		code_challenge = base64.urlsafe_b64encode(d).decode().replace("=", "")
		return code_challenge

	def gui_auth(self):
		self.dbg("gui_auth")
		self.auth_url(code_challenge=self.create_code_challenge())
		self.web_server.reg_callback(state=self.unique_state, on_success=self.success_auth_code, on_error=self.error_auth_code)
		return self.open_url()

	def auth_part2(self):
		code_verifier = self.random

		form_values = {
			"grant_type": "authorization_code",
			"client_id": self.settings['client_id'],
			"code": self.auth_code,
			"code_verifier": code_verifier
		}

		sso_auth_response = self.send_token_request(form_values)

		if sso_auth_response.status_code == 200:
			data = sso_auth_response.json()
			self.access_token = data["access_token"]
			self.refresh_token = data["refresh_token"]
			self.expired = int(data["expires_in"]) + int(time.time())
			self.validate_auth()
			return self.auth_object()
		else:
			self.print_sso_failure(sso_auth_response)

	def validate_auth(self):
		validated_jwt = self.validate_eve_jwt()
		self.dbg("\nThe contents of the access token are: {}".format(validated_jwt))
		self.character_id = validated_jwt["sub"].split(":")[2]
		self.character_name = validated_jwt["name"]
		self.expired = validated_jwt["exp"]
		self.settings['client_id'] = validated_jwt["azp"]
		self.scope = self.combine_client_scopes(validated_jwt["scp"])

	def auth_object(self):
		self.user_auth={
			"access_token": self.access_token,
			"refresh_token":self.refresh_token,
			"expired":self.expired,
			"character_id":self.character_id,
			"character_name":self.character_name,
			"client_id":self.settings['client_id'],
			"scope":self.scope
		}
		self.storage.write(self.character_name,self.user_auth)
		return self.user_auth

	def get(self,char_name):
		self.user_auth=self.storage.read(char_name)
		if not self.user_auth == None:
			self.dbg('Character data readed')
			self.access_token=self.user_auth['access_token']
			self.refresh_token=self.user_auth['refresh_token']
			self.expired=self.user_auth['expired']
			self.character_id=self.user_auth['character_id']
			self.character_name=self.user_auth['character_name']
			self.settings['client_id']=self.user_auth['client_id']
			self.scope=self.user_auth['scope']
			return self.re_auth()
		self.user_auth={}
		if self.gui:
			return self.gui_auth()
		else:
			return self.auth()
		return None

	def stop_web_server(self):
		if self.WebServer:
			self.WebServer.shutdown()

	def open_url(self):
		self.window.show(self.settings['gui_auth_window_name'], self.full_auth_url)

		self.stop_web_server()

		if self.auth_code == '':
			return False
		return True

	def success_auth_code(self,query):
		self.set_auth_code(query)
		self.window.destroy()

	def error_auth_code(self,query):
		self.window.destroy()
		self.dbg('error_auth_code',query)

	def set_auth_code(self,query):
		if query['state'][0] == self.unique_state:
			self.dbg('Authorization server valid')
		self.auth_code=query['code']
		self.dbg(self.auth_part2())

	def re_auth(self):
		if self.refresh_token == '':
			return None
		if self.expired > time.time():
			return self.auth_object()
		sso_auth_response = self.send_token_refresh()

		if sso_auth_response.status_code == 200:
			data = sso_auth_response.json()

			self.access_token = data["access_token"]
			self.refresh_token = data["refresh_token"]
			self.expired = int(data["expires_in"]) + int(time.time())

			self.validate_auth()

			return self.auth_object()
		else:
			self.print_sso_failure(sso_auth_response)

	def prepare_obj_to_url(self,obj):
		for param in obj:
			if type(obj[param]) == list:
				obj[param]=self.combine_client_scopes(obj[param])
		return obj

	def clear_cache(self):
		self.cache.Clear()

	def param_creator(self,command,params,token=False):
		pattern = re.compile(r'({[^\}]+})')
		splitted=pattern.split(command)
		for i in range(len(splitted)):
			sub = splitted[i]
			if not pattern.match(sub):
				continue
			var=sub[1:-1:] # Remove {}
			if var in params:
				splitted[i]=str(params[var])
			elif var in self.user_auth:
				splitted[i]=str(self.user_auth[var])
			else:
				self.dbg('Error, no variable {} in params'.format(var))
				return None
		path="".join(splitted)
		if token:
			params.update({'token':self.refresh_token})
		params=self.prepare_obj_to_url(params)
		uri=urllib.parse.urlunparse([self.settings['esi_proto'],self.settings['esi_url'],path,'',urllib.parse.urlencode(params),''])
		return uri

	def op_single(self,command,params={},post=False,etag=None,method="GET",body=None,raw=False, validate_array=None):
		result=None
		repeat=True
		i=0
		while ((i < self.repeat_max_try) and (repeat==True)):
			i=i+1
			if post:
				method="POST"
			if not method=="GET":
				repeat=False
			uri=self.param_creator(command,params)
			if uri is None:
				return None
			if raw:
				result=self.send_cached_data(uri, body=body, etag=etag, method=method, validate_array=validate_array)
				if not result['error']:
					return self.send_cached_data(uri, body=body, etag=etag, method=method, validate_array=validate_array)
			else:
				result=self.send_cached_json(uri, body=body, etag=etag, method=method, validate_array=validate_array)
				if not type(result) is tuple:
					return result
		return result

	def paged_data(self,data,obj):
		if type(data) is list:
			return obj+data
		return obj.append(data)

	def check_consistent(self,pages_count,command,params,method,body,validate_array=None):
		consistent=True
		for i in range(pages_count):
			page_params=params.copy()
			page_params['page']=i+1
			page=self.op_single(command,params=page_params,method=method,etag=None,body=body,raw=True,validate_array=validate_array)
			last_header=dict(page['headers'])
			last_status=page['status_code']
			last_validated_headers=page['validated_headers']

			if not last_validated_headers:
				self.dbg(i,['data changed before getted'])
				consistent=False

			if (not ( page['status_code'] == 304 )):
				self.dbg(i,['status_code',page['status_code']])
				consistent=False

			if not int(page['headers']['X-Pages']) == pages_count:
				self.dbg(i,['pages_count changed',pages_count,int(page['headers']['X-Pages'])])
				pages_count=int(page['headers']['X-Pages'])
				consistent=False
			
			if not consistent:
				break

		return {
			'consistent':consistent,
			'pages_count':pages_count,
			'last_header':last_header,
			'last_status':last_status,
			'validated_headers':last_validated_headers
			}

	def get_all_pages(self,first,pages_count,command,params,method,body):
		result=[]
		result_hash=[]
		last_header=dict(first['headers'])
		last_status=first['status_code']
		last_validated_headers=False
		consistent=True
		
		validate_array=None
		for i in range(pages_count):
			page_params=params.copy()
			page_params['page']=i+1
			uri=self.param_creator(command,page_params,token=False)
			if uri is None:
				return None
			result_hash.append(self.uri_hash(uri))
			page=self.op_single(command,params=page_params,method=method,body=body, raw=True, validate_array=validate_array)

			if i==0: #Make validate_array for first page
				validate_array=self.make_validate_array(page['headers'])

			last_header=dict(page['headers'])
			last_status=page['status_code']
			last_validated_headers=page['validated_headers']
			consistent=page['consistent']

			data=self.json(page['data'])
			if type(data) is None:
				consistent=False
				break

			if not last_validated_headers:
				self.dbg(i,['data changed before getted'])
				consistent=False
				break

			if last_status in [200,304] :
				if ( (last_status == 200) and (self.use_cache) ):
					self.dbg(i,last_status)
					consistent=False
			else:
				self.dbg(i,last_status)
				consistent=False
				break

			if page['error']:
				data=self.json(page['data'])
				consistent=False

			result=self.paged_data(data,result)
			

		return {
			'consistent':consistent,
			'pages_count':pages_count, 
			'result':result, 
			'result_hash':result_hash, 
			'last_header':last_header,
			'last_status':last_status,
			'validated_headers':last_validated_headers,
			'validate_array':validate_array
			}

	def make_validate_array(self,headers):
		validate_array={
			'X-Pages':None,
			'Last-Modified':None,
		}
		for field in validate_array:
			if field in headers:
				validate_array[field]=headers[field]
		return validate_array

	def data_returner(self,data,raw):
		json_data=self.json(data['data'])
		if not type(json_data) is None:
			data['data']=json_data
		if raw:
			return data
		return data['data']

	def list_filters_fields(self,data,query_array):
		for query in query_array:
			if self.list_filters_field(data,query[0],query[1],query[2]):
				last_map_action=query[3]
				if self.last_map_action == None:
					self.last_map_action=last_map_action
				elif self.last_map_action_priority.index(self.last_map_action) > self.last_map_action_priority.index(last_map_action):
						self.last_map_action=last_map_action
					

	def list_filters_field(self,data,field_name,operator,compared_data):
		if field_name in data:
			if operator == '==':
				return data[field_name] == compared_data
			elif operator == '!=':
				return (not (data[field_name] == compared_data))
			elif operator == '>':
				return data[field_name] > compared_data
			elif operator == '<':
				return data[field_name] < compared_data
			elif operator == '>=':
				return data[field_name] >= compared_data
			elif operator == '<=':
				return data[field_name] <= compared_data
			elif operator == 'in':
				return data[field_name] in compared_data
			elif operator == 'not in':
				return (not (data[field_name] in compared_data))
			elif operator == 'startswith':
				return data[field_name].startswith(compared_data)
			elif operator == 'endswith':
				return data[field_name].endswith(compared_data)
			elif operator == 're':
				return (not (compared_data.match(data[field_name]) == None))
		return False

	def map_obj (self,data,obj):
		return_data={}
		if self.last_map_action in ['skip','stop']:
			return return_data

		if 'fields' in obj:
			if type(obj['fields']) is list:
				for field in obj['fields']:
					if field in data:
						return_data[field]=data[field]
			else:
				return data[obj['fields']]

		if self.last_map_action == 'stop':
			return return_data

		if 'id' in obj:
			if (('params' in obj) and (obj['id'] in obj['params'])):
				return_data.update({obj['id']:obj['params'][obj['id']]})
			elif obj['id'] in self.user_auth:
				return_data.update({obj['id']:self.user_auth[obj['id']]})
		if 'map' in obj:
			for field in obj['map']:
				if not (field in data):
					continue
				n_param={}
				if field in data:
					n_param[field]=data[field]
				new_obj=obj['map'][field].copy()
				
				if 'link' in obj['map'][field]:
					n_param[obj['map'][field]['link']]=n_param[field]
					new_obj['id']=new_obj['link']
					del n_param[field]
					del new_obj['link']
				else:
					new_obj['id']=field
					
				if 'params' in obj['map'][field]:
					n_param.update(obj['map'][field]['params'])
					del new_obj['params']

				new_obj['params']=n_param
				if self.last_map_action == 'stop':
					return return_data
				if 'name' in obj['map'][field]:
					return_data[obj['map'][field]['name']]=self.map(new_obj,first=False)
				else:
					return_data[field]=self.map(new_obj,first=False)
		return return_data

	def map_list (self,data,obj):
		return_data=[]
		
		for field in data:
			if 'list_filters' in obj:
				self.list_filters_fields(field,obj['list_filters'])
			if self.last_map_action == 'stop':
				return return_data
			if self.last_map_action == 'skip':
				self.last_map_action=None
				continue
			return_data.append(self.map_check(field,obj))
		return return_data

	def map_check (self,data,obj):
		if self.last_map_action == 'stop':
			return None
		if type(data) is dict:
			return_data=self.map_obj(data,obj)
		elif type(data) is list:
			return_data=self.map_list(data,obj)
		elif 'link' in obj:
			new_obj=obj.copy()
			if not 'params' in obj:
				new_obj['params']={}
			new_obj['params'][obj['link']]=data
			return_data=self.map(new_obj,first=False)
		else:
			return_data=data
		return return_data

	def make_flags(self,flags):
		self_flags=dir(self)
		prev_state={}
		for flag in flags:
			if flag in self_flags:
				prev_state[flag]=getattr(self,flag)
				setattr(self,flag,True)
		return prev_state

	def return_state(self,flags):
		self_flags=dir(self)
		for flag in flags:
			if flag in self_flags:
				setattr(self,flag,flags[flag])

	def map (self,obj,first=True):
		params={}
		if 'params' in obj:
			params=obj['params']
		command=None
		method="GET"
		if 'get' in obj:
			command=obj['get']
			method="GET"
		prev_state={}
		if 'flags' in obj:
			prev_state=self.make_flags(obj['flags'])
		data=self.op(command,params=params,method=method)

		if 'flags' in obj:
			self.return_state(prev_state)
		return_data=self.map_check(data,obj)
		if first:
			self.last_map_action=None
		return return_data

	def op(self,command,params={},post=False,etag=None,method="GET",body=None,raw=False,single=False):
		if ((post) and (method=="GET")):
			method="POST"

		if ((method == "GET") and (single)): # Return not paged GET request
			return self.op_single(command,params=params,post=post,etag=etag,method=method,body=body,raw=raw)

		first=self.op_single(command,params=params,method=method,body=body, raw=True)
		if first is None:
			return None
		data=self.json(first['data'])

		if type(data) is None:
			self.dbg('data is not valid json')
			return self.data_returner(first,raw)

		if not 'X-Pages' in first['headers']: # Single page responce
			return self.data_returner(first,raw)
		
		if not self.use_cache:
			self.dbg('cannot get consistented and verified paged data without cache')
			return self.data_returner(first,raw)
		
		pages_count=int(first['headers']['X-Pages'])
		consistent_try=0
		consistent=False
		result={'consistent':False,'pages_count':pages_count, 'result':[], 'result_hash':[], 'last_header':dict(first['headers']),'last_status':first['status_code']}
		while ( (not consistent) and (consistent_try < self.max_consistent_try)):
			consistent=False
			consistent_try=consistent_try+1
			self.dbg('get_all_pages')
			result=self.get_all_pages(first,pages_count,command,params,method,body) # Getting data
			self.cache.Sync()

			if result['consistent']:
				consistent=True
				break

			elif not result['validated_headers']: # Restart request pages if data changed
				continue

			self.dbg('check_consistent')
			check=self.check_consistent(pages_count,command,params,method,body,result['validate_array'])
			self.cache.Sync()
			if not check['consistent']:
				consistent=False
				pages_count=check['pages_count']
				continue
			consistent=True
			result['consistent']=check['consistent']
			result['pages_count']=check['pages_count']
			result['last_header']=check['last_header']
			result['last_status']=check['last_status']

		if consistent:
			if raw:
				return self.http_return_obj(self.use_cache,result['last_status'],result['result'],result['last_header'],True)
			return result['result']
		
		self.dbg('Cannot get consistent data')
		return self.http_return_obj(first['cached'],first['status_code'],first['data'],first['headers'],False)
