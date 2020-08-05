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

class ESI:
	def __init__(self,
		settings,
		name=None,
		gui=True,
		debug=False,
		callback_print=None,
		callback_input=None,
		callback_web_server=None,
		callback_saved_data=None
		):
		"""Prints the URL to redirect users to.
		Args:
			settings: (Required) settings object with client_id, client_secret etc..
			name: (None) string with name for autoauth storred user
			gui: (True) bool for prefer auth method
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
		"""
		self.settings=self.configure(settings)

		self.gui = gui

		self.user_auth={}

		self.refresh_token = ''
		self.access_token = ''
		self.expired = -1

		self.auth_code = ''
		self.random = ''
		self.unique_state = ''

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

		if callable(callback_saved_data):
			self.storage=callback_saved_data
		else:
			self.storage=ESIUserDataStorage()

		if type(name) == str:
			self.get(name)

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
							issuer=self.settings['esi_proto']+self.settings['login_host']
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
				'user_agent':"ESI Class 0.1",
				'esi_url':"esi.evetech.net/latest/",
				'esi_proto':"https://",
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

		self.p(form_values)

		res = self.session.post(
			self.settings['token_req_url'],
			data=form_values,
			headers=headers,
		)

		self.p("Request sent to URL {} with headers {} and form values: "
			"{}\n".format(res.url, headers, form_values))
		res.raise_for_status()

		return res

	def send_esi_request_http(self, uri, etag, body=None):
		headers = {
			"Authorization": "Bearer {}".format(self.access_token),
		}
		if not (etag is None) and (body is None):
			headers.update({"If-None-Match": etag})
		if self.settings['user_agent']:
			headers.update({"User-Agent": self.settings['user_agent']})

		try:
			if body is None:
				res = self.session.get(uri, headers=headers)
				if self.debug:
					self.p("\nMade GET request to {} with headers: "
							"{}\nAnd the answer {} was received with "
							"headers {} and encoding {}".
							format(uri,
									res.request.headers,
									res.status_code,
									res.headers,
									res.encoding))
			else:
				headers.update({"Content-Type": "application/json"})
				res = self.session.post(uri, data=body, headers=headers)
				if self.debug:
					self.p("\nMade POST request to {} with data {} and headers: "
							"{}\nAnd the answer {} was received with "
							"headers {} and encoding {}".
							format(uri,
									body,
									res.request.headers,
									res.status_code,
									res.headers,
									res.encoding))
			res.raise_for_status()
		except requests.exceptions.HTTPError as err:
			self.p(err)
			json_error=res.json()
			self.p(json_error)
			if ((json_error) and (json_error['error']=='token is expired')):
				self.re_auth()
				return self.send_esi_request_http(uri, etag, body)
			else:
				return res
			#raise
		except:
			self.p(sys.exc_info())
			#raise

		#debug = str(res.status_code) + " " + uri[31:]
		#if ('Last-Modified' in res.headers):
		#    debug = debug + " " + str(res.headers['Last-Modified'])[17:-4]
		#if ('Etag' in res.headers):
		#    debug = debug + " " + str(res.headers['Etag'])
		#print(debug)

		return res

	def send_esi_request_json(self, uri, etag, body=None):
		res=self.send_esi_request_http(uri, etag, body)
		if res.content == b'':
			return {}
		else:
			return res.json()

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
		self.p(self.auth_url(code_challenge=self.create_code_challenge()))

		self.auth_code = self.i("Copy the \"code\" query parameter and enter it here: ")
		return self.auth_part2()

	def create_code_challenge(self):
		self.random = base64.urlsafe_b64encode(secrets.token_bytes(32))
		m = hashlib.sha256()
		m.update(self.random)
		d = m.digest()
		code_challenge = base64.urlsafe_b64encode(d).decode().replace("=", "")
		return code_challenge

	def gui_auth(self):
		self.p("Follow the prompts and enter the info asked for.")
		self.auth_url(code_challenge=self.create_code_challenge())
		self.web_server.reg_callback(state=self.unique_state, on_success=self.success_auth_code, on_error=self.error_auth_code)
		return self.open_url()

		#auth_code = input("Copy the \"code\" query parameter and enter it here: ")	#Webserver and browser here

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
		self.p("\nThe contents of the access token are: {}".format(validated_jwt))
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
			self.p('Character data readed')
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

	def open_url(self):
		self.window=webview.create_window('Auth', self.full_auth_url, width=580, height=1024) #580 x 1024
		webview.start()
		if self.WebServer:
			self.WebServer.shutdown()
		if self.auth_code == '':
			return False
		return True

	def success_auth_code(self,query):
		self.set_auth_code(query)
		self.window.destroy()

	def error_auth_code(self,query):
		self.window.destroy()
		self.p(self.path)

	def set_auth_code(self,query):
		if query['state'][0] == self.unique_state:
			self.p('Authorization server valid')
		self.auth_code=query['code']
		self.p(self.auth_part2())

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

	def op(self,command,params={},post=False,etag=None,body=None):
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
				self.p('Error, no variable {} in params'.format(var))
				return None
		uri=self.settings['esi_url']+"".join(splitted)
		uri=self.settings['esi_proto']+uri.replace('//','/')

		postURI=params
		postURI.update({'token':self.refresh_token})
		postURI=urllib.parse.urlencode(params)
		uri=uri+"?"+postURI
		if post:
			body=""
		return self.send_esi_request_json(uri, etag, body)
