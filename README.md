# Eve Simple ESI

The Python 3+ library for simple and **fast** work with https://esi.evetech.net data.

`Thanks Qandra-Si ( https://github.com/Qandra-Si ) for help and basis of implementation`

## This library can:

- locally autorize with eve-online user (with gui and without gui interface)
- automatically refresh authorization without gui
- get data (include data require authorization)
- post data (include data require authorization)

## install:

### pypi:
```
pip install eve-simple-esi
```

### manual:
Just put eve_simple_esi.py in the directory with your project

## how to use:

- **initialization**:
	```python
	import eve_simple_esi as esi

	settings={
		'client_id':"<Client ID>", # go to https://developers.eveonline.com/ create app and get Client ID
		'client_secret':"<Secret Key>", # go to https://developers.eveonline.com/ create app and get Secret Key
		'client_callback_url':"<Callback URL>", # default http://localhost:8635/ need to be same as in your app in https://developers.eveonline.com/
		'user_agent':"<User Agent string>",
		'scopes':<list of scopes>, # ['publicData','esi-location.read_location.v1',...etc.]
		'port':<port for local web server for authorization>, # default 8635
	}

	ESI=esi.ESI(settings)
	```
	
- **get data**:
	```python
	data=ESI.op('/characters/{character_id}/',params={'character_id':2117005244})
	```
	
- **get multipaged data**:
	```python
	data=ESI.op('/characters/{character_id}/assets/') # if cache is enabled you get all data from all pages with Etag and Last-Modified control
	# 'ESI.max_consistent_try' option can control maximum tries to get valid and consistent data (default 20)
	```
	
- **get forced single page data**:
	```python
	data=ESI.op('/characters/{character_id}/assets/',params={'page':6},single=True)
	```
	
- **post data**:
	```python
	data=ESI.op('/ui/autopilot/waypoint/',params={'add_to_beginning':False, 'clear_other_waypoints':False, 'destination_id':30000142}, method="POST")
	```
	
- **post data with body**:
	```python
	data=ESI.op('/universe/ids/',body=json.dumps(["Gila","Thrasher","Jita","CCP Alpha"]), method="POST")
	```

- **put data with body**:
	```python
	data=ESI.op('/fleets/{fleet_id}/',params={'fleet_id':123456789},body=json.dumps({"is_free_move": True,"motd": "Fleet now is Free Move"}), method="PUT")
	```
	
- **delete data**:
	```python
	data=ESI.op('/fleets/{fleet_id}/members/{member_id}/',params={'fleet_id':123456789,'member_id':987654321}, method="DELETE")
	```
	
- **get data with headers and other fields**:
	```python
	data=ESI.op('/characters/{character_id}/', raw=True)
	```
	
- **gui autorization**:
	```python
	ESI.gui_auth()
	```
	The builtin webserver starts only when needed for authorization and automatically shuts down when no authorization jobs found



- cli autorization:
	```python
	ESI.auth() #need to go by url and after autorization insert code from url (http://localhost:8635/?code=<requested_code>&state=...)
	```
	
- change character for request (if they storred):
	```python
	ESI.get("EVE Character Name") # if character never autorized in your program - ESI.gui_auth() or ESI.auth() calls automatically for login
	```

- **complicated requests**:

	**documentation**
	```
	#action_obj:
	{
		'get':str, 			# (Required) Api address of Action
		
		'link':str, 			# Create parameter with this link name and parent field data params.update({link:parent_field_data})
		
		'flags':list, 			# ESI flags for current action get request [flag,...] (individual for each action get request data). see supported flags
		
		'map':dict, 			# dict of anctions for fields {field_name:action_obj,...}
		
		'fields':list or str, 		# list of raw fields in result [field_name,...] (if it str return only this field raw data and ignore map and id functions)
		
		'name': str,			# rename parent field to this name
		
		'params': dict, 		# dict of additional params for request {'param_name':value,...}
		
		'list_filters':list of list 	# [[field_name,operator,value,filter_action], ...] 
						# operator can be '==', '!=', '<', '>', '<=', '>=', 'in', 'not in', 'startswith', 'endswith', 're' 
						# (with 're' operator your value must be compiled regexp object)
						# action can be 'skip', 'stop'. see supported filter_action
	}

	#supported flags:
	'force_cache' 	# get data from cache and dont check etag
	'debug' 	# turns on debug

	#supported filter_action:
	'skip'		# skip current row
	'stop'		# skip current row, immediatley return collected data and stop
	```
	**examples**
	- **get character data**:
		```python
		complicated_map={
			'get':'/characters/{character_id}/',
			'map':{
				'alliance_id':{
					'get':'/alliances/{alliance_id}/',
					'fields':['name','ticker'],
					'name':'alliance',
					'map':{
						'creator_id':{
							'link':'character_id',
							'get':'/characters/{character_id}/',
							'fields':['name'],
							'name':'creator'
						}
					}
				},
				'corporation_id':{
					'get':'/corporations/{corporation_id}/',
					'map':{
						'ceo_id':{
							'link':'character_id',
							'get':'/characters/{character_id}/',
							'fields':['name','security_status'],
							'name':'ceo'
						}
					},
					'name':'corporation',
					'fields':['name','ticker']
				}
			},
			'fields':['name','security_status','faction_id'],
			'id':'character_id'
		}
		data=ESI.map(complicated_map)
		```
		returns:
		```json
		{
			"name": "Samanta ZORG",
			"security_status": 4.550539685,
			"character_id": "2112184541",
			"alliance": {
				"name": "DEOS Alliance",
				"ticker": "DEOS",
				"alliance_id": 99005266,
				"creator": {
					"name": "De-Caelo",
					"character_id": 94177853
				}
			},
			"corporation": {
				"name": "DC Reunion",
				"ticker": "DCXLL",
				"corporation_id": 98313424,
				"ceo": {
					"name": "De-Caelo",
					"security_status": 1.496001863,
					"character_id": 94177853
				}
			}
		}
		```
	- **get corporate industry jobs**:
		```python
		complicated_map={
			'get':'/characters/{character_id}/',
			'flags':['force_cache'],
			'map':{
				'corporation_id':{
					'get':'/corporations/{corporation_id}/industry/jobs/',
					'map':{
						'product_type_id':{
							'link':'type_id',
							'get':'/universe/types/{type_id}/',
							'flags':['force_cache'],
							'fields':'name',
							'name':'job'
						},
						'installer_id':{
							'link':'character_id',
							'get':'/characters/{character_id}/',
							'flags':['force_cache'],
							'fields':'name',
							'name':'installer'
						},
						'facility_id':{
							'link':'structure_id',
							'get':'/universe/structures/{structure_id}/',
							'flags':['force_cache'],
							'fields':'name',
							'name':'facility'
						}
					},
					'fields':['job_id','start_date','end_date','status','runs','activity_id'],
					'params':{'include_completed':True},
					'name':'industry_jobs',
					'list_filters':[
						['status','==','delivered','skip'],
						['start_date','<',"2020-06-26T22:13:56Z",'stop'],
					]
				}
			}
		}
		data=ESI.map(complicated_map)
		```
		returns:
		```json
		[
			{
				"job_id": 432601643,
				"start_date": "2020-07-31T06:17:03Z",
				"end_date": "2020-07-31T21:00:30Z",
				"status": "cancelled",
				"runs": 1,
				"activity_id": 5,
				"corporation_id": 98313424,
				"job": "Strip Miner I Blueprint",
				"installer": "Simba Researcher",
				"facility": "A4B-V5 - Lab House"
			},
			{
				"job_id": 430265203,
				"start_date": "2020-07-08T13:14:32Z",
				"end_date": "2020-09-11T06:52:12Z",
				"status": "active",
				"runs": 1,
				"activity_id": 4,
				"corporation_id": 98313424,
				"job": "Capital Hull Repairer I Blueprint",
				"installer": "Irida ZORG",
				"facility": "A4B-V5 - Lab House"
			},
			{
				"job_id": 429341629,
				"start_date": "2020-06-29T15:31:43Z",
				"end_date": "2020-06-30T06:21:29Z",
				"status": "cancelled",
				"runs": 1,
				"activity_id": 5,
				"corporation_id": 98313424,
				"job": "Radio L Blueprint",
				"installer": "Himera dior",
				"facility": "A4B-V5 - Lab House"
			},
			...
		]
		```
- get character in initialize:
	```python
	ESI=esi.ESI(settings,name="EVE Character Name")
	```
	
- force cli autorization if no storred character:
	```python
	ESI=esi.ESI(settings,name="EVE Character Name", gui=False)
	```

- use multiplue instance:
	```python
	import eve_simple_esi as esi
	
	web_server=esi.ESIAuthWebServer(local_address='localhost', port=8635) # make one instance of webserver for all ESI instances
	
	ESI1=esi.ESI(settings, name="first EVE Character Name", callback_web_server=web_server)
	ESI2=esi.ESI(settings, callback_web_server=web_server)
	ESI3=esi.ESI(settings, callback_web_server=web_server)
	ESI3.gui_auth()
	```

- fash user switch:
	```python
	import eve_simple_esi as esi
	
	ESI=esi.ESI(settings, name="first EVE Character Name")
	data=ESI.op('/characters/{character_id}/')
	ESI.get("second EVE Character Name")
	data=ESI.op('/characters/{character_id}/')
	data=ESI.op('/ui/autopilot/waypoint/',params={'add_to_beginning':False, 'clear_other_waypoints':False, 'destination_id':30000142}, method="POST")
	ESI.get("third EVE Character Name")
	data=ESI.op('/characters/{character_id}/')
	```
	
- autoapply self character information if autorized:
	```python
	ESI=esi.ESI(settings,name="EVE Character Name")
	data=ESI.op('/characters/{character_id}/') # data for character_id with "EVE Character Name" name
	data=ESI.op('/characters/{character_id}/',params={'character_id':2117005244}) # data for character_id: 2117005244
	```
	
- you also can use your own function to get all messages from ESI class:
	```python
	def my_print_function(text_string):
		...
		print(text_string) # as example
		...
		
	ESI=esi.ESI(settings,callback_print=my_print_function)
	```
	
- and your own function for request auth_code:
	```python
	def my_input_function(text_string):
		...
		return input(text_string) # as example
		
	ESI=esi.ESI(settings,callback_input=my_input_function)
	```
	
- and your own class for store user data:
	```python
	class custom_callback_saved_data:
		def read(char_name):
			...
			return json.loads(saved_data)

		def write(char_name,data):
			saved_data=json.dumps(data)
			...
		
	ESI=esi.ESI(settings,callback_saved_data=custom_callback_saved_data)
	```
	
- and your own webserver class:
	```python
	class custom_callback_web_server:
		def __init__(self, address, port):
			...
		def reg_callback(state_string, on_success_function, on_error_function):
			...
		...
	ESI=esi.ESI(settings,callback_web_server=custom_callback_web_server)
	```

- and your own cache server class:
	```python
	class custom_callback_cache_server:
		def Get(self,key):
			#...
			if key in cache:
				return data
			else:
				return None
		def Del(self,key):
			#...
		def Set(self,key,data):
			#...
		def Clear(self):
			#...
		def Close(self):
			#...
		def Sync(self):
			#...
	
	ESI=esi.ESI(settings,callback_cache_server=custom_callback_cache_server)
	```
