from django.utils import simplejson

from google.appengine.ext import db

class Users(db.Model):
	username     = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	grade        = db.IntegerProperty(required = True)
	score        = db.IntegerProperty(required = True) 
	confirmed    = db.BooleanProperty(required = True) 
	password     = db.StringProperty(required = True)
	date_created = db.DateTimeProperty(auto_now_add = True)
	email        = db.StringProperty(required = True)

class Guides(db.Model):
	user_created = db.StringProperty(required = True)
	title        = db.StringProperty(required = True)
	subject      = db.StringProperty(required = True)
	teacher      = db.StringProperty(required = True)
	tags         = db.StringListProperty(required = True)
	blob_key     = db.StringProperty(required = True)
	locked       = db.BooleanProperty(required = True)
	votes        = db.IntegerProperty(required = True) 
	edit_link    = db.StringProperty(required = False)
	school       = db.StringProperty(required = True)
	url          = db.StringProperty(required = True)
	date_created = db.DateTimeProperty(auto_now_add = True)

# stores dictionaries as JSON objects in datastore
class JsonProperty(db.TextProperty):
	def validate(self, value):
		return value

	def get_value_for_datastore(self, model_instance):
		'''creates value for datastore'''
		result = super(JsonProperty, self).get_value_for_datastore(model_instance)
		result = simplejson.dumps(result)
		return db.Text(result)

	def make_value_from_datastore(self, value):
		'''makes value for dictionary'''
		try:
			value = simplejson.loads(str(value))
		except:
			pass
		return super(JsonProperty, self).make_value_from_datastore(value)

class Indexes(db.Model):
	school = db.StringProperty(required = True)
	index  = JsonProperty()