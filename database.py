from django.utils import simplejson

from google.appengine.ext import db

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

class Users(db.Model):
	username     = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	grade        = db.IntegerProperty(required = True)
	score        = db.IntegerProperty(required = True) 
	confirmed    = db.BooleanProperty(required = True) 
	password     = db.StringProperty(required = False)
	date_created = db.DateTimeProperty(auto_now_add = True)
	email        = db.StringProperty(required = False)

class Guides(db.Model):
	user_created = db.StringProperty(required = True)
	title        = db.StringProperty(required = True)
	subject      = db.StringProperty(required = True)
	teacher      = db.StringProperty(required = True)
	tags         = db.StringListProperty(required = True)
	blob_key     = db.StringProperty(required = True)
	locked       = db.BooleanProperty(required = False) #! delete this before final deploy
	votes        = db.IntegerProperty(required = True) 
	edit_url     = db.StringProperty(required = False) #! change to true before final deploy
	school       = db.StringProperty(required = True)
	url          = db.StringProperty(required = True) #! change to dl_url
	date_created = db.DateTimeProperty(auto_now_add = True)
	users_voted  = JsonProperty()

class Bookmarks(db.Model):
	user         = db.ReferenceProperty(Users)
	guide        = db.ReferenceProperty(Guides)

class Feedback(db.Model):
	content      = db.TextProperty(required = True)
	origin       = db.StringProperty(required = True)

class Teachers(db.Model):
	school        = db.StringProperty(required = True)
	teachers_list = db.StringListProperty(required = True)

class Subjects(db.Model):
	school        = db.StringProperty(required = True)
	subjects_list = db.StringListProperty(required = True)

class Teacher_Subjects(db.Model):
	'''List subjects for a teacher'''
	school        = db.StringProperty(required = True)
	teacher       = db.StringProperty(required = True)
	subjects_list = db.StringListProperty(required = True)

class Subject_Teachers(db.Model):
	'''List of teachers for a subject'''
	school        = db.StringProperty(required = True)
	subject       = db.StringProperty(required = True)
	teachers_list = db.StringListProperty(required = True)

class Indexes(db.Model):
	school = db.StringProperty(required = True)
	index  = JsonProperty()