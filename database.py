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
	username       = db.StringProperty(required = True)
	school         = db.StringProperty(required = True)
	grade          = db.IntegerProperty(required = False)
	score          = db.IntegerProperty(required = True) 
	confirmed      = db.BooleanProperty(required = True) 
	password       = db.StringProperty(required = False)
	date_created   = db.DateTimeProperty(auto_now_add = True)
	email          = db.StringProperty(required = False)
	bergen_mail    = db.StringProperty(required = False)
	email_verified = db.BooleanProperty(required = False)

class Guides(db.Model):
	user_created = db.StringProperty(required = True)
	title        = db.StringProperty(required = True)
	subject      = db.StringProperty(required = True)
	teacher      = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	blob_key     = db.StringProperty(required = True) # url for download
	edit_url     = db.StringProperty(required = False) # url for google doc
	url          = db.StringProperty(required = True) # url for guide page
	tags         = db.StringListProperty(required = True)
	icon         = db.StringProperty(required = True)
	report_users = db.StringListProperty(required = True)
	date_created = db.DateTimeProperty(auto_now_add = True)
	votes        = db.IntegerProperty(required = True)
	up_users     = db.StringListProperty()
	down_users   = db.StringListProperty()
	misc         = db.StringProperty(required = False)

class Email_Verification(db.Model):
	username      = db.StringProperty(required = True)
	date_created  = db.DateTimeProperty(auto_now_add = True)

class Bookmarks(db.Model):
	user  = db.ReferenceProperty(Users, collection_name='bookmark_list')
	guide = db.ReferenceProperty(Guides)

class Feedback(db.Model):
	content = db.TextProperty(required = True)
	origin  = db.StringProperty(required = True)

class Teachers(db.Model):
	school        = db.StringProperty(required = True)
	teachers_list = db.StringListProperty(required = True)

class Subjects(db.Model):
	school        = db.StringProperty(required = True)
	subjects_list = db.StringListProperty(required = True)

class ActiveTeachers(db.Model):
	school        = db.StringProperty(required = True)
	active_teachers_list = db.StringListProperty(required = True)

class ActiveSubjects(db.Model):
	school        = db.StringProperty(required = True)
	active_subjects_list = db.StringListProperty(required = True)

class Teacher_Subjects(db.Model):
	'''List subjects for a teacher'''
	school        = db.StringProperty(required = True)
	teacher       = db.StringProperty(required = True)
	subjects_list = db.StringListProperty(required = True)
	is_guides     = db.BooleanProperty(required = False)

class Subject_Teachers(db.Model):
	'''List of teachers for a subject'''
	school        = db.StringProperty(required = True)
	subject       = db.StringProperty(required = True)
	teachers_list = db.StringListProperty(required = True)
	is_guides     = db.BooleanProperty(required = False)

class Indexes(db.Model):
	school = db.StringProperty(required = True)
	index  = JsonProperty()

class Notification(db.Model):
	username     = db.StringProperty(required = True)
	is_new       = db.BooleanProperty(required = True)
	name         = db.StringProperty(required = False)
	notification = db.StringProperty(required = False)

class SubjectIcons(db.Model):
	subject = db.StringProperty(required = True)
	icon    = db.StringProperty(required = True)
