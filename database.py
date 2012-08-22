from google.appengine.ext import db

class Users(db.Model):
	username     = db.StringProperty(required = True)
	email        = db.StringProperty(required = True)
	pw_hash      = db.StringProperty(required = True)
	salt         = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	academy      = db.StringProperty(required = False)
	grade        = db.IntegerProperty(required = True)
	score        = db.IntegerProperty(required = True) 
	confirmed    = db.BooleanProperty(required = True) 
	date_created = db.DateTimeProperty(auto_now_add = True)

class Docs(db.Model):
	title        = db.StringProperty(required = True)
	subject      = db.StringProperty(required = True)
	teacher      = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	points       = db.IntegerProperty(required = True)
	edit_link    = db.StringProperty(required = True)
	locked       = db.VooleanProperty(required = True)
	user_created = db.StringProperty(required = True)    
	date_created = db.DateTimeProperty(auto_now_add = True)

class Comments(db.Model):
	doc_id       = db.IntegerProperty(required = True) 
	user_created = db.StringProperty(required = True)    
	comment      = db.TextProperty(required = True)  
	date_created = db.DateTimeProperty(auto_now_add = True)