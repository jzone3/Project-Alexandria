import jinja2
import os
import webapp2
import secret
import hmac
import hashlib
import re
import urllib
from google.appengine.ext import db
import urllib2
from cStringIO import StringIO

from google.appengine.api import urlfetch
from google.appengine.ext import blobstore
from google.appengine.ext import webapp
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp.util import run_wsgi_app

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SCHOOL_RE= re.compile(r"^[a-zA-Z0-9 _]{1,30}$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

class PageHandler(webapp2.RequestHandler):
	'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		return self.request.get(name)

	def render(self, template, params={}):
		try:
			params['signed_in']
		except KeyError:
			params['signed_in'] = self.logged_in()
		template = jinja_env.get_template(template)
		self.response.out.write(template.render(params))

	def hash_str(self, string):
		return hmac.new(secret.SECRET, str(string), hashlib.sha512).hexdigest()

	def salted_hash(self, password, salt):
		return hashlib.sha256(password + salt).hexdigest()

	def logged_in(self):
		return True
		username = self.request.cookies.get('qwerty', '')
		if username and not username == '':
			name, hashed_name = username.split("|")
			if name and hashed_name and self.hash_str(name) == hashed_name:
				return True
			else:
				self.delete_cookie()
				return False
		else:
			return False

	def delete_cookie(self):
		self.response.headers.add_header('Set-Cookie', 'qwerty=; Path=/')

	def make_salt(self):
	    return ''.join(random.choice(string.letters) for x in xrange(5))

class Users(db.Model):
	username     = db.StringProperty(required = True)
	email        = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	grade        = db.IntegerProperty(required = True)
	score        = db.IntegerProperty(required = True) 
	confirmed    = db.BooleanProperty(required = True) 
	date_created = db.DateTimeProperty(auto_now_add = True)

class MainHandler(PageHandler):
	'''Handles homepage: index.html'''
	def get(self):
		logged_in = self.logged_in()

		if logged_in:
			self.render('dashboard.html', {'signed_in' : True})
		else:
			self.render('index.html', {'signed_in' : False})

	def post(self):
		which = self.rget('which')

		if which == 'login':
			username, original_password = (self.rget('username'), self.rget('password'))
			correct = False

			if username != '' and original_password != '':
				accounts = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")

				acc = accounts[0]
				(db_password, salt) = (acc.password).split("|")

				if self.salted_hash(original_password, salt) == db_password:
					correct = True
					self.response.headers.add_header('Set-Cookie', 'username=%s|%s; Path=/' % (str(username), str(self.hash_str(username))))
					self.redirect('/')
			if not correct:
				self.render('index.html', {'username' : username, 'wrong' : 'Invalid username and password!'})
		elif which == 'signup':
			username, password, verify, email, school, year, agree = (self.rget('username'), self.rget('password'), self.rget('verify'), self.rget('email'), self.rget('school'), self.rget('year'), self.rget('agree'))
			username_valid, password_valid, verify_valid, email_valid, school_valid, year_valid = (True, True, True, True, True, True)
			username_error, password_error, verify_error, email_error, school_error, year_error, agree_error = ('', '', '', '', '', '', '')
			
			if username != '' and not USER_RE.match(username):
				username_error = "That's not a valid username."
				username_valid = False
			if password != '' and not PASS_RE.match(password):
				password_error = "That's not a valid password."
				password_valid = False
			if verify != password:
				verify_error = "Your passwords didn't match."
				verify_valid = False
			if email != '' and not EMAIL_RE.match(email):
				email_error = "That's not a valid email."
				email_valid = False
			if school != '' and not SCHOOL_RE.match(school):
				school_error = "That is not a valid school name"
				school_valid = False
			if year != '' and (not (year in (int(a) for a in range(6,12))) and year != 'Later'):
				year_error = "That is not a valid grade level"
				year_valid = False
			if agree != 'on':
				agree_error = "You must agree to the Terms of Service to create an account"
			if not (username_valid and password_valid and verify_valid and email_valid and school_valid and year_valid):
				raise 'Something is invalid'
			# self.write(username + ' ' + password + ' ' + verify + ' ' + email + ' ' + school + ' ' + year )
			
			if username_valid and password_valid and verify_valid and email_valid and school_valid and year_valid and username != '' and password != '' and school != '' and year != '' and agree == 'on':
				self.response.headers.add_header('Set-Cookie', 'username=%s|%s; Path=/' % (str(username), self.hash_str(username)))

				same_username_db = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")
				same_username = same_username_db.get()

				if same_username:
					username_error = "Username already exists!"
				else:
					salt = self.make_salt()
					hashed = self.salted_hash(password, salt)
					hashed_pass = hashed + '|' + salt
					account = Users(username = username.replace("'", "&lsquo;"), email = email, password = hashed_pass, school = school, score = 0, confirmed = False)
					account.put()

					#add School database functionality... put entered school into db and or add user to school list

					self.redirect('/')

			self.render('index.html', {'email' : email,
										'username' : username,
										'username_error' : username_error,
										'password_error' : password_error,
										'verify_error' : verify_error,
										'email_error' : email_error,
										'school' : school,
										'school_error' : school_error,
										'year' : year_error,
										'agree_error' : agree_error})
		else:
			self.redirect('/')


class GuidesHandler(PageHandler):
	'''Handles guides: guides.html'''
	def get(self):
		self.render('guides.html', {'signed_in':self.logged_in()})

class AboutHandler(PageHandler):
	'''Handles about: about.html'''
	def get(self):
		self.render('about.html', {'signed_in':self.logged_in()})

class ContactHandler(PageHandler):
	'''Handles contact: contact.html'''
	def get(self):
		self.render('contact.html', {'signed_in':self.logged_in()})

class TeamHandler(PageHandler):
	'''Handles team: team.html'''
	def get(self):
		self.render('team.html', {'signed_in':self.logged_in()})

class DashboardHandler(PageHandler):
	'''Handlers dashboard: dashboard.html'''
	def get(self):
		self.render('dashboard.html', {'signed_in':self.logged_in()})

class GuidePageHandler(PageHandler):
	'''Handlers custom guide pages: guide_page.html'''
	def get(self, url):
		self.render('guide_page.html', {'signed_in':self.logged_in()})

class UserPageHandler(PageHandler):
	'''Handlers custom user pages: user_page.html'''
	def get(self, url):
		self.render('user_page.html', {'signed_in':self.logged_in()})

class UploadGuideHandler(PageHandler):
	def get(self):
		upload_url = blobstore.create_upload_url('/upload')
		self.render("uploads.html", {'upload_url': upload_url, 'signed_in':self.logged_in()})


class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
	def post(self):
		upload_files = self.get_uploads('file')  # 'file' is file upload field in the form
		blob_info = upload_files[0]
		self.redirect('/serve/%s' % blob_info.key())

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, resource):
		resource = str(urllib.unquote(resource))
		blob_info = blobstore.BlobInfo.get(resource)
		self.send_blob(blob_info)

app = webapp2.WSGIApplication([('/?', MainHandler),
							   ('/about', AboutHandler),
							   ('/guides', GuidesHandler),
							   ('/contact', ContactHandler),
							   ('/team', TeamHandler),
							   ('/dashboard', DashboardHandler),
							   ('/guides' + PAGE_RE, GuidePageHandler),
							   ('/user'+ PAGE_RE, UserPageHandler),
							   ('/uploads', UploadGuideHandler),
							   ('/upload', UploadHandler),
							   ('/serve/([^/]+)?', ServeHandler)
							   ], debug=True)
