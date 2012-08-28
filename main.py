import jinja2
import os
import webapp2
import secret
import hmac
import hashlib
import re
import urllib
import urllib2
import logging
from cStringIO import StringIO
import util

from google.appengine.api import urlfetch
from google.appengine.ext import blobstore
from google.appengine.ext import webapp
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp.util import run_wsgi_app

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class PageHandler(webapp2.RequestHandler):
	'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		return self.request.get(name)

	def get_username(self):
		username = self.request.cookies.get('uohferrvnksj', '')
		if username and not username == '':
			name, hashed_name = username.split("|")
			return name
		return None

	def render(self, template, params={}):
		try:
			params['signed_in']
		except KeyError:
			params['signed_in'] = self.logged_in()
			if params['signed_in']:
				params['username'] = self.get_username()
		template = jinja_env.get_template(template)
		self.response.out.write(template.render(params))

	def logged_in(self):
		username = self.request.cookies.get('uohferrvnksj', '')
		if username and not username == '':
			name, hashed_name = username.split("|")
			if name and hashed_name and util.hash_str(name) == hashed_name:
				return True
			else:
				self.delete_cookie('uohferrvnksj')
				return False
		else:
			return False

	def set_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', cookie)

	def delete_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % cookie)


class MainHandler(PageHandler):
	'''Handles homepage: index.html'''
	def get(self):
		logged_in = self.logged_in()

		if logged_in:
			self.render('dashboard.html', {'signed_in' : True, 'username' : self.get_username()})
		else:
			self.render('index.html', {'signed_in' : False})

	def post(self):
		which = self.rget('which')

		if which == 'login':
			
			key, value = util.check_login(username, self.rget('password'))

			if key:
				self.set_cookie(value)
				self.redirect('/')
			else:
				self.render('index.html', {'username' : username, 'wrong' : value})

		elif which == 'signup':
			username, password, verify, email, school, year, agree = ('', '', '', '', '', '', '')
			username, password, verify, email, school, year, agree = (self.get_username(), self.rget('password'), self.rget('verify'), self.rget('email'), self.rget('school'), self.rget('year'), self.rget('agree'))
			results = util.signup(username, password, verify, email, school, year, agree)
			username_error, password_error, verify_error, email_error, school_error, year_error, agree_error = ('', '', '', '', '', '', '')

			logging.error("Signing up")

			if results['success']:
				logging.error("Success")
				self.set_cookie(results['cookie'])
				self.redirect('/')
			else:
				logging.error("Failure")
				for key, value in results.iteritems():
					vars()[key + '_error'] = value
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
		self.render('guides.html')

class AboutHandler(PageHandler):
	'''Handles about: about.html'''
	def get(self):
		self.render('about.html')

class ContactHandler(PageHandler):
	'''Handles contact: contact.html'''
	def get(self):
		self.render('contact.html')

class TeamHandler(PageHandler):
	'''Handles team: team.html'''
	def get(self):
		self.render('team.html')

class DashboardHandler(PageHandler):
	'''Handlers dashboard: dashboard.html'''
	def get(self):
		if self.logged_in():
			self.render('dashboard.html', {'signed_in' : True, 'username' : self.get_username()})
		self.redirect('/')

class GuidePageHandler(PageHandler):
	'''Handlers custom guide pages: guide_page.html'''
	def get(self, url):
		self.render('guide_page.html')

class UserPageHandler(PageHandler):
	'''Handlers custom user pages: user_page.html'''
	def get(self, url):
		self.render('user_page.html')

class UploadGuideHandler(PageHandler):
	def get(self):
		upload_url = blobstore.create_upload_url('/upload')
		self.render("uploads.html")


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
							   ('/about/?', AboutHandler),
							   ('/guides/?', GuidesHandler),
							   ('/contact/?', ContactHandler),
							   ('/team/?', TeamHandler),
							   ('/dashboard/?', DashboardHandler),
							   ('/guides' + util.PAGE_RE, GuidePageHandler),
							   ('/user'+ util.PAGE_RE, UserPageHandler),
							   ('/uploads/?', UploadGuideHandler),
							   ('/upload/?', UploadHandler),
							   ('/serve/([^/]+)?', ServeHandler)
							   ], debug=True)
