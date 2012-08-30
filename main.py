import hashlib
import hmac
import jinja2
import logging
import os
import re
import urllib
import urllib2
import webapp2

import secret
import util

from google.appengine.api import files
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
		username = self.request.cookies.get(util.LOGIN_COOKIE_NAME, '')
		if username and not username == '':
			name, hashed_name = username.split("|")
			return name
		return None

	def render(self, template, params={}):
		if not params.get('signed_in'):
			params['signed_in'] = self.logged_in()
			if params['signed_in']:
				params['username'] = self.get_username()
		template = jinja_env.get_template(template)
		self.response.out.write(template.render(params))

	def logged_in(self):
		username = self.request.cookies.get(util.LOGIN_COOKIE_NAME, '')
		if username and not username == '':
			name, hashed_name = username.split("|")
			if name and hashed_name and util.hash_str(name) == hashed_name:
				return True
			else:
				self.delete_cookie(util.LOGIN_COOKIE_NAME)
				return False
		else:
			return False

	def set_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', cookie)

	def delete_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % cookie)


class MainHandler(PageHandler):
	'''Handles homepage: index.html and dashboard.html'''
	def get(self):
		logged_in = self.logged_in()

		if logged_in:
			self.render('dashboard.html', {'signed_in': True, 'username': self.get_username()})
		else:
			self.render('index.html', {'signed_in': False})

	def post(self):
		formname = self.rget('formname')

		if formname == 'login':
			username = self.rget('username')
			key, value = util.check_login(username, self.rget('password'))

			if key:
				if self.rget('remember') == 'on':
					value = value + ' Expires=' + util.remember_me() + ' Path=/'
					logging.error(value)
					self.set_cookie(value)
				else:
					self.set_cookie(value + ' Path=/')
				self.redirect('/')
			else:
				self.render('index.html', {'username': username, 'wrong': value, 'modal' : 'login'})

		elif formname == 'signup':
			username, password, verify, email, school, year, agree = ('', '', '', '', '', '', '')
			username_error, password_error, verify_error, email_error, school_error, year_error, agree_error = ('', '', '', '', '', '', '')

			username, password, verify, email, school, year, agree = [self.rget(x) for x in ('username', 'password', 'verify', 'email', 'school', 'year', 'agree')]
			results = util.signup(username=username, password=password, verify=verify, email=email, school=school, year=year, agree=agree)
			
			logging.error("Signing up")

			if results['success']:
				logging.error("Success")
				self.set_cookie(results['cookie'])
				self.redirect('/')	
			else:
				self.render('index.html', {'email': email,
										   'username': username,
										   'school': school,
										   'username_error': util.get_error(results, 'username'),
										   'password_error': util.get_error(results, 'password'),
										   'verify_error': util.get_error(results, 'verify'),
										   'email_error': util.get_error(results, 'email'),
										   'school_error': util.get_error(results, 'school'),
										   'year_error': util.get_error(results, 'year'),
										   'agree_error': util.get_error(results, 'agree'),
										   'modal' : 'signup'})
		else:
			self.redirect('/')

class LogoutHandler(PageHandler):
	'''Handles logging out'''
	def get(self):
		self.delete_cookie(util.LOGIN_COOKIE_NAME)
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
			self.render('dashboard.html', {'signed_in': True, 'username': self.get_username()})
		self.redirect('/')

class GuidePageHandler(PageHandler):
	'''Handlers custom guide pages: guide_page.html'''
	def get(self, url):
		self.render('guide_page.html')

class UserPageHandler(PageHandler):
	'''Handlers custom user pages: user_page.html'''
	def get(self, url):
		self.render('user_page.html')

class UploadHandler(PageHandler):
	def get(self):
		self.render('upload.html')

	def post(self):
		url = self.rget('file')
		result = urlfetch.fetch(url)

		if result.status_code != 200:
			return "some error"

		size = int(result.headers['content-length'])
		mime_type = result.headers['content-type']

		if size > 2097152:
			self.write('File size too big.')
			return

		if (mime_type != 'application/msword' and
			mime_type != 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' and
			mime_type != 'application/pdf'):
			self.write('Wrong file format.')
			return

		file_name = files.blobstore.create(mime_type=mime_type, _blobinfo_uploaded_filename='test')
		with files.open(file_name, 'a') as f:
  			f.write(result.content)

  		files.finalize(file_name)
  		blob_key = files.blobstore.get_blob_key(file_name)
  		self.redirect('/serve/' + str(blob_key))

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, resource):
		resource = str(urllib.unquote(resource))
		blob_info = blobstore.BlobInfo.get(resource)
		self.send_blob(blob_info, save_as=blob_info.filename)

app = webapp2.WSGIApplication([('/?', MainHandler),
							   ('/about/?', AboutHandler),
							   ('/logout/?', LogoutHandler),
							   ('/guides/?', GuidesHandler),
							   ('/contact/?', ContactHandler),
							   ('/team/?', TeamHandler),
							   ('/dashboard/?', DashboardHandler),
							   ('/guides/?' + util.PAGE_RE, GuidePageHandler),
							   ('/user/?'+ util.PAGE_RE, UserPageHandler),
							   ('/upload/?', UploadHandler),
							   ('/serve/([^/]+)?', ServeHandler)
							   ], debug=True)
