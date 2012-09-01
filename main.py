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
from utils import *

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
		username = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
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
		username = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if username and not username == '':
			name, hashed_name = username.split("|")
			if name and hashed_name and hash_str(name) == hashed_name:
				return True
			else:
				self.delete_cookie(LOGIN_COOKIE_NAME)
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
			self.render('index.html', {'signed_in': False, 'blockbg':True})

	def post(self):
		formname = self.rget('formname')

		if formname == 'login':
			username = self.rget('username')
			key, value = check_login(username, self.rget('password'))

			if key:
				if self.rget('remember') == 'on':
					value = value + ' Expires=' + remember_me() + ' Path=/'
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
			results = signup(username=username, password=password, verify=verify, email=email, school=school, year=year, agree=agree)
			
			logging.error("Signing up")

			if results['success']:
				logging.error("Success")
				self.set_cookie(results['cookie'])
				self.redirect('/')	
			else:
				self.render('index.html', {'email': email,
										   'username': username,
										   'school': school,
										   'username_error': get_error(results, 'username'),
										   'password_error': get_error(results, 'password'),
										   'verify_error': get_error(results, 'verify'),
										   'email_error': get_error(results, 'email'),
										   'school_error': get_error(results, 'school'),
										   'year_error': get_error(results, 'year'),
										   'agree_error': get_error(results, 'agree'),
										   'modal' : 'signup'})
		else:
			self.redirect('/')

class LogoutHandler(PageHandler):
	'''Handles logging out'''
	def get(self):
		self.delete_cookie(LOGIN_COOKIE_NAME)
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
		url = url[1:]
		q = Guides.all()
		q.filter('url =', url)
		result = q.get()
		if result:
			votes = str_votes(result.votes)
			dl_link = '/serve/' + result.blob_key
			self.render('guide_page.html', {'result':result, 'votes':votes, 'dl_link':dl_link})
		else:
			self.write('Guide not found.')

class UserPageHandler(PageHandler):
	'''Handlers custom user pages: user_page.html'''
	def get(self, url):
		url = url[1:]
		q = Users.all()
		q.filter('username =', url)
		result = q.get()
		if result:
			score = str_votes(result.score)
			grade = str_grade(result.grade)
			self.render('user_page.html', {'result':result, 'grade':grade, 'score':score})
		else:
			self.write('User not found.')

class UploadHandler(PageHandler):
	def get(self):
		self.render('upload.html')

	def post(self):
		title = self.rget('title')
		subject = self.rget('subject')
		teacher = self.rget('teacher')
		locked = self.rget('locked')
		doc_url = self.rget('doc_url')
		tags = self.rget('tags')
		file_url = self.rget('file')
		if file_url:
			# get the file from filepicker.io
			result = urlfetch.fetch(file_url)
			headers = result.headers
			if result.status_code != 200:
				self.write("Connection Error.")
				return
			errors = upload_errors(title, subject, teacher, locked, doc_url, headers)
		else:
			errors = upload_errors(title, subject, teacher, locked, doc_url, 
				                   {'content-type':'text/plain', 'content-length':'0'})
			errors['file_error'] = 'Please upload a file.'

		if any(errors.values()):
			fields = {'title':title, 'subject':subject, 'teacher':teacher, 
					  'locked':locked, 'doc_url':doc_url, 'tags':tags}
			errors.update(fields)
			self.render('/upload.html', errors)
		else:
			tags = get_tags(tags)
			username = self.get_username()
			doc_name = get_name(title, username)
			school = get_school(username)
			if locked: 
				locked = True
			else: 
				locked = False

			# write file to blobstore
			file_name = files.blobstore.create(mime_type=headers['content-type'], _blobinfo_uploaded_filename=doc_name)
			with files.open(file_name, 'a') as f:
	  			f.write(result.content)
	  		files.finalize(file_name)
	  		blob_key = files.blobstore.get_blob_key(file_name)

	  		guide = Guides(user_created=username, title=title, subject=subject,
	  			   teacher=teacher, tags=tags, blob_key=str(blob_key), locked=locked,
	  			   votes=0, edit_link=doc_url, school=school, url=doc_name)
	  		guide.put()
	  		self.redirect('/guides/' + doc_name)

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, resource):
		resource = str(urllib.unquote(resource))
		blob_info = blobstore.BlobInfo.get(resource)
		self.send_blob(blob_info, save_as=blob_info.filename)

from search import *
from collections import Counter

class Tags(db.Model):
	tags = db.StringListProperty()
	title = db.StringProperty()

for entry in db_entries:
	t = Tags(tags=entry['tags'], title=entry['title'])
	t.put()

class Test(PageHandler):
	def get(self):
		keywords = ['notes']
		queries = []
		for k in keywords:
			query = db.Query(Tags)
			query.filter('tags =', k)
			results = query.run()
			map(lambda x: queries.append(x), results)

		#counts = Counter(queries)
		for result in results:
			self.write(queries)



app = webapp2.WSGIApplication([('/?', MainHandler),
							   ('/about/?', AboutHandler),
							   ('/logout/?', LogoutHandler),
							   ('/guides/?', GuidesHandler),
							   ('/contact/?', ContactHandler),
							   ('/team/?', TeamHandler),
							   ('/dashboard/?', DashboardHandler),
							   ('/guides/?' + PAGE_RE, GuidePageHandler),
							   ('/user/?'+ PAGE_RE, UserPageHandler),
							   ('/upload/?', UploadHandler),
							   ('/serve/([^/]+)?', ServeHandler),
							   ('/test', Test)
							   ], debug=True)
