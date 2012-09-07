import hashlib
import hmac
import jinja2
import logging
import os
import re
import urllib2
import webapp2

import secret
from search import *
from utils import *

import externals.ayah
from google.appengine.api import files
from google.appengine.api import urlfetch
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp.util import run_wsgi_app

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class BaseHandler(webapp2.RequestHandler):
	'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		return self.request.get(name)

	def get_username(self):
		username = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if username and not username == '':
			return username.split("|")[0]
		return None

	def list_to_str(self, lst):
		to_return = '['
		for i in lst:
			if i == lst[len(lst) - 1]:
				to_return += '"' + i + '"]'
			else:
				to_return += '"' + i + '",'
		return to_return

	def render(self, template, params={}):
		params['signed_in'] = self.logged_in()
		if params['signed_in']:
			params['username'] = self.get_username()
		else:
			# setup school list for typeahead
			params['all_schools'] = self.list_to_str(get_schools())
			# set username to blank
			if not 'username' in params.keys():
				params['username'] = ''
			# setup areyouahuman
			externals.ayah.configure('9ee379aab47a91907b9f9b505204b16494367d56', 
									 '7ec7c6561c6dba467095b91dd58778f2c60fbaf2')
			widget_html = externals.ayah.get_publisher_html()
			params['widget_html'] = widget_html

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


class MainHandler(BaseHandler):
	'''Handles homepage: index.html and dashboard.html'''
	def get(self):
		logged_in = self.logged_in()

		if self.rget('q'):
			self.redirect('/search?q=' + self.rget('q'))

		if logged_in:
			self.render('dashboard.html')
		else:
			self.render('index.html', {'blockbg':True})

	def post(self):
		formname = self.rget('formname')

		if formname == 'login':
			username = self.rget('username')
			key, value = check_login(username, self.rget('password'))

			if key:
				if self.rget('remember') == 'on':
					value = value + ' Expires=' + remember_me() + ' Path=/'
					self.set_cookie(value)
				else:
					self.set_cookie(value + ' Path=/')
				self.set_cookie(str('school=%s'%get_school(username)))
				self.redirect('/')
			else:
				self.render('index.html', {'username': username, 'wrong': value, 'modal' : 'login'})

		elif formname == 'signup':
			username, password, verify, school, year, agree, human, email = ('', '', '', '', '', '', '', '')
			username_error, password_error, verify_error, school_error, year_error, agree_error, human_error, email_error = ('', '', '', '', '', '', '', '')

			username, password, verify, school, year, agree, human, email = [self.rget(x) for x in ('username', 'password', 'verify', 'school', 'year', 'agree', 'session_secret', 'email')]
			results = signup(username=username, password=password, verify=verify, school=school, year=year, agree=agree, human=human, email=email)
			
			if results['success']:
				add_school(school)
				self.set_cookie(results['cookie'])
				self.set_cookie(str('school=%s'%school))
				self.redirect('/')	
			else:
				self.render('index.html', {'username': username,
										   'school': school,
										   'email' : email,
										   'email_error' : get_error(results, 'email'),
										   'username_error': get_error(results, 'username'),
										   'password_error': get_error(results, 'password'),
										   'verify_error': get_error(results, 'verify'),
										   'school_error': get_error(results, 'school'),
										   'year_error': get_error(results, 'year'),
										   'agree_error': get_error(results, 'agree'),
										   'human_error': get_error(results, 'human'),
										   'modal': 'signup'})

		else:
			self.redirect('/')

class LogoutHandler(BaseHandler):
	'''Handles logging out'''
	def get(self):
		self.delete_cookie(LOGIN_COOKIE_NAME)
		self.redirect('/')

class GuidesHandler(BaseHandler):
	'''Handles guides: guides.html'''
	def get(self):
		if self.rget('q'):
			self.redirect('/search?q=' + self.rget('q'))
		self.render('guides.html')

class AboutHandler(BaseHandler):
	'''Handles about: about.html'''
	def get(self):
		self.render('about.html')

class ContactHandler(BaseHandler):
	'''Handles contact: contact.html'''
	def get(self):
		self.render('contact.html')

class TeamHandler(BaseHandler):
	'''Handles team: team.html'''
	def get(self):
		self.render('team.html')

class DashboardHandler(BaseHandler):
	'''Handlers dashboard: dashboard.html'''
	def get(self):
		if self.rget('q'):
			self.redirect('/search?q=' + self.rget('q'))

		if self.logged_in():
			self.render('dashboard.html')
		else:
			self.redirect('/')

class GuidePageHandler(BaseHandler):
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
			self.error(404)
			self.render('guide404.html')

class UserPageHandler(BaseHandler):
	'''Handlers custom user pages: user_page.html'''
	def get(self, url):
		url = url[1:]
		q = Users.all()
		q.filter('username =', url)
		result = q.get()
		if result:
			score = int(str_votes(result.score))
			grade = str_grade(result.grade)
			self.render('user_page.html', {'result':result, 'grade':grade, 'score':score})
		else:
			self.error(404)
			self.render('user404.html', {'user' : url})

class UploadHandler(BaseHandler):
	def get(self):
		if self.logged_in():
			self.render('upload.html')
		else:
			self.redirect('/')

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
			tags = get_tags(tags) + create_tags(title, subject, teacher)
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
	  		
	  		# add guide to index
	  		key = str(guide.key())
	  		add_to_index(school, key, tags)

	  		self.redirect('/guides/' + doc_name)

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, resource):
		resource = str(urllib.unquote(resource))
		blob_info = blobstore.BlobInfo.get(resource)
		self.send_blob(blob_info, save_as=blob_info.filename)

class NotFoundHandler(BaseHandler):
	def get(self):
		self.error(404)
		self.render('404.html')

class ToSHandler(BaseHandler):
	def get(self):
		self.render('tos.html')

class SearchHandler(BaseHandler):
	def get(self):
		query = self.rget('q')
		school = self.request.cookies.get('school')
		if not school:
			school = 'Bergen County Academies'
		rankings = search(school, query)
		results = []

		for ranking in rankings:
			# get guides by key
			guide = Guides.get(ranking[0])
			# format results
			result = {'url':guide.url, 'title':guide.title, 'subject':guide.subject,
					  'teacher':guide.teacher, 'votes':str_votes(guide.votes)}
			results.append(result)

		if results:
			self.render('search.html', {'results':results})
		else:
			self.render('search.html')

class Test(BaseHandler):
	def get(self):
		externals.ayah.configure('9ee379aab47a91907b9f9b505204b16494367d56', '7ec7c6561c6dba467095b91dd58778f2c60fbaf2')
		html = externals.ayah.get_publisher_html()
		self.write('<form method="post"><input type="text">'+html+'<button type="submit"></button></form>')

	def post(self):
		secret = self.rget('session_secret')
		externals.ayah.configure('9ee379aab47a91907b9f9b505204b16494367d56', '7ec7c6561c6dba467095b91dd58778f2c60fbaf2')
		if externals.ayah.score_result(secret):
			self.write(secret)
		else:
			self.write('no')

class PreferencesHandler(BaseHandler):
	def get(self):
		if self.logged_in():
			self.render('prefs.html')
		else:
			self.redirect('/prefs.html')


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
							   ('/tos/?', ToSHandler),
							   ('/preferences/?', PreferencesHandler),
							   ('/search', SearchHandler),	
							   ('/test', Test),						   
							   ('/.*', NotFoundHandler),
							   ], debug=True)
