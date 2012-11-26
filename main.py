## import python modules
import cgi
import datetime
import hashlib
import hmac
import jinja2
import logging
import os
import re
import urllib
import urllib2
import webapp2

## import application modules
import secret
from models.database import *
from tools.search import *
from tools.utils import *

## import external modules
import externals.ayah
import externals.gdata.gauth
import externals.gdata.docs.service
import externals.gdata.docs.data

## import GAE modules
from google.appengine.api import files
from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.api import datastore_errors
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.api import memcache
		
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)
jinja_env.filters['str_votes'] = str_votes

##### Important handlers #####

class BaseHandler(webapp2.RequestHandler):
	'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		'''Gets a HTTP parameter'''
		return self.request.get(name)

	def get_username(self):
		'''Gets the username if the user cookie is valid'''
		user_cookie = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if self.logged_in():
			return user_cookie.split("|")[0]
		else:
			return None

	def render(self, template, params={}):
		'''Renders template using params and other parameters'''
		if template == 'index.html':
			params['main_page'] = True
		elif template == '404.html':
			params['not_found'] = True
		params['signed_in'] = self.logged_in()
		params['bg'] = self.request.cookies.get('bg', '')
		if params['signed_in']:
			params['username'] = self.get_username()
			# check for notifications
			notification_list, is_new = get_notifications(params['username'])
			notification_html = get_notification_html(notification_list)
			params['notification_html'] = notification_html
			params['new_notif'] = is_new		
		else:
			# get schools list for typeahead
			params['all_schools'] = get_schools_list()
			# set username to blank
			if 'username' not in params:
				params['username'] = ''
			# setup areyouahuman
			externals.ayah.configure('9ee379aab47a91907b9f9b505204b16494367d56', 
									 '7ec7c6561c6dba467095b91dd58778f2c60fbaf2')
			widget_html = externals.ayah.get_publisher_html()
			params['widget_html'] = widget_html

		if template == 'prefs.html':
			params['all_schools'] = get_schools_list()

		template = jinja_env.get_template(template)
		self.response.out.write(template.render(params))

	def render_prefs(self, params={}):
		'''Renders the preferences page using specific parameters and params'''
		username = self.get_username()
		user = get_user(username)
		email, email_verified = None, None

		if 'email' not in params:
			if hasattr(user, 'email'):
				email = user.email
		else:
			email = params.pop('email')

		if user.school == "Bergen County Academies":
			if user.bergen_mail:
				email = user.bergen_mail

		if 'email_verified' not in params:
			if hasattr(user, 'email_verified'):
				email_verified = user.email_verified
		else:
			email_verified = params.pop('email_verified')

		school = self.get_school_cookie()
		if 'school' in params:
			del params['school']

		params.update({'email':email, 'email_verified':email_verified, 'school':school, 'prefs':True, 'user':user})
		self.render('prefs.html', params)

	def logged_in(self, username = None):
		'''Checks if login cookie is valid (authenticates user)'''
		username = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
		if username:
			name, hashed_name = username.split("|")
			if name and hashed_name and hash_str(name) == hashed_name:
				return True
			else:
				self.delete_cookie(LOGIN_COOKIE_NAME)
				self.delete_cookie('school')
				return False
		return False

	def set_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', cookie)

	def delete_cookie(self, cookie):
		self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % cookie)

	def set_school_cookie(self, school):
		'''Sets and formats school cookie'''
		school = str(school).replace(' ', '_')
		self.set_cookie('school='+school)

	def get_school_cookie(self):
		'''Retrieves school and formats from cookie'''
		school = self.request.cookies.get('school', '')
		if school:
			school = school.replace('_', ' ')
			if school in get_schools():
				return school
		school = get_school(self.get_username())
		self.set_school_cookie(school)
		return school

class DashboardHandler(BaseHandler):
	'''Handlers dashboard: dashboard.html'''
	def get(self):
		if self.rget('q'):
			self.redirect('/search?q=' + self.rget('q'))

		tour = False # first log in tour
		if self.rget('tour') == 'True':
			tour = True

		username = self.get_username()
		if username:
			user = get_user(username)
			bookmark_list = list(user.bookmark_list)
			self.render('dashboard.html', {'bookmark_list':bookmark_list, 'tour':tour})
		else:
			self.redirect('/')

class DeleteAccountHandler(BaseHandler):
	def get(self):
		username = self.get_username()
		if username:
			self.render('delete_account.html', {'google_account':is_google_account(username)})
		else:
			self.redirect('/')

	def post(self):
		username = self.get_username()
		if username:			
			if is_google_account(username):
				self.delete_account(username)
			else:
				password = self.rget('password')
				if check_login(username, password):
					feedback = self.rget('feedback')
					self.delete_account(username)
				else:
					self.render('/delete_account')
		else:
			self.redirect('/')

	def delete_account(self, username):
		feedback = self.rget('feedback')
		if feedback:
			save_feedback(feedback, username)
		delete_user_account(username)
		self.delete_cookie(LOGIN_COOKIE_NAME)
		self.delete_cookie('school')
		self.redirect('/')

class DeleteEmailVerification(BaseHandler):
	def get(self, key):
		try:
			if deleted(key):
				self.render('email_deleted.html')
			else:
				self.error(404)
				self.render('404.html', {'blockbg':True})
		except datastore_errors.BadKeyError:
			self.error(404)
			self.render('404.html', {'blockbg':True})

class EmailVerificationHandler(BaseHandler):
	def get(self, key):
		try:
			if verify(key):
				self.render('email_verified.html')
			else:
				self.error(404)
				self.render('404.html', {'blockbg':True})
		except datastore_errors.BadKeyError:
			self.error(404)
			self.render('404.html', {'blockbg':True})

class ExternalSignUp(BaseHandler):
	'''Handles external signup: /ext_signup'''
	def get(self):
		user = users.get_current_user()
		if not user:
			self.redirect('/google_signup')

		# unique email check	
		q = Users.all()
		q.filter('email =', user.email())
		if q.get():
			self.render('index.html', {'blockbg':True, 'modal':'signup',
						'ext_duplicate_error':'Someone is already using that account. Did you mean to <a href="#login" role="button" data-toggle="modal" onclick="$(\'#signup\').modal(\'hide\')">log in</a>?'})
			return

		self.render('external_signup.html', {'ext':True})

	def post(self):
		user = users.get_current_user()
		if user:
			username = self.rget('username')
			school = self.rget('school')
			agree = self.rget('agree')

			if school == 'Bergen County Academies':
				email = self.rget('email') + '@bergen.org'
				ext_email = user.email()
			else:
				email = user.email()
				ext_email = ''

			result = signup_ext(username, school, agree, email, ext_email)

			if result['success']:
				# set user cookie
				cookie = result['cookie']
				self.set_cookie(cookie)
				#set school cookie
				self.set_school_cookie(school)
				self.redirect('/dashboard?tour=True')
			else:
				self.render('external_signup.html', {'username':username, 'school':school, 'email':email[:-11], 
					'ext':True, 'email_error':result.get('email_error'), 'agree_error':result.get('agree_error'),
					'school_error':result.get('school_error'), 'username_error':result.get('username_error')})
		else:
			self.redirect('/google_signup')

class GoogleLoginHandler(BaseHandler):
	'''Handles google login: /google_login'''
	def google_login(self, user):
		account = memcache.get('useremail-'+user.email())
		if account:
			logging.info('CACHE GLOGIN: '+user.email())
		else:
			logging.info('DB GLOGIN: '+user.email())
			q = Users.all()
			q.filter('email =', user.email())
			account = q.get()

			memcache.set('useremail-'+user.email(), account)
			logging.info('CACHE set glogin useremail-'+user.email())

		if account:
			username = account.username
			cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(username), hash_str(username), remember_me())
			self.set_cookie(cookie)
			self.set_school_cookie(get_school(username))
			return True
		else:
			return False

	def get(self):
		user = users.get_current_user()
		if user:
			if self.google_login(user):
				self.redirect('/')
			else:
				self.render('index.html', {'blockbg': True, 'modal':'login',
							'google_error':"""There was no information found for your Google Account. Did you mean to <a href="#signup" role="button" data-toggle="modal" onclick="$('#login').modal('hide')">sign up</a>?"""})
				return
		else:
			self.redirect(users.create_login_url("/google_login"))

class GuidePageHandler(BaseHandler):
	'''Handlers custom guide pages: guide_page.html'''
	def get(self, url):
		bookmarked, reported, deletable, diff, user, admin = [False]*6
		username = self.get_username()
		url = url[1:] # formats url 

		# retrieve guide from db
		q = Guides.all()
		q.filter('url =', url.lower())
		guide = q.get()

		# if guide exists, render page
		if guide:
			# get comments
			comments = guide.comments_list
			if not comments.get():
				comments = False
			else:
				comments.order('date_created').run()

			votes = str_votes(guide.votes)
			dl_link = '/serve/' + guide.blob_key

			if username:
				# check if reported & bookmarked
				reported = (username in guide.report_users)				
				user = get_user(username)
				if any([bookmark.guide.blob_key == guide.blob_key for bookmark in user.bookmark_list]):
						bookmarked = True

				# check if uploaded/deleteable
				if user.username == guide.user_created:
					diff = datetime.datetime.now() - guide.date_created 
					if diff < datetime.timedelta(days=1):
						deletable = True
					diff = "%0.1f"%((datetime.timedelta(0, 86400)-diff).total_seconds()/3600) # convert to remaining time

				# check for admin access
				admin = (user.username == "admin")
				if admin: deletable = True

			self.render('guide_page.html', {'guide':guide, 'difference':time_difference(guide.date_created), 
						'votes':votes, 'dl_link':dl_link, 'bookmarked':bookmarked, 'reported':reported, 
						'deletable':deletable, 'diff':diff, 'comments':comments, 'admin':admin, 
						'fake_users':['admin']+FAKE_USERS, 'user':user})
		else:
			self.error(404)
			self.render('404.html', {'blockbg':True})

class GuidesHandler(BaseHandler):
	'''Handles guides: guides.html'''
	def get(self):
		if self.rget('q'):
			self.redirect('/search?q=' + self.rget('q'))

		# page on top guides tab
		page = 0
		if self.rget('page'): 
			try:
				page = int(self.rget('page'))
				if page > 2 or page < 0:
					page = 0
			except:
				page = 0
		page_offset = page*25

		# page on new guides tab
		new_page = 0
		if self.rget('new_page'):
			try:
				new_page = int(self.rget('new_page'))
				if new_page == 0:
					new_page = 'zero'
				elif new_page > 2 or new_page < 0:
					new_page = 0
			except:
				new_page = 0	

		# get top guides, active subj/teach if logged in
		username = self.get_username()
		school = get_school(username)
		if username:
			top_guides = get_top_guides(school, page)
			subjects = get_all_active_subjects(school)
			teachers = get_all_active_teachers(school)

			self.render('guides.html', {'top_guides':top_guides,'subjects':subjects, 
						'teachers':teachers, 'page':page, 'page_offset':page_offset,
						'school':school, 'new_page':new_page, 'username':username})
		else:
			top_guides = get_top_guides(None, page)

			self.render('guides.html', {'top_guides':top_guides, 'page':page,
						'page_offset':page_offset, 'new_page':new_page,
						'username':username})

class MainHandler(BaseHandler):
	'''Handles homepage: index.html, dashboard.html, singup, and signin'''
	def get(self):
		if self.rget('q'):
			self.redirect('/search?q=' + self.rget('q'))
		elif self.logged_in():
			self.redirect('/dashboard/')
		else:
			self.render('index.html', {'blockbg':True, 'index':True})

	def post(self):
		formname = self.rget('formname')

		if formname == 'login':
			username = self.rget('username')

			blocked_time = memcache.get('loginblock-'+username)
			if blocked_time and (datetime.datetime.now() - blocked_time < datetime.timedelta(minutes=1)):
				self.render('index.html', {'username': username, 'wrong': 'You attempted to login too many times. Try again in 1 minute.', 
							'modal' : 'login', 'blockbg' : True, 'index': True})
				return

			correct, value = check_login(username, self.rget('password'))
			if correct:
				if self.rget('remember') == 'on':
					value = value + ' Expires=' + remember_me() + ' Path=/'
					self.set_cookie(value)
				else:
					self.set_cookie(value + ' Path=/')
				self.set_school_cookie(get_school(username))
				self.redirect('/')
			else:
				# log the login attempt
				tries = memcache.get('login-'+username)
				if not tries: # first attempted login
					tries = 1
					memcache.set('login-'+username, tries)
				elif tries > 4: # logged in more than 4 times
					memcache.set('loginblock-'+username, datetime.datetime.now())
				else:
					tries += 1
					memcache.set('login-'+username, tries)

				self.render('index.html', {'username': username, 'wrong': value, 'modal' : 'login', 'blockbg' : True, 'index': True})

		elif formname == 'signup':
			username = self.rget('username')
			password = self.rget('password')
			verify = self.rget('verify')
			school = self.rget('school')
			agree = self.rget('agree')
			human = self.rget('session_secret')
			email = self.rget('email')
			results = signup(username, password, verify, school, agree, human, email)

			username_error, password_error, verify_error, school_error, agree_error, human_error, email_error = ['']*7	

			if results['success']:
				add_school(school)
				self.set_cookie(results['cookie'])
				self.set_school_cookie(school)
				self.redirect('/dashboard?tour=True')
			else:
				self.render('index.html', {'username':username, 'school':school, 'email':email, 
					'email_error':results.get('email'), 'username_error':results.get('username'),
					'password_error':results.get('password'), 'verify_error':results.get('verify'),
					'school_error':results.get('school'), 'agree_error':results.get('agree'),
					'human_error':results.get('human'), 'blockbg':True, 'modal':'signup', 'index':True})
		else:
			self.redirect('/')

class PreferencesHandler(BaseHandler):
	def get(self):
		if self.logged_in():
			school_success = self.rget('school_success')
			self.render_prefs({'school_success':school_success})
		else:
			self.redirect('/')

class SearchHandler(BaseHandler):
	def get(self):
		query = self.rget('q')
		school = self.get_school_cookie()
		if not school:
			school = 'Bergen County Academies'
		results = search(school, query)
		
		if not results:
			self.render('search.html', {'query':query})
			return

		guides = [r[0] for r in results]
		self.render('search.html', {'guides':guides, 'query':query})

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, blob_key):
		guide = Guides.all().filter('blob_key =', blob_key).get()
		if guide:
			# record download in database
			if guide.downloads is None:
				guide.downloads = 0
			guide.downloads += 1
			guide.top_score = calc_score(guide)
			guide.put()

			# serve file to browser
			blob_key = str(urllib.unquote(blob_key))
			blob_info = blobstore.BlobInfo.get(blob_key)
			self.send_blob(blob_info, save_as=blob_info.filename, content_type=blob_info.content_type)			
		else:
			self.error(404)

class UploadHandler(BaseHandler):
	def get(self):
		username = self.get_username()
		if username:
			school = get_school(username)
			params = dict()

			qs = Subjects.all().filter('school =', school).get()
			if qs:
				params['subjects'] = map(lambda x: x.encode('ascii', 'ignore'), qs.subjects_list)

			qt = Teachers.all().filter('school =', school).get()	
			if qt:
				params['teachers'] = map(lambda x: x.encode('ascii', 'ignore'), qt.teachers_list)			

			self.render('upload.html', params)
		else:
			self.redirect('/')

	def post(self):
		title = self.rget('title')
		subject = self.rget('subject')
		teacher = self.rget('teacher')
		editable = self.rget('editable')
		tags = self.rget('tags')
		file_url = self.rget('file')
		username = self.get_username()

		# check last upload time
		last_upload = memcache.get('uploadtime-'+username)
		if last_upload and (datetime.datetime.now() - last_upload < datetime.timedelta(minutes=1)):
			fields = {'title':title, 'subject':subject, 'teacher':teacher, 
					  'editable':editable, 'tags':tags, 
					  'time_error':'You\'re uploading too quickly! Try waiting 1 minute between uploads.'}
			self.render('/upload.html', fields)	 
			return

		if file_url:
			# get the file from filepicker.io
			result = urlfetch.fetch(file_url)
			headers = result.headers
			if result.status_code != 200:
				self.write("Connection Error.")
				return
			_editable, errors = upload_errors(title, subject, teacher, editable, headers)
		else:
			_editable, errors = upload_errors(title, subject, teacher, editable, 
								   {'content-type':'text/plain', 'content-length':'0'})
			errors['file_error'] = 'Please upload a file.'

		if any(errors.values()):
			fields = {'title':title, 'subject':subject, 'teacher':teacher, 
					  'editable':editable, 'tags':tags}
			errors.update(fields)
			self.render('/upload.html', errors)
		else:						
			tags = get_tags(tags) + create_tags(title, subject, teacher, username)
			filename = get_filename(title, username, headers['content-type'])
			school = get_school(username)
			edit_url = None

			# write file to blobstore
			f = files.blobstore.create(mime_type=headers['content-type'], _blobinfo_uploaded_filename=filename)
			with files.open(f, 'a') as data:
				data.write(result.content)
			files.finalize(f)
			blob_key = files.blobstore.get_blob_key(f)

			# write file to google docs
			if _editable:
				google_doc_name = school + ': ' + filename 
				client = externals.gdata.docs.service.DocsService()
				client.ClientLogin(secret.G_USERNAME, secret.G_PASSWORD)
				ms = externals.gdata.MediaSource(file_handle=result.content, 
					                   content_type=headers['content-type'], 
					                   content_length=int(headers['content-length']))
				entry = client.Upload(ms, google_doc_name, folder_or_uri=secret.G_FOLDER_URI)
				edit_url = entry.GetAlternateLink().href

			# construct url for guide page
			url = get_url(filename, username)

			# setting icon for guide
			icon = memcache.get('icon-'+subject)
			if not icon: # if icon not in memcache
				q = SubjectIcons.all()
				q.filter('subject =', subject)
				si = q.get()
				if not si: # if icon not in db
					icon = 'default_icon' ##! change to default icon later
				else:
					icon = si.icon

			# add guide to db
			guide = Guides(user_created=username, title=title, subject=subject,
				   		   teacher=teacher, tags=tags, blob_key=str(blob_key),
				   		   edit_url=edit_url, school=school, url=url, icon=icon,
				   		   votes=0, up_users=[], down_users=[], top_score=0.0, downloads=0)
			guide.put()

			increase_guides_uploaded(username)

			# add subject, teacher to db
			add_teacher(school, teacher)
			add_subject(school, subject)
			add_subject_to_teacher(school, teacher, subject)
			add_teacher_to_subject(school, teacher, subject)

			key = str(guide.key())

			memcache.delete('new-guides-None')
			memcache.delete('new-guides-' + school)

			# add guide to user's submitted guides cache
			add_submitted(username,key)
			
			# add guide to index
			add_to_index(school, key, tags)
			self.redirect('/guides/' + url)

			# set last upload time for user
			memcache.set('uploadtime-'+username, datetime.datetime.now())

class UserPageHandler(BaseHandler):
	'''Handlers custom user pages: user_page.html'''
	def get(self, url):
		username = url[1:]
		submitted = get_submitted(username)

		if not submitted:
			self.error(404)
			self.render('404.html', {'blockbg':True})
		else:
			user = get_user(username)
			if not user:
				self.error(404)
				self.render('404.html', {'blockbg':True})
				return
			count = len(submitted)
			self.render('user_page.html', {'count':count, 'submitted':submitted, 'user':user})

##### Backend handlers #####

class AddBookmarkHandler(BaseHandler):
	def post(self):
		if self.logged_in():
			
			blob_key = self.rget('id')
			current_user = get_user(self.get_username());
			#check to make sure user doesnt have a duplicate bookmark
			bookmarks = Bookmarks.all();
			bookmarks.filter('user =', current_user)
			temp_guide = Guides.all().filter('blob_key =', blob_key).get()
			
			bookmarks.filter('guide =', temp_guide)
			if bookmarks.count() == 0:
				temp_bookmark = Bookmarks(user=current_user, guide=temp_guide)
				temp_bookmark.put()
		#self.redirect('/guides')

class CommentHandler(BaseHandler):
	def post(self):
		key = self.rget('key')
		comment = self.rget('comment')
		username = self.get_username()

		if username == 'admin':
			username = self.rget('user')

		if not username:
			self.write('signin')
			return None

		if comment and key and username:
			guide = Guides.get(key)
			user = get_user(username)
			if guide and user:
				temp_comment = Comments(user=user, guide=guide, comment=comment, upvotes=0, 
										downvotes=0, up_users=[], down_users=[], flagged_users=[])
				if guide.user_created != username:
					notificationStr = "<a href='/user/%s'>%s</a>"%(username,username) + \
						              " commented on your guide " + \
						              "<a href='/guides/%s'>%s</a><br/>"%(guide.url, guide.title) + \
						              "<span style='font-size:11px;color:gray;'>%s</span>"%comment_preview(comment)
					notif = Notification(username=guide.user_created, is_new=True, name="comment", 
										 notification=notificationStr)
					notif.put()
				temp_comment.put()

			else:
				self.write('False')
				return
			self.write(username+','+str(temp_comment.date_created))

		else:
			self.write('False')
			return

class CommentVoteHandler(BaseHandler):
	def post(self):
		key = self.rget('id')
		vote_type = self.rget('type')
		username = self.get_username()
		
		response = comment_vote(key, vote_type, username)
		self.write(response)

class CronCountHandler(BaseHandler):
	def get(self):
		user_count =  Users.all().count()
		guide_count = Guides.all().count()

		d1 = Data(name="user_count", value=user_count)
		d2 = Data(name="guide_count", value=guide_count)

		d1.put()
		d2.put()

		logging.info('CRON logged user_count & guide_count')
		self.write('CRON logged user_count & guide_count')

class DeleteCommentHandler(BaseHandler):
	def post(self):
		key = self.rget('id')
		comment = Comments.get(key)

		user = get_user(self.get_username())
		if user and user.key() == comment.user.key():
			comment.delete()
			self.write('True')
		else:
			self.write('False') # this isn't really used

class DeleteGuideHandler(BaseHandler):
	def post(self):
		key = self.rget('key')
		delete_guide(key)
		self.write("Successfully deleted!")

class DeleteNotifHandler(BaseHandler):
	def post(self):
		key = self.rget('key')
		notif = Notification.get(key)
		notif.delete()

		self.write('True')

class FeedbackHandler(BaseHandler):
	def post(self):
		message = self.rget('message')
		idea = self.rget('Idea')
		question = self.rget('Question')
		problem = self.rget('Problem')
		praise = self.rget('Praise')
		username = self.get_username()

		# write content
		content = 'Type: '+idea+' '+question+' '+problem+' '+praise
		content += '<br />'
		content += message

		save_feedback(content, username)
		
		self.redirect('/')

class GoogleSignupHandler(BaseHandler):
    def get(self):
        self.redirect(users.create_login_url("/ext_signup"))

class LogoutHandler(BaseHandler):
	'''Handles logging out'''
	def get(self):
		self.delete_cookie(LOGIN_COOKIE_NAME)
		self.delete_cookie('ACSID')
		self.delete_cookie('school')
		self.delete_cookie('bg')
		self.set_cookie('tour_current_step=0')
		self.redirect('/')

class NewGuidesHandler(BaseHandler):
	def get(self):
		self.redirect('/guides')

	def post(self):
		school = self.rget('school')
		if not school:
			school = ''
		try:
			page = int(self.rget('new_page'))
		except:
			page = 0
		
		username = self.get_username()
		if not username: username = ''

		response = get_new_guides(school, page, username)
		self.write(response)

class NotificationHandler(BaseHandler):
	def post(self):
		username = self.get_username()
		q = Notification.all()
		q.filter('username =', username)
		q.filter('is_new =', True)
		for notif in q:
			notif.is_new = False
			notif.put()

class PreferenceEditHandler(BaseHandler):
	def post(self):
		formname = self.rget('formname')
		username = self.get_username()

		if not username:
			self.redirect('/preferences')

		elif formname == 'change_email':
			email = self.rget('email')
			results = new_user_email(email, username)
			if results[0]:
				self.render_prefs({'email_success':True})
			else:
				self.render_prefs({'email_error':results[1]})

		elif formname == 'resend_email':
			email = self.rget('email')
			email_verification(username, email)
			self.render_prefs({'verification_success':True})

		elif formname == 'change_school':
			school = self.rget('school')
			results = change_school(school, username)
			if results[0]:
				self.set_school_cookie(school)
				self.redirect('/preferences?school_success=True')
			else:
				self.write(results[1])
				self.render('prefs', {'school_error' : results[1]})

		elif formname == 'change_password':
			old_password = self.rget('current_password')
			new_password = self.rget('new_password')
			verify_new_password = self.rget('verify_new_password')
			results = change_password(old_password, new_password, verify_new_password, username)
			if results[0]:
				self.set_cookie(results[1])
				self.render_prefs({'username':username, 'password_success':True})
			else:
				self.render_prefs(results[1])

		else:
			self.redirect('/preferences')

class RemoveBookmarkHandler(BaseHandler):
	def get(self):
		self.redirect('/')
		
	def post(self):
		if self.logged_in():
			blob_key = self.rget('id')
			current_user = get_user(self.get_username())
			# check to make sure user has bookmark
			bookmarks = Bookmarks.all();
			bookmarks.filter('user =', current_user)
			temp_guide = Guides.all().filter('blob_key =', blob_key).get()
	
			bookmarks.filter('guide =', temp_guide)
			if bookmarks.count() != 0:
				bookmarks.get().delete()
			self.response.out.write("done")

class ReportHandler(BaseHandler):
	''' Handles users reporting guides '''
	def post(self):
		blob_key = self.rget('blob_key')
		username = self.get_username()
		if get_user(username):
			q = Guides.all()
			q.filter('blob_key =', blob_key)
			guide = q.get()

			report_users = guide.report_users
			if report_users and username not in report_users:
				report_users.append(username)
			else:
				report_users = [username]
			guide.report_users = report_users

			if len(report_users) >= 10:
				# guide.locked = True
				send_report_mail(blob_key)

			guide.put()
		else:
			self.write('An error occured.')
			return

		self.write('Reported. Thank you!')

class SubjectsHandler(BaseHandler):
	'''receives AJAX request for the second page on guides->subject'''
	def post(self):
		subject = cgi.escape(self.rget('subject'))
		school = self.get_school_cookie()
		teachers = get_teachers_for_subject(school, subject)
		teachers.append("View All")

		# construct return HTML
		html = """
		<ul class="breadcrumb">
		  <li><a href="#" onclick="subtoggle1()">Subjects</a> <span class="divider">/</span></li>
		  <li class="active">%s</li>		  
		</ul>
		<div class="row-fluid">"""%subject

		# script must be initialized AFTER the html is in place, so we send it through AJAX
		script = """
		<script>
		$('.subjects2').click(function (e) {
      		teacher = this.id;
      		$(document.getElementById('t_'+teacher+'load2')).show();
      		e.preventDefault();
      		$.ajax({
	            type:'POST', 
	            url:'/subjects2', 
	            data:'teacher=' + teacher + "&subject=%s", 
	            success: function(response) {
	            	$(document.getElementById('t_'+teacher+'load2')).hide();
	            	$('#subjectlist2').hide();
	            	$('#subjectlist3').html(response);
	            	$('#subjectlist3').show();                
	            }
        	});
      	})
		</script>
		"""%subject

		for i in range(len(teachers)):
			teacher = teachers[i]

			if i % 3 == 0:
				html += """</div><div class="row-fluid">"""

			html += """<div class="span4 hoverspn4">
				<a href="#" class="subjects2" id="%s">%s</a>
				&nbsp;&nbsp;<img src="../static/img/ajax-loader.gif" id="t_%sload2" style="display:none;"/>
				</div>
				"""%(teacher,teacher,teacher)

		# send this html back to jquery/ajax
		self.write(html+'</div>'+script)

class SubjectsHandler2(BaseHandler):
	'''receives AJAX request for the third page on guides->subject'''
	def post(self):
		teacher = self.rget('teacher')
		subject = self.rget('subject')
		
		school = self.get_school_cookie()
		
		if teacher == "View All":
			results = find_guides_ts(school, None, subject)
		else:
			results = find_guides_ts(school, teacher, subject)

		# construct return HTML
		html = """
		<ul class="breadcrumb">
		  <li><a href="#" onclick="subtoggle2()">Subjects</a> <span class="divider">/</span></li>
		  <li><a href="#" onclick="subtoggle3()">%s</a> <span class="divider">/</span></li>
		  <li class="active">%s</li>		  
		</ul>
		<table class="table-hover">
			<thead>
				<tr>
					<th>&nbsp;</th>
					<th>Title</th>
					<th>Subject</th>
					<th>Teacher</th>
					<th>Uploader</th>
					<th>Votes</th>
				</tr>
			</thead>
			<tbody>
			"""% (subject, teacher)

		for result in results:
			html += """<tr style="height:38px;"><td>&nbsp;</td>"""
			html += """<td><a href="/guides/%s">%s</a></td>"""%(result.url, result.title)
			html += """<td>%s</td>"""%result.subject
			html += """<td>%s</td>"""%result.teacher
			html += """<td>%s</td>"""%result.user_created
			html += """<td>%s</td>"""%result.votes
			html += """</tr>"""

		html += """</tbody></table>"""
		# send this html back to jquery/ajax	
		self.write(html)

class SubmittedHandler(BaseHandler):
	def get(self):
		self.redirect('/guides')

	def post(self):
		if self.logged_in():
			self.write(get_submitted_html(self.get_username()))
		else:
			self.error(404)		
	
class TeachersHandler(BaseHandler):
	'''receives AJAX request for the second page on guides->teacher'''
	def post(self):
		teacher = cgi.escape(self.rget('teacher'))
		school = self.get_school_cookie()
		subjects = get_subjects_for_teacher(school, teacher)
		subjects.append("View All")

		# construct return HTML
		html = """
		<ul class="breadcrumb">
		  <li><a href="#" onclick="teachtoggle1()">Teachers</a> <span class="divider">/</span></li>
		  <li class="active">%s</li>		  
		</ul>
		<div class="row-fluid">"""%teacher

		# script must be initialized AFTER the html is in place, so we send it through AJAX
		script = """
		<script>
		$('.teachers2').click(function (e) {
      		subject = this.id;
      		$(document.getElementById('s_'+subject+'load2')).show();
      		e.preventDefault();
      		$.ajax({
	            type:'POST', 
	            url:'/teachers2', 
	            data:'subject=' + subject + '&teacher=%s', 
	            success: function(response) {
	            	$(document.getElementById('s_'+subject+'load2')).hide();
	            	$('#teacherlist2').hide();
	            	$('#teacherlist3').html(response);
	            	$('#teacherlist3').show();                
	            }
        	});
      	})

		</script>
		"""%teacher

		for i in range(len(subjects)):
			subject = subjects[i]
			if i % 3 == 0:
				html += """</div><div class="row-fluid">"""
			html += """<div class="span4 hoverspn4">
				<a href="#" class="teachers2" id="%s">%s</a>
				&nbsp;&nbsp;<img src="../static/img/ajax-loader.gif" id="s_%sload2" style="display:none;"/>
			</div>"""%(subject,subject,subject)

		# send this html back to jquery/ajax
		self.write(html+'</div>'+script)

class TeachersHandler2(BaseHandler):
	'''receives AJAX request for the third page on guides->teacher'''
	def post(self):
		teacher = self.rget('teacher')
		subject = self.rget('subject')

		school = self.get_school_cookie()
		
		if subject == "View All":
			results = find_guides_ts(school, teacher, None)
		else:
			results = find_guides_ts(school, teacher, subject)

		# construct return HTML
		html = """
		<ul class="breadcrumb">
		  <li><a href="#" onclick="teachtoggle2()">Teachers</a> <span class="divider">/</span></li>
		  <li><a href="#" onclick="teachtoggle3()">%s</a> <span class="divider">/</span></li>
		  <li class="active">%s</li>		  
		</ul>
		<table class="table-hover">
			<thead>
				<tr>
					<th>&nbsp;</th>
					<th>Title</th>
					<th>Subject</th>
					<th>Teacher</th>
					<th>Uploader</th>
					<th>Votes</th>
				</tr>
			</thead>
			<tbody>
			"""% (teacher, subject)

		for result in results:
			html += """<tr style="height:38px;"><td>&nbsp;</td>"""
			html += """<td><a href="/guides/%s">%s</a></td>"""%(result.url, result.title)
			html += """<td>%s</td>"""%result.subject
			html += """<td>%s</td>"""%result.teacher
			html += """<td>%s</td>"""%result.user_created			
			html += """<td>%s</td>"""%result.votes
			html += """</tr>"""

		html += """</tbody></table>"""
		# send this html back to jquery/ajax	
		self.write(html)

class VoteHandler(BaseHandler):
	def get(self):
		self.error(404)
		self.render('404.html',{'blockbg':True})

	def post(self):
		key = self.rget('id')
		vote_type = self.rget('type')
		username = self.get_username()
		
		response = vote(key, vote_type, username)
		self.write(response)

##### Static handlers #####

class AdminHandler(BaseHandler):
	def get(self):
		user_count =  Users.all().count()
		new_users = Users.all().order('-date_created').run(limit=10)
		top_uploaders = Users.all().order('-guides_uploaded').run(limit=10)
		guide_count = Guides.all().count()
		new_guides = Guides.all().order('-date_created').run(limit=10)
		top_guides = Guides.all().order('-downloads').run(limit=10)
		all_guides = Guides.all()

		user_data = Data.all().filter('name =', 'user_count').order('-date_created')
		guide_data = Data.all().filter('name =', 'guide_count').order('-date_created')

		downloads_count = 0
		for guide in all_guides:
			if guide.downloads is None:
				continue
			downloads_count += guide.downloads
		new_comments = Comments.all().order('-date_created').run(limit=10)
		feedback = Feedback.all().run(limit=5)

		self.render('admin.html', {'user_count':user_count, 'new_users':new_users, 'top_uploaders':top_uploaders,
					'guide_count':guide_count,'new_guides':new_guides, 'new_comments':new_comments,
					'feedback':feedback, 'top_guides':top_guides, 'downloads_count':downloads_count,
					'user_data':user_data, 'guide_data':guide_data})

class AboutHandler(BaseHandler):
	'''Handles about: about.html'''
	def get(self):
		self.render('about.html')

class ContactHandler(BaseHandler):
	'''Handles contact: contact.html'''
	def get(self):
		self.render('contact.html')

class NotFoundHandler(BaseHandler):
	def get(self):
		self.error(404)
		self.render('404.html', {'blockbg':True})

class TeamHandler(BaseHandler):
	'''Handles team: team.html'''
	def get(self):
		self.render('team.html')

class ToSHandler(BaseHandler):
	def get(self):
		self.render('tos.html')

app = webapp2.WSGIApplication([('/?', MainHandler),
							   ('/about/?', AboutHandler),
							   ('/logout/?', LogoutHandler),
							   ('/guides/?', GuidesHandler),
							   ('/newguides/?', NewGuidesHandler),
							   ('/submitted/?', SubmittedHandler),
							   ('/contact/?', ContactHandler),
							   ('/team/?', TeamHandler),
							   ('/dashboard/?', DashboardHandler),
							   ('/guides' + PAGE_RE, GuidePageHandler),
							   ('/user'+ PAGE_RE, UserPageHandler),
							   ('/upload/?', UploadHandler),
							   ('/serve/([^/]+)?', ServeHandler),
							   ('/tos/?', ToSHandler),
							   ('/preferences/?', PreferencesHandler),
							   ('/search', SearchHandler),	
							   ('/verify/([^/]+)?', EmailVerificationHandler),
							   ('/delete_email/([^/]+)?', DeleteEmailVerification),
							   ('/delete_account/?', DeleteAccountHandler),
							   ('/google_signup/?', GoogleSignupHandler),
							   ('/google_login/?', GoogleLoginHandler),
							   ('/ext_signup/?', ExternalSignUp),
							   ('/teachers/?', TeachersHandler),
							   ('/subjects/?', SubjectsHandler),
							   ('/subjects2/?', SubjectsHandler2),
							   ('/teachers/?', TeachersHandler),
							   ('/teachers2/?', TeachersHandler2),
							   ('/vote/?', VoteHandler),
							   ('/addbookmark/?', AddBookmarkHandler),
							   ('/removebookmark/?', RemoveBookmarkHandler),
							   ('/report/?', ReportHandler),
							   ('/notifications/?', NotificationHandler),
							   ('/feedback/?', FeedbackHandler),
							   ('/guide/delete/?', DeleteGuideHandler),
							   ('/comment/?', CommentHandler),
							   ('/admin/?', AdminHandler),
							   ('/cron/admin_counts/?', CronCountHandler),
							   ('/delete_comment/?', DeleteCommentHandler),
							   ('/comment_vote/?', CommentVoteHandler),
							   ('/delete_notif/?', DeleteNotifHandler),
							   ('/edit_prefs/?', PreferenceEditHandler),
							   ('/.*', NotFoundHandler),
							   ], debug=True)
