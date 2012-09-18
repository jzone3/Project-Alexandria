import re
import hmac
import hashlib
import logging
import string
import random
import datetime
import time

from django.utils import simplejson
import externals.ayah
from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.api import memcache

import secret
from database import *

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SCHOOL_RE= re.compile(r"^[a-zA-Z0-9 _]{1,30}$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
LOGIN_COOKIE_NAME = 'uohferrvnksj'

############################### misc. functions ###############################

def str_votes(votes):
	if votes > 0:
		return '+' + str(votes)
	else:
		return str(votes)

def str_grade(grade):
	if grade == 9:
		return 'Freshman'
	elif grade == 10:
		return 'Sophomore'
	elif grade == 11:
		return 'Junior'
	elif grade == 12:
		return 'Senior'
	else:
		return 'Alumnus'

def get_schools():
	lst = memcache.get('all_schools')
	if lst is None:
		all_users = db.GqlQuery("SELECT * FROM Users")
		schools = []
		for i in all_users:
			if not i.school in schools:
				schools.append(i.school)
		if len(schools) == 0:
			schools = ['Bergen County Academies']
		memcache.set('all_schools', schools)
	return lst

def add_school(new_school):
	# implement CAS later
	current_schools = get_schools()
	if not new_school in current_schools:
		current_schools.append(new_school)
	memcache.set('all_schools', current_schools)

def save_feedback(content, origin):
	new_feedback = Feedback(content = content, origin = origin)
	new_feedback.put()

def add_submitted(username, blob_key):
	cached_items = memcache.get(username + '_submitted')
	submission = db.GqlQuery("SELECT * FROM Guides WHERE blob_key = '" + blob_key + "'").get()
	if not cached_items is None:
		new_guide = [{'title' : submission.title, 'subject' : submission.subject, 'votes' : submission.votes, 'date_created' : submission.date_created}]
		try:
			cached_items = new_guide.append(cached_items)
			memcache.set(username + '_submitted', cached_items)
		except:
			memcache.set(username + '_submitted', new_guide)

def get_submitted(username):
	to_return = memcache.get(username + '_submitted')
	if to_return is None:
		guides = db.GqlQuery("SELECT * FROM Guides WHERE user_created = '" + username.replace("'", "&lsquo;") + "' ORDER BY date_created DESC")
		logging.error(username + '_submitted db read')
		to_return = []
		for submission in guides:
			to_return.append({'title' : submission.title, 'subject' : submission.subject, 'votes' : submission.votes, 'date_created' : submission.date_created})
		memcache.set(username + '_submitted', to_return)
	return to_return

############################### user functions ###############################

def remember_me():
	expiration = datetime.datetime.now() + datetime.timedelta(days=50)
	return expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST")

def hash_str(string):
	return hmac.new(secret.SECRET, str(string), hashlib.sha512).hexdigest()

def salted_hash(password, salt):
	return hashlib.sha256(password + salt).hexdigest()

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def get_error(results, error):
	if error in results.keys():
		return results[error]
	else:
		return None

def get_user(username):
	user = (db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")).get()
	return user

def get_school(username):
	'''gets school from db from username'''
	q = Users.all()
	q.filter('username =', username)
	results = q.get()
	if results:
		return results.school
	else:
		return None

def unique_email(email):
	accounts = (db.GqlQuery("SELECT * FROM Users WHERE email = '" + email.replace("'", "&lsquo;") + "'")).get()
	if accounts is None:
		return True
	return False

def unique_username(username):
	accounts = (db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")).get()
	if accounts:
		return False
	return True

def check_login(username, password):
	"""Checks if login info is correct

	Returns:
		[False, error text]
		OR
		[True, cookie]
	"""

	correct = False

	if username != '' and password != '':
		accounts = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")
		logging.error("DB QUERY - check_login()")
		accounts = accounts.get()
		if accounts is None:
			return [False, 'Username does not exist']

		if accounts.password == None:
			return [False, 'Please "Log In with Google"']
		(db_password, salt) = (accounts.password).split("|")

		if salted_hash(password, salt) == db_password:
			return [True, '%s=%s|%s;' % (LOGIN_COOKIE_NAME, str(username), str(hash_str(username)))]
	return [False, 'Invalid username or password!']

def signup(username='', password='', verify='', school='', year='', agree='', human='', email=''):
	"""Signs up user

	Returns:
		Dictionary of elements with error messages and 'success' : False
		OR
		{'cookie' : cookie, 'success' : True}
	"""

	to_return = {'success' : False}
	
	if username == '':
		to_return['username'] = "Please enter a username"
	elif not USER_RE.match(username):
		to_return['username'] = "That's not a valid username."

	
	if password == '':
		to_return['password'] = "Please enter a password"
	elif not PASS_RE.match(password):
		to_return['password'] = "That's not a valid password."
	elif verify == '':
		to_return['verify'] = "Please verify your password"
	elif verify != password:
		to_return['verify'] = "Your passwords didn't match."

	if email != '' and not EMAIL_RE.match(email):
		to_return['email'] = "That's not a valid email."
	
	if school == '':
		to_return['school'] = "Please enter a school"
	if not SCHOOL_RE.match(school):
		to_return['school'] = "That is not a valid school name"
	
	if year == '':
		to_return['year'] = "Please enter a year"
	if not int(year) in [9,10,11,12]:
		to_return['year'] = "That is not a valid grade level"
	
	if agree != 'on':
		to_return['agree'] = "You must agree to the Terms of Service to create an account"
	# self.write(username + ' ' + password + ' ' + verify + ' ' + email + ' ' + school + ' ' + year )

	# check areyouahuman result
	externals.ayah.configure('9ee379aab47a91907b9f9b505204b16494367d56', 
							 '7ec7c6561c6dba467095b91dd58778f2c60fbaf2')
	if not externals.ayah.score_result(human):
		to_return['human'] = "Please try the human test again."

	if len(to_return) == 1:
		if not unique_username(username):
			to_return['username'] = "Username already exists!"
		else:
			if not unique_email(email):
				to_return['email'] = "Email already exists!"
			else:
				salt = make_salt()
				hashed = salted_hash(password, salt)
				hashed_pass = hashed + '|' + salt
				account = Users(username = username.replace("'", "&lsquo;"), password = hashed_pass, school = school, grade = int(year), score = 0, confirmed = False, email = email)
				account.put()
				cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(username), hash_str(username), remember_me())
				to_return['cookie'] = cookie
				to_return['success'] = True
	return to_return

def signup_ext(username='', school='', year='', agree='', email=''):
	"""Signs up user from google/facebook"""

	to_return = {'success' : False}
	
	if username == '':
		to_return['username'] = "Please enter a username"
	elif not USER_RE.match(username):
		to_return['username'] = "That's not a valid username."
	
	if school == '':
		to_return['school'] = "Please enter a school"
	if not SCHOOL_RE.match(school):
		to_return['school'] = "That is not a valid school name"
	
	if year == '':
		to_return['year'] = "Please enter a year"
	if not int(year) in [9,10,11,12]:
		to_return['year'] = "That is not a valid grade level"
	
	if agree != 'on':
		to_return['agree'] = "You must agree to the Terms of Service to create an account"

	if len(to_return) == 1:
		if not unique_username(username):
			to_return['username'] = "Username already exists!"
		elif not unique_email(email):
			to_return['email'] = "Email already exits!"
		else:
			account = Users(username = username.replace("'", "&lsquo;"), school = school, grade = int(year), score = 0, confirmed = False, email = email)
			account.put()
			cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(username), hash_str(username), remember_me())
			to_return['cookie'] = cookie
			to_return['success'] = True
			
	return to_return
		
############################### user pref functions ###############################

def change_school(school, username):
	if school == '':
		return [False, 'No school entered']
	if not SCHOOL_RE.match(school):
		return [False, "That is not a valid school name"]
	add_school(school)
	user = get_user(username)
	user.school = school
	user.put()
	return [True]

def new_email(email, username):
	"""
	Returns:
		[Success_bool, error]
	"""
	if email == '':
		return [False, 'No email entered']
	if not EMAIL_RE.match(email):
		return [False, "That's not a valid email."]

	user = get_user(username)
	user.email = email
	user.put()
	return [True]

def change_password(old, new, verify, username):
	if new == '':
		return [False, {'new_password_error' : "Please enter a password"}]
	if old == '':
		return [False, {'new_password_error' : "Please enter your current password"}]
	elif not PASS_RE.match(new):
		return [False, {'new_password_error' : "That's not a valid password."}]
	elif verify == '':
		return [False, {'verify_new_password_error' : "Please verify your password"}]
	elif verify != new:
		return [False, {'verify_new_password_error' : "Your passwords didn't match."}]

	user = get_user(username)
	logging.error(old)
	(db_password, db_salt) = (user.password).split("|")
	if salted_hash(old, db_salt) == db_password:		
		salt = make_salt()
		hashed = salted_hash(new, salt)
		hashed_pass = hashed + '|' + salt

		user.password = hashed_pass
		user.put()

		cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(username), hash_str(username), remember_me())
		return [True, cookie]
	else:
		return [False, {'current_password_error' : 'Incorrect current password'}]

def delete_user_account(username):
	user = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")
	for i in user:
		i.delete()

############################### file handling functions ###############################

def get_tags(string):
	'''Gets tags from a comma separated string'''
	splitted = string.split(',')
	tags = []
	for tag in splitted:
		tag = tag.replace(' ', '')
		if tag:
			tags.append(tag)
	return tags

def get_filename(title, user):
	'''Makes a filename from the guide title and uploading user'''
	title = title.lower()
	user = user.lower()
	new_title = ''
	for char in title:
		if char != ' ':
			new_title += char
		else:
			new_title += '_'
	return new_title + '_' + user

def get_url(filename, user):
	'''Creates url: user/guidename from filename and uploading user'''
	user = user.lower()
	filename = filename[:filename.rfind('_')]
	return user + '/' + filename

def upload_errors(title, subject, teacher, locked, doc_url, headers):
	title_error, subject_error, teacher_error, doc_url_error = '', '', '', ''
	if not title:
		title_error = 'Please provide a title.'
	if not subject:
		subject_error = 'Please provide a subject.'
	if not teacher:
		teacher_error = 'Please provide a teacher.'
	if not locked and not doc_url:
		doc_url_error = 'Please provide a Google Docs URL. '
	if not locked and 'docs.google' not in doc_url:
		doc_url_error = 'Please provide a Google Docs URL. '
	if not locked and doc_url[0:4] != 'http':
		doc_url_error += 'Please include http:// or https:// before the URL.'

	file_error = ''
	size = int(headers['content-length'])
	mime_type = headers['content-type']

	if size > 2097152:
		file_error = 'File size too big. '

	if (mime_type != 'application/msword' and
		mime_type != 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' and
		mime_type != 'application/pdf' and
		mime_type != 'text/plain' and
		mime_type != 'application/rtf'):
		file_error += 'Wrong file format.'

	return {'title_error':title_error, 'subject_error':subject_error, 
			'teacher_error':teacher_error, 'doc_url_error':doc_url_error,
			'file_error':file_error}

############################### db functions ###############################

last_refresh = {}

def get_top_guides(school=None):
	global last_refresh
	if str(school) in last_refresh.keys():
		if time.time() > last_refresh[str(school)] + 3600:
			last_refresh[str(school)] = time.time()
			results = list(top_guides_from_db(school))
			memcache.set(str(school) + '-top_guides', results)
		else:
			results = memcache.get(str(school) + '-top_guides')
			if results is None:
				results = list(top_guides_from_db(school))
				memcache.set(str(school) + '-top_guides', results)
	else:
		last_refresh[str(school)] = time.time()
		results = list(top_guides_from_db(school))
		memcache.set(str(school) + '-top_guides', results)
	return results

def top_guides_from_db(school):
	q = Guides.all()
	if school: # i.e. if user is logged in (school cookie)
		q.filter('school =', school)
	q.order('-votes')
	results = q.run(limit=25)

	# logging
	if school:
		logging.error('DB HIT: top guides for '+school)
	else:
		logging.error('DB HIT: top guides for ALL')

	return results

def add_subject(school, subject):
	'''adds/updates a subject to Subjects'''
	q = Subjects.all()
	q.filter('school =', school)
	result = q.get()

	if result:
		# update old entry
		subjects = result.subjects_list 
		if subject not in subjects:
			subjects.append(subject)
		result.subjects_list = subjects
	else:
		# new entry
		result = Subjects(school=school, subjects_list=[subject])
	result.put()

def add_teacher(school, teacher):
	'''adds/updates a teacher to Teachers'''
	q = Teachers.all()
	q.filter('school =', school)
	result = q.get()

	if result:
		# update old entry
		logging.error('update')
		teachers = result.teachers_list 
		if teacher not in teachers:
			teachers.append(teacher)
		result.teachers_list = teachers
	else:
		# new entry
		logging.error('new')
		result = Teachers(school=school, teachers_list=[teacher])
	result.put()

def get_all_subjects(school):
	'''gets list of all subjects from Subjects model'''
	q = Subjects.all()
	q.filter('school =', school)
	result = q.get()
	if result:
		return result.subjects_list
	else:
		return []

def get_all_teachers(school):
	'''gets list of all teachers from Teachers model'''
	q = Teachers.all()
	q.filter('school =', school)
	result = q.get()
	if result:
		return result.teachers_list
	else:
		return []

def get_subjects_for_teacher(school, teacher):
	'''gets all subjects taught by one teacher'''
	q = Teacher_Subjects.all()
	q.filter('school =', school)
	q.filter('teacher =', teacher)
	result = q.get()
	if result:
		return result.subjects_list
	else:
		return []

def get_teachers_for_subject(school, subject):
	'''gets all teachers for one subject'''
	q = Subject_Teachers.all()
	q.filter('school =', school)
	q.filter('subject =', subject)
	result = q.get()
	if result:
		return result.teachers_list
	else:
		return []

def add_subject_to_teacher(school, teacher, subject):
	'''add a subject to a teacher'''
	q = Teacher_Subjects.all()
	q.filter('school =', school)
	q.filter('teacher =', teacher)
	result = q.get()
	if result:
		subjects = result.subjects_list
		if subject not in subjects:
			subjects.append(subject)
		result.subject_list = subjects
	else:
		result = Teacher_Subjects(school=school, teacher=teacher, subjects_list=[subject])
	result.put()


def add_teacher_to_subject(school, teacher, subject):
	'''add a teacher to a subject'''
	q = Subject_Teachers.all()
	q.filter('school =', school)
	q.filter('subject =', subject)
	result = q.get()
	if result: 
		teachers = result.teachers_list
		if teacher not in teachers:
			teachers.append(teacher)
		result.teachers_list = teachers
	else:
		result = Subject_Teachers(school=school, subject=subject, teachers_list=[teacher])
	result.put()