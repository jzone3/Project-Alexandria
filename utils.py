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

def str_votes(votes):
	if votes > 0:
		return '+' + str(votes)
	else:
		return str(votes)

def get_school(username):
	q = Users.all()
	q.filter('username =', username)
	results = q.get()
	if results:
		return results.school
	else:
		return None

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
		same_username_db = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")
		logging.error("DB QUERY - signup()")
		same_username = same_username_db.get()

		if same_username:
			to_return['username'] = "Username already exists!"
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

def get_schools():
	lst = memcache.get('all_schools')
	if not lst:
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

def change_school(school, username):
	user = get_user(username)
	if school == '':
		return [False, 'No school entered']
	if not SCHOOL_RE.match(school):
		return [False, "That is not a valid school name"]
	add_school(school)
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

def change_password(old, new, username):
	# WRITE THIS

	if email == '':
		return [False, 'No email entered']
	if not EMAIL_RE.match(email):
		return [False, "That's not a valid email."]

	user = get_user(username)
	user.email = email
	user.put()
	return [True]