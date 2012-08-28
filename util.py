import re
import hmac
import hashlib
import logging
import string
import secret
import random
from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SCHOOL_RE= re.compile(r"^[a-zA-Z0-9 _]{1,30}$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

class Users(db.Model):
	username     = db.StringProperty(required = True)
	email        = db.StringProperty(required = True)
	school       = db.StringProperty(required = True)
	grade        = db.IntegerProperty(required = True)
	score        = db.IntegerProperty(required = True) 
	confirmed    = db.BooleanProperty(required = True) 
	password     = db.StringProperty(required = True)
	date_created = db.DateTimeProperty(auto_now_add = True)

def hash_str(string):
	return hmac.new(secret.SECRET, str(string), hashlib.sha512).hexdigest()

def salted_hash(password, salt):
	return hashlib.sha256(password + salt).hexdigest()

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

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

		acc = accounts[0]
		if not acc.password:
			return [False, 'Username does not exist']
		(db_password, salt) = (acc.password).split("|")

		if salted_hash(original_password, salt) == db_password:
			return [True, 'username=%s|%s; Path=/' % (str(username), str(self.hash_str(username)))]
	return [False, 'Invalid username and password!']

def signup(username, password, verify, email, school, year, agree):
	"""Signs up user

	Returns:
		Dictionary of elements with error messages and 'success' : False
		OR
		{'cookie' : cookie, 'success' : True}
	"""

	to_return = {'success' : False}
	
	if username == '':
		to_return['username'] = "Please enter a username"
		logging.error("username")
	elif not USER_RE.match(username):
		to_return['username'] = "That's not a valid username."
		logging.error("username")

	
	if password == '':
		to_return['password'] = "Please enter a password"
		logging.error("password")
	elif not PASS_RE.match(password):
		to_return['password'] = "That's not a valid password."
		logging.error("password")
	elif verify == '':
		to_return['verify'] = "Please verify your password"
		logging.error("password")
	elif verify != password:
		to_return['verify'] = "Your passwords didn't match."
		logging.error("password")
	
	if email == '':
		to_return['email'] = "Please enter a email"
		logging.error("email")
	elif not EMAIL_RE.match(email):
		to_return['email'] = "That's not a valid email."
		logging.error("email")
	
	if school == '':
		to_return['school'] = "Please enter a school"
		logging.error("school")
	if not SCHOOL_RE.match(school):
		to_return['school'] = "That is not a valid school name"
		logging.error("school")
	
	if year == '':
		to_return['year'] = "Please enter a year"
		logging.error("year - none")
	if not int(year) in [9,10,11,12]:
		to_return['year'] = "That is not a valid grade level"
		logging.error("year - invalid" + year)
	
	if agree != 'on':
		agree_error = "You must agree to the Terms of Service to create an account"
		logging.error("agree")
	# self.write(username + ' ' + password + ' ' + verify + ' ' + email + ' ' + school + ' ' + year )

	if len(to_return) == 1 and username != '' and password != '' and school != '' and year != '' and agree == 'on':
		same_username_db = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")
		logging.error("DB QUERY - signup()")
		same_username = same_username_db.get()

		if same_username:
			to_return['username'] = "Username already exists!"
		else:
			salt = make_salt()
			hashed = salted_hash(password, salt)
			hashed_pass = hashed + '|' + salt
			account = Users(username = username.replace("'", "&lsquo;"), email = email, password = hashed_pass, school = school, grade = int(year), score = 0, confirmed = False)
			account.put()
			cookie = 'uohferrvnksj=%s|%s; Path=/' % (str(username), hash_str(username))
			to_return['cookie'] = cookie
			to_return['success'] = True
			#add School database functionality... put entered school into db and or add user to school list
	return to_return