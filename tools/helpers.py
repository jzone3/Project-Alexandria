import datetime
import hmac
import hashlib
import random
import re

import secret

from google.appengine.ext import db

LOGIN_COOKIE_NAME = 'uohferrvnksj'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SCHOOL_RE= re.compile(r"^[a-zA-Z0-9 _]{1,30}$")
TITLE_RE = re.compile(r'^[\'\.: a-zA-Z0-9_-]+$')
PAGE_RE = r'(/(?:[\'\.:a-zA-Z0-9_-]+/?)*)'

GET_USER = db.GqlQuery("SELECT * FROM Users WHERE username = :username LIMIT 1")
GET_USER_GUIDES = db.GqlQuery("SELECT * FROM Guides WHERE user_created = :username ORDER BY date_created DESC")
GET_GUIDES_BY_BLOB_KEY = db.GqlQuery("SELECT * FROM Guides WHERE blob_key = :blob_key LIMIT 1")

CONTENT_TYPE_EXTS = {'application/msword':'.doc',
					'application/vnd.openxmlformats-officedocument.wordprocessingml.document':'.docx',
					'application/pdf':'.pdf',
					'text/plain':'.txt',
					'application/rtf':'.rtf',
					'image/jpg':'.jpg'}

FAKE_USERS = ["emanresu","shyguy","shaneybo","saucey","pikachun","lartple","coldshoulder","distargirl","jarson5","weakev","jonhar", "oxacuk", "ollypop", "zfinter", "korile1", "sinkra", "jojo", "bert95", "mickey", "ghost_man"]

PEOPLE = ['jared@projectalexa.com', 'kenny@projectalexa.com', 'matthew@projectalexa.com', 'eric@projectalexa.com', 'justin@projectalexa.com']
DEVS = ['jared@projectalexa.com', 'kenny@projectalexa.com', 'matthew@projectalexa.com']
last_refresh = {}
person = 0
dev = 0

def list_to_str(lst):
	'''Converts a list into a string to put into HTML'''
	to_return = '['
	for i in lst:
		if i == lst[len(lst) - 1]:
			to_return += '"' + i + '"]'
		else:
			to_return += '"' + i + '",'
	return to_return

def time_difference(time):
	'''Calculates text time difference for guide page'''
	now = datetime.datetime.now()
	if now > time + datetime.timedelta(days=365.25):
		ago = now.year - time.year
		if ago == 1:
			return str(ago) + " year ago"
		else:
			return str(ago) + " years ago"
	elif now >= time + datetime.timedelta(days=30):
		ago = now.month - time.month
		if ago == 1:
			return str(ago) + " month ago"
		else:
			return str(ago) + " months ago"
	elif now >= time + datetime.timedelta(days=1):
		ago = now.day - time.day
		if ago == 1:
			return str(ago) + " day ago"
		else:
			return str(ago) + " days ago"
	elif now >= time + datetime.timedelta(hours=1):
		ago = now.hour - time.hour
		if ago == 1:
			return str(ago) + " hour ago"
		else:
			return str(ago) + " hours ago"
	elif now >= time + datetime.timedelta(minutes=1):
		ago = now.minute - time.minute
		if ago == 1:
			return str(ago) + " minute ago"
		else:
			return str(ago) + " minutes ago"
	elif now >= time + datetime.timedelta(seconds=1):
		ago = now.second - time.second
		if ago == 1:
			return str(ago) + " second ago"
		else:
			return str(ago) + " seconds ago"
	else:
		return "less than 1 second ago"

def comment_preview(comment):
	'''Shortens comment for notification box'''
	if len(comment) > 28:
		comment = comment[:28]
	return comment + '...'

def str_votes(votes):
	'''Prepends +- to a vote integer'''
	if votes > 0:
		return '+' + str(votes)
	else:
		return str(votes)

def remember_me():
	'''Returns expiration time for remember me cookie'''
	expiration = datetime.datetime.now() + datetime.timedelta(days=50)
	return expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST")

def hash_str(string):
	'''Hashes a string for user cookie'''
	return hmac.new(secret.SECRET, str(string), hashlib.sha512).hexdigest()

def salted_hash(password, salt):
	'''Hashes a string for user password'''
	return hashlib.sha256(password + salt).hexdigest()

def make_salt():
	'''Makes random salt for user cookie'''
	return ''.join(random.choice(string.letters) for x in xrange(5))

def get_filename(title, user, content_type):
	'''Makes a filename from the guide title and uploading user'''
	title = title.lower()
	user = user.lower()
	extension = CONTENT_TYPE_EXTS[content_type]
	new_title = ''	
	for char in title:
		if char != ' ':
			new_title += char
		else:
			new_title += '_'
	return new_title + '_' + user + extension

def get_url(filename, user):
	'''Creates url: user/guidename from filename and uploading user'''
	user = user.lower()
	filename = filename[:filename.rfind('_')]
	filename = filename.replace("'",'')
	filename = filename.replace("/",'')
	filename = filename.replace("\\",'')
	filename = filename.replace(".",'')
	filename = filename.replace(":",'')
	filename = filename.replace("-",' ')
	return user + '/' + filename

def get_tags(string):
	'''Gets tags from a comma separated string'''
	splitted = string.split(',')
	tags = []
	for tag in splitted:
		tag = tag.replace(' ', '')
		if tag:
			tags.append(tag)
	return tags

def get_unique_link(username):
	'''Creates a verification link for new user'''
	reset_user_link(username)
	link_row = Email_Verification(username = username)
	link_row.put()
	return 'http://projectalexa.com/verify/' + str(link_row.key()), 'http://projectalexa.com/delete_email/' + str(link_row.key())