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
from google.appengine.api import mail

import secret
from database import *
from activation import make_activation_email

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SCHOOL_RE= re.compile(r"^[a-zA-Z0-9 _]{1,30}$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
LOGIN_COOKIE_NAME = 'uohferrvnksj'

GET_USER = db.GqlQuery("SELECT * FROM Users WHERE username = :username LIMIT 1")
GET_USER_GUIDES = db.GqlQuery("SELECT * FROM Guides WHERE user_created = :username ORDER BY date_created DESC")
GET_GUIDES_BY_BLOB_KEY = db.GqlQuery("SELECT * FROM Guides WHERE blob_key = :blob_key LIMIT 1")

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
	submission = db.GqlQuery("SELECT * FROM Guides WHERE blob_key = :blob_key", blob_key=blob_key).get()
	if not cached_items is None:
		new_guide = [{'title' : submission.title, 'subject' : submission.subject, 'votes' : submission.votes, 'date_created' : submission.date_created}]
		try:
			cached_items = new_guide.append(cached_items)
			memcache.set(username + '_submitted', cached_items)
		except:
			memcache.set(username + '_submitted', new_guide)

def get_submitted(username):
	from_cache = memcache.get(username + '_submitted')
	to_return = []
	if from_cache is None:
		GET_USER_GUIDES.bind(username = username)
		guides = GET_USER_GUIDES
		logging.error(username + '_submitted db read')
		for submission in guides:
			to_return.append({'title' : submission.title, 'subject' : submission.subject, 'votes' : submission.votes, 'date_created' : submission.date_created, 'blob_key' : submission.blob_key})
		memcache.set(username + '_submitted', [x['blob_key'] for x in to_return])
	else:
		for submission in from_cache:
			GET_GUIDES_BY_BLOB_KEY.bind(blob_key = submission)
			guide = GET_GUIDES_BY_BLOB_KEY.get()
			to_return.append({'title' : guide.title, 'subject' : guide.subject, 'votes' : guide.votes, 'date_created' : guide.date_created, 'blob_key' : submission})

	return to_return

def get_submitted_guide_names(username):
	to_return = memcache.get(username + '_submitted')
	if to_return is None:
		GET_USER_GUIDES.bind(username = username)
		guides = GET_USER_GUIDES
		# guides = db.GqlQuery("SELECT * FROM Guides WHERE user_created = '" + username.replace("'", "&lsquo;") + "' ORDER BY date_created DESC")
		logging.error(username + '_submitted db read')
		to_return = []
		for submission in guides:
			to_return.append({'title' : submission.title, 'subject' : submission.subject, 'votes' : submission.votes, 'date_created' : submission.date_created})
		memcache.set(username + '_submitted', to_return)
	return to_return

def send_report_mail(blob_key):
	GET_GUIDES_BY_BLOB_KEY.bind(blob_key = blob_key)
	guide = GET_GUIDES_BY_BLOB_KEY.get()
	
	mail.send_mail(sender="Project Alexandria <info@projectalexa.com>",
						to="Jared Zoneraich <jszoneraich@gmail.com>, Kenny Song <jellyksong@gmail.com>, Justin Kim <nitsuj199@gmail.com>, Eric Kim <randomperson97xd@gmail.com>, Matthew Lotocki <matthew.lotocki@gmail.com>",
						subject="'%s' Reached 10 Reports!" % guide.title,
						body= """
The guide "%s" has reached 10 reports!

Link: http://projectalexa.com/guides/%s
Votes: %s
Reports %s

School: %s
Teacher: %s
Subject: %s
User Created: %s

Sincerely,
PA9000
""" % (guide.title, guide.url, str(guide.votes), str(len(guide.report_users) + 1), guide.school, guide.teacher, guide.subject, guide.user_created),
						html= """
<!DOCTYPE HTML>
<html>
<head></head>
<body>
The guide "%s" has reached 10 reports!<br/>
<br/>
Link: <a href="http://projectalexa.com/guides/%s">http://projectalexa.com/guides/%s</a><br/>
Votes: %s<br/>
Reports %s<br/>
<br/>
School: %s<br/>
Teacher: %s<br/>
Subject: %s<br/>
User Created: %s<br/>
<br/>
Sincerely,<br/>
PA9000<br/>
</body>
</html>
""" % (guide.title, guide.url, guide.url, str(guide.votes), str(len(guide.report_users) + 1), guide.school, guide.teacher, guide.subject, guide.user_created)
						)

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
	GET_USER.bind(username = username)
	return GET_USER.get()

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
	accounts = (db.GqlQuery("SELECT * FROM Users WHERE email = :email", email = email)).get()
	if accounts is None:
		return True
	return False

def unique_username(username):
	GET_USER.bind(username = username)
	accounts = GET_USER.get()
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
		GET_USER.bind(username = username)
		accounts = GET_USER.get()
		# accounts = db.GqlQuery("SELECT * FROM Users WHERE username = '" + username.replace("'", "&lsquo;") + "'")
		# accounts = accounts.get()
		logging.error("DB QUERY - check_login()")
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
	elif not USER_RE.match(username) or username == '[deleted]' or username == 'null':
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

				account = Users(username = username, password = hashed_pass, school = school, grade = int(year), score = 0, confirmed = False, email = email)
				account.put()
				#put welcome notification
				notification = Notification(username=username, is_new=True, name="welcome")
				notification.put()

				# make initial bookmarks
				top_guides = get_top_guides(school)
				counter = 0
				if top_guides:
					for guide in top_guides:
						if counter == 3: break
						bookmark = Bookmarks(user=account.key(), guide=guide.key())
						bookmark.put()
						counter += 1

				cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(username), hash_str(username), remember_me())
				to_return['cookie'] = cookie
				to_return['success'] = True
				email_verification(username, email)

	return to_return

def signup_ext(username='', school='', year='', agree='', email=''):
	"""Signs up user from google/facebook"""

	to_return = {'success' : False}
	
	if username == '':
		to_return['username'] = "Please enter a username"
	elif not USER_RE.match(username) or username == '[deleted]' or username == 'null':
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
			# username.replace("'", "&lsquo;")
			account = Users(username = username, school = school, grade = int(year), score = 0, confirmed = False, email = email)
			account.put()

			#put welcome notification
			notification = Notification(username=username, is_new=True, name="welcome")
			notification.put()

			# make initial bookmarks
			top_guides = get_top_guides(school)
			counter = 0
			if top_guides:
				for guide in top_guides:
					if counter == 3: break
					bookmark = Bookmark(user=account.key(), guide=guide.key())
					bookmark.put()
					counter += 1

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
	user.email_verified = False
	user.put()
	email_verification(username, email)
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
	GET_USER.bind(username = username)
	user = GET_USER
	for i in user:
		i.delete()
	GET_USER_GUIDES.bind(username = username)
	guides = GET_USER_GUIDES
	for x in guides:
		x.user_created = '[deleted]'
		x.url = (x.url).replace(username, 'null')
		x.put()
	reset_user_link(username)
	delete_bookmarks(username)
	memcache.delete(username + '_submitted')

def delete_bookmarks(username):
	pass

############################### email verification ###############################

def deleted_old_links():
	links = db.GqlQuery("SELECT * FROM Email_Verification ORDER BY DESC")
	for i in links:
		if datetime.datetime.now() >= i.date_created + datetime.timedelta(hours=3):
			i.delete()
		else:
			break

def delete_link(key):
	links = db.get(key)
	for i in link:
		i.delete()

def reset_user_link(username):
	links = db.GqlQuery("SELECT * FROM Email_Verification WHERE username = :username", username = username)
	for i in links:
		i.delete()

def get_unique_link(username):
	reset_user_link(username)
	link_row = Email_Verification(username = username)
	link_row.put()
	return 'http://projectalexa.com/verify/' + str(link_row.key()), 'http://projectalexa.com/delete_email/' + str(link_row.key())

def email_verification(username, email):
	link, dellink = get_unique_link(username)
	body, html = make_activation_email(username, link, dellink)
	mail.send_mail(sender="Project Alexandria <info@projectalexa.com>",
						to="%s <%s>" % (username, email),
						subject="Email Verification",
						body=body,
						html=html
						)

def verify(key):
	link = db.get(key)
	if link is None:
		return False
	if datetime.datetime.now() >= link.date_created + datetime.timedelta(hours=3):
		link.delete()
		return False
	user = get_user(link.username)
	if user is None:
		return False
	user.email_verified = True
	user.put()
	link.delete()
	return True

def deleted(key):
	link = db.get(key)
	if link is None:
		return False
	user = get_user(link.username)
	if user is None:
		return False
	user.email = None
	user.put()
	link.delete()
	return True

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

def upload_errors(title, subject, teacher, editable, headers):
	title_error, subject_error, teacher_error, doc_url_error = '', '', '', ''
	if not title:
		title_error = 'Please provide a title.'
	if not subject:
		subject_error = 'Please provide a subject.'
	if not teacher:
		teacher_error = 'Please provide a teacher.'

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

	if not editable:		
		_editable = False
	elif (mime_type == 'application/msword' or
		mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' or
		mime_type == 'text/plain' or
		mime_type == 'application/rtf'):
		_editable = True
	else:
		_editable = False

	return _editable, {'title_error':title_error, 'subject_error':subject_error, 
			'teacher_error':teacher_error, 'file_error':file_error}

############################### db functions ###############################

last_refresh = {}

from database import *
from django.utils import simplejson

def delete_guide(guide_key):
	# delete guide
	guide = Guides.get(guide_key)
	school = guide.school
	db.delete(guide_key)

	# delete from bookmarks
	bookmarks = list(guide.bookmarks_set)
	for bookmark in bookmarks:
	    bk_key = bookmark.key()
	    db.delete(bk_key)

	# delete from index
	q = Indexes.all()
	q.filter('school =', school)
	index = q.get()
	py_index = simplejson.loads(index.index)
	del(py_index[str(guide_key)])
	index.index = simplejson.dumps(py_index)
	index.put()

def get_top_guides(school=None, page=0):
	global last_refresh
	if page >= 5: # 5 is max number of memcache'd pages
		results = list(top_guides_from_db(school, page))
	elif str(school) in last_refresh.keys():
		if time.time() > last_refresh[str(school)] + 900:
			last_refresh[str(school)] = time.time()
			results = list(top_guides_from_db(school, page))
			memcache.set(str(school) + '-top_guides-' + str(page), results)
		else:
			results = memcache.get(str(school) + '-top_guides-' + str(page))
			if results is None:
				results = list(top_guides_from_db(school, page))
				memcache.set(str(school) + '-top_guides-' + str(page), results)
	else:
		last_refresh[str(school)] = time.time()
		results = list(top_guides_from_db(school, page))
		memcache.set(str(school) + '-top_guides-' + str(page), results)
	return results

def top_guides_from_db(school, page=0):
	q = Guides.all()
	if school: # i.e. if user is logged in (school cookie)
		q.filter('school =', school)
	q.order('-votes')
	results = q.run(limit=25, offset=page*25)

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
		return sorted(result.subjects_list)
	else:
		return []

def get_all_teachers(school):
	'''gets list of all teachers from Teachers model'''
	q = Teachers.all()
	q.filter('school =', school)
	result = q.get()
	if result:
		return sorted(result.teachers_list)
	else:
		return []

def get_subjects_for_teacher(school, teacher):
	'''gets all subjects taught by one teacher'''
	q = Teacher_Subjects.all()
	q.filter('school =', school)
	q.filter('teacher =', teacher)

	result = q.get()
	if result:
		return sorted(result.subjects_list)
	else:
		return []

def get_teachers_for_subject(school, subject):
	'''gets all teachers for one subject'''
	q = Subject_Teachers.all()
	q.filter('school =', school)
	q.filter('subject =', subject)
	result = q.get()
	if result:
		return sorted(result.teachers_list)
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

def find_guides_ts(school, teacher, subject):
	'''retrieves a list of guides based on school, teacher, and subject'''
	q = Guides.all()
	q.filter('school =', school)
	q.filter('teacher =', teacher)
	q.filter('subject =', subject)
	q.order('-votes')
	results = q.run(limit=1000)
	return results

############################### voting functions ###############################

def vote(key, vote_type, username):
	if username == "":
		return False

	guide = Guides.get(key)

	# calculate vote difference
	if vote_type == 'up':
		if username in guide.up_users:
			return False
		elif username in guide.down_users:
			diff = 2
			guide.down_users.remove(username)
		else:
			diff = 1
	elif vote_type == 'down':
		if username in guide.down_users:
			return False
		elif username in guide.up_users:
			diff = -2
			guide.up_users.remove(username)
		else:
			diff = -1
	else:
		return False

	# record changes in guide
	guide.votes += diff
	if diff > 0:
		guide.up_users.append(username)
	else:
		guide.down_users.append(username)
	guide.put()

	last_refresh[str(guide.school)] = 0
	last_refresh['None'] = 0

	return diff
