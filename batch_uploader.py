
import hashlib
import hmac
import jinja2
import logging
import os
import re
import urllib
import urllib2
import webapp2

import externals.ayah
import gdata.gauth
import gdata.docs.service
import gdata.docs.data

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

import os.path
import secret
from search import *
from utils import *
from database import *
from random import choice

f = open(os.path.dirname(__file__) + '/AllStudyGuides.txt', 'r')

username = choice(["emanresu", "shyguy", "shaneybo","saucey","pikachun","lartple","coldshoulder","distargirl","jarson5","weakev","jonhar", "oxacuk", "ollypop", "zfinter", "korile1", "sinkra", "jojo", "bert95", "mickey", "ghost_man"])
title = f.readline()
subject = f.readline()
teacher = f.readline()
tags = f.readline()
file_url = f.readline()
bufferline = f.readline()

result = urlfetch.fetch(file_url)
headers = result.headers
if result.status_code != 200:
	print "!!! Error !!!"
	print title
	print file_url
	print "!!! End Error !!!"

tags = get_tags(tags) + create_tags(title, subject, teacher)
filename = get_filename(title, username)
school = 'Bergen County Academies'

# write file to blobstore
f = files.blobstore.create(mime_type=headers['content-type'], _blobinfo_uploaded_filename=filename)
with files.open(f, 'a') as data:
	data.write(result.content)
files.finalize(f)
blob_key = files.blobstore.get_blob_key(f)

# write file to google docs
if headers['content-type'] in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/rtf']:
	google_doc_name = school + ': ' + filename 
	client = gdata.docs.service.DocsService()
	client.ClientLogin(secret.G_USERNAME, secret.G_PASSWORD)
	ms = gdata.MediaSource(file_handle=result.content, 
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
		icon = 'backpack' ##! change to default icon later
	else:
		icon = si.icon

# add guide to db
guide = Guides(user_created=username, title=title, subject=subject,
	   		   teacher=teacher, tags=tags, blob_key=str(blob_key),
	   		   edit_url=edit_url, school=school, url=url, icon=icon,
	   		   votes=0, up_users=[], down_users=[])
guide.put()

# add subject, teacher to db
add_teacher(school, teacher)
add_subject(school, subject)
add_subject_to_teacher(school, teacher, subject)
add_teacher_to_subject(school, teacher, subject)

# add guide to index
key = str(guide.key())
add_to_index(school, key, tags)

print 'added ' + title + ' by ' + username

f.close()