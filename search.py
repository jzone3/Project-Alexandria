import operator
from django.utils import simplejson

from google.appengine.ext import db

from database import Indexes

db_entries = [{'tags':['freshman', 'biology', 'chapter', 'one', 'notes', 'zhang'], 'title':'bio'},
			{'tags':['sophomore', 'french', 'vocabulary', 'vocab', 'guide', 'ballas'], 'title':'french'},
			{'tags':['med', 'physics', 'circular', 'motion', 'notes', 'russo'], 'title':'physics'},
			{'tags':['freshman', 'literature', 'thesis', 'statement', 'notes', 'kaplan'], 'title':'lit'},
			{'tags':['sophomore', 'drivers', 'education', 'chapter', 'six', 'notes', 'fuentes'], 'title':'drivers ed'},
			{'tags':['junior', 'first aid', 'chapter', 'two', 'notes', 'symons'], 'title':'first aid'},
			{'tags':['sophomore', 'history', 'buddhism', 'notes', 'alschen'], 'title':'buddhism'},
			{'tags':['sophomore', 'history', 'reformation', 'study', 'guide', 'kramer'], 'title':'reformation'},
			{'tags':['sophomore', 'spanish', 'vocabulary', 'guide', 'mendelsohn'], 'title':'spanish'},
			{'tags':['med', 'chemistry', 'thermodynamics', 'guide', 'rick'], 'title':'thermodynamics'}]

# likely errant key presses that are not part of a query
CHARS = """'"\\`~!@#$%^&*()-_=+/|[]{};:<>.,?"""

# spaces are important!
WORD_MAPPING = {'bio ':'biology ', 'chem ':'chemistry ', 'calc ':'calculus ', 'vocab ':'vocabulary ',
				'lit ':'literature '} # etcetc, add more if you can think of any
NUM_MAPPING = {'1':'one', '2':'two', '3':'three', '4':'four'} # etcetc...we need a better way to do this

# divide votes by this for ranking (will implement later)
# VOTES_DIVISOR = 1000000

def filt_query(query):
	"""Returns a filtered query with assumptions, i.e. remove CHARS from string, lowercaseify"""
	query = query.lower()
	for char in CHARS: 
		query = query.replace(char, '')
		
	for word in WORD_MAPPING:
		if word in query:
			query = query.replace('bio ', 'biology ')

	# number mapping
	### to be implemented ###

	return query 

def create_tags(title, subject, teacher):
	"""Returns a list of tags given the inputs."""
	title_tags = filt_query(title).split()
	subject_tags = filt_query(subject).split()
	teacher_tags = filt_query(teacher).split()
	return title_tags + subject_tags + teacher_tags

def add_to_index(school, key, tags):
	'''Adds a guide to the index for its school'''
	q = Indexes.all()
	q = q.filter('school =', school).get()
	if q: # if the school exists in db
		index = simplejson.loads(str(q.index))
		index.update({key: tags})
		q.index = simplejson.dumps(index)
		q.put()
	else:
		index = simplejson.dumps({key:tags})
		new_index = Indexes(school=school, index=index)
		new_index.put()

def get_index(school):
	q = Indexes.all()
	q = q.filter('school =', school).get()
	if q:
		return simplejson.loads(q.index)
	else:
		return None

def get_rankings(query, index):
	"""Ranks guides given a query and all db entries.
	   Returns dictionary of {guide_key:score}
	"""
	query = filt_query(query)
	rankings = dict()
	for key in index:
		tags = index[key]
		rank = 0
		for tag in tags:
			if tag in query:
				rank += 1
		rankings[key] = rank

	return rankings

# highest level function!
def search(school, query):
	'''Returns search results'''
	index = get_index(school)
	query = filt_query(query)
	rankings = get_rankings(query, index)

	# sort rankings, convert to list of tuples
	rankings = sorted(rankings.iteritems(), key=operator.itemgetter(1), reverse=True)

	# remove all 0 scores
	rankings = filter(lambda x: x[1] != 0, rankings)

	return rankings