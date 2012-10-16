import operator
from django.utils import simplejson
import logging
from google.appengine.api import memcache

from google.appengine.ext import db

from database import Indexes, Guides

# likely errant key presses that are not part of a query
ERROR_CHARS = """'"\\`~!@#$%^&*()-_=+/|[]{};:<>.,?"""

ABBREVIATIONS = {'bio':'biology', 'chem':'chemistry', 'calc':'calculus', 'vocab':'vocabulary',
				'lit':'literature', 'econ':'economics', 'stat':'statistics', 'stats':'statistics',
				'tech':'technology'}

NUM_MAPPING = {'1':'one', '2':'two', '3':'three', '4':'four', '5':'five', '6':'six', '7':'seven', 
			   '8':'eight', '9':'nine', '10':'ten', '11':'eleven', '12':'twelve', '13':'thirteen',
			   '14':'fourteen', '15':'fifteen', '16':'sixteen', '17':'seventeen', '18':'eighteen',
			   '19':'nineteen', '20':'twenty', '30':'thirty', '40':'forty', '50':'fifty',
			   '60':'sixty', '70':'seventy', '80':'eighteen', '90':'ninety'}

COMMON_WORDS = {'the', 'a', 'or', 'and', 'to', 'that', 'of', 'is', 'it', 'for', 'from', 'but', 'an'}

# divide votes by this for ranking
VOTES_DIVISOR = 10.0**6

def filt_query(query):
	"""Returns a filtered query with assumptions, i.e. remove CHARS from string, lowercaseify"""
	query = query.lower()

	for char in ERROR_CHARS: 
		query = query.replace(char, '')
	
	# split into list for word analysis
	query = query.split()

	# replace words in query
	for i in range(len(query)):
		word = query[i]
		if word in ABBREVIATIONS:
			query[i] = ABBREVIATIONS[word]
		elif word in COMMON_WORDS:
			query[i] = ''
		elif word in NUM_MAPPING:
			query[i] = NUM_MAPPING[word]

	query = filter(lambda x: x, set(query))

	return ' '.join(query)

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
	index = memcache.get('index-'+school)
	if index:
		logging.error("CACHE get_index(): "+school)
	else:
		logging.error("DB get_index(): "+school)
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
	results = memcache.get('query'+query)
	if results:
		logging.error('CACHE query search(): '+query)
		return results

	index = get_index(school)
	if not index: # if no entries for that school
		return None
	query = filt_query(query)
	rankings = get_rankings(query, index)

	# remove all 0 scores
	# {key1:rank1, key2:rank2, ...}
	rankings = {key: rankings[key] for key in rankings if rankings[key] != 0}

	# list all keys, retrieve guides
	keys = rankings.keys()
	guides = Guides.get(keys)

	# adjust scores for votes, save in results list
	# [(guide1, adj_rank1), (guide2, adj_rank2), ...]
	results = []
	for i in range(len(guides)):
		guide = guides[i]
		adj_score = rankings[str(guide.key())] + (guide.votes / VOTES_DIVISOR)
		results.append((guide, adj_score))
	
	results_final = sorted(results, key=lambda x: x[1], reverse=True)

	logging.error('DB query search(): '+query)
	memcache.set('query'+query, results_final)
	logging.error('CACHE set query-'+query)

	return results_final