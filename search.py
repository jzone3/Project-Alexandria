### this module will be integrated into utils.py ###
import operator

# datastore is also not mongodb (unfortunately), what is the data structure returned by db.getall()? 
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

def filt_query(query):
	"""Returns a filtered query with assumptions, i.e. remove CHARS from string, lowercaseify"""
	# filter out errant characters
	for char in query:
		if char in CHARS: 
			query = query.replace(char, '')

	# word mapping
	query = query.lower()
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

def get_rankings(query, db_entries):
	"""Ranks guides given a query and all db entries.
	   Returns sorted list of tuples.
	"""
	query = filt_query(query)
	rankings = dict()
	for guide in db_entries:
		tags = guide['tags']
		rank = 0
		for tag in tags:
			if tag in query:
				rank += 1
		rankings[guide['title']] = rank

	# sort rankings, convert to list of tuples
	rankings = sorted(rankings.iteritems(), key=operator.itemgetter(1), reverse=True)
	return rankings