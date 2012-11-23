import re
import hmac
import hashlib
import logging
import string
import random
import datetime
import time

from database import *
from django.utils import simplejson
from google.appengine.ext import db

import secret
from database import *

from google.appengine.api import memcache

def delete_orphan_subteach(school='Bergen County Academies'):
	'''Cleans up the Subject and Teacher tab
	Use sparingly, this takes a lot of db reads and writes.
	'''
	act_teachers = ActiveTeachers.all().filter('school =', school).get()
	act_subjects = ActiveSubjects.all().filter('school =', school).get()
	act_teachers_list = act_teachers.active_teachers_list
	act_subjects_list = act_subjects.active_subjects_list

	del_teachers = []
	for teacher in act_teachers_list:
		# test if teacher has subjects		
		q = Teacher_Subjects.all()
		q.filter('school =', school)
		q.filter('teacher =', teacher)
		ts = q.get()
		if not ts:
			del_teachers.append(teacher)
			continue
		elif not ts.subjects_list:
			del_teachers.append(teacher)
			continue
		else:
			# if has subjects, clean up subjects if needed
			del_teacher_subjects = []
			for subject in ts.subjects_list:
				q = Guides.all()
				q.filter('school =', school)
				q.filter('teacher =', teacher)
				q.filter('subject =', subject)
				g = q.get()
				if not g:
					del_teacher_subjects.append(subject)
			
			# remove empty subjects		
			subs = filter(lambda x: x not in del_teacher_subjects, ts.subjects_list)
			ts.subjects_list = subs
			ts.put()
			logging.info('removed '+repr(del_teacher_subjects)+' from '+teacher)

	# remove empty teachers
	teachers = filter(lambda x: x not in del_teachers, act_teachers_list)
	act_teachers.active_teachers_list = teachers
	act_teachers.put()
	logging.info('removed '+repr(del_teachers)+' from ActiveTeachers')

	del_subjects = []
	for subject in act_subjects_list:
		# test if subject has teachers
		q = Subject_Teachers.all()
		q.filter('school =', school)
		q.filter('subject =', subject)
		st = q.get()
		if not st:
			del_subjects.append(subject)
			continue
		elif not st.teachers_list:
			del_subjects.append(subject)
			continue
		else:
			# if has teachers, clean up each teachers if needed
			del_subject_teachers = []
			for teacher in st.teachers_list:
				q = Guides.all()
				q.filter('school =', school)
				q.filter('subject =', subject)
				q.filter('teacher =', teacher)
				g = q.get()
				if not g:
					del_subject_teachers.append(teacher)

			# remove empty teachers
			teachers = filter(lambda x: x not in del_subject_teachers, st.teachers_list)
			st.teachers_list = teachers
			st.put()
			logging.info('removed '+repr(del_subject_teachers)+' from '+subject)

	# remove empty subjects
	subjects = filter(lambda x: x not in del_subjects, act_subjects_list)
	act_subjects.active_subjects_list = subjects
	act_subjects.put()
	logging.info('removed '+repr(del_subjects)+' from ActiveSubjects')

def delete_all_test_guides(school='Bergen County Academies'):
	'''Deletes all test guides on gae server (tag:deletethis)'''
	# delete guide, index entries, etc.
	q = Guides.all()
	q.filter('tags =', 'deletethis')
	for g in q.run():
		delete_guide(str(g.key()))

	# delete from active subjects
	q = ActiveSubjects.all()
	q.filter('school =', school)
	result = q.get()
	l = result.active_subjects_list
	result.active_subjects_list = [x for x in l if x not in ["Subject", "subject"]]
	result.put()

	# delete from active teachers
	q = ActiveTeachers.all()
	q.filter('school =', school)
	result = q.get()
	l = result.active_teachers_list
	result.active_teachers_list = [x for x in l if x not in ["Teacher", "teacher"]]
	result.put()

	# delete from Subjects
	q = Subjects.all()
	q.filter('school =', school)
	result = q.get()
	l = result.subjects_list
	result.subjects_list = [x for x in l if x not in ["Subject", "subject"]]
	result.put()

	# delete from Teachers
	q = Teachers.all()
	q.filter('school =', school)
	result = q.get()
	l = result.teachers_list
	result.teachers_list = [x for x in l if x not in ["Teacher", "teacher"]]
	result.put()

	# delete from Subject_Teachers
	q = Subject_Teachers.all()
	q.filter('subject =', 'Subject')
	result = q.get()
	if result:
		result.delete()
	q = Subject_Teachers.all()
	q.filter('subject =', 'subject')
	result = q.get()
	if result:
		result.delete()

	# delete from Teacher_Subjects
	q = Teacher_Subjects.all()
	q.filter('teacher =', 'Teacher')
	result = q.get()
	if result:
		result.delete()

	q = Teacher_Subjects.all()
	q.filter('teacher =', 'teacher')
	result = q.get()
	if result:
		result.delete()