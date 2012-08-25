import jinja2
import os
import webapp2

from database import Users, Docs, Comments

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class PageHandler(webapp2.RequestHandler):
	'''Parent class for all handlers, shortens functions'''
	def write(self, content):
		return self.response.out.write(content)

	def rget(self, name):
		return self.request.get(name)

	def render(self, template, params={}):
		template = jinja_env.get_template(template)
		self.response.out.write(template.render(params))

class MainHandler(PageHandler):
	'''Handles homepage: index.html'''
	def get(self):
		logged_in = True #True for testing, change back to false
		# check if logged in

		if logged_in:
			self.render('dashboard.html')
		else:
			self.render('index.html')

	def post(self):
		if self.rget('formname') == 'signup':
			email   = self.rget('email')
			pw      = self.rget('password')
			v_pw    = self.rget('verify')
			school  = self.rget('school')
			grade   = self.rget('grade')
			academy = self.rget('academy')
			agree   = self.rget('agree')

			self.write([email, pw, v_pw, school, grade, academy, agree])
		elif self.rget('formname') == 'login':
			pass
		else:
			self.error(404)

class GuidesHandler(PageHandler):
	'''Handles guides: guides.html'''
	def get(self):
		self.render('guides.html')

class AboutHandler(PageHandler):
	'''Handles about: about.html'''
	def get(self):
		self.render('about.html')

class ContactHandler(PageHandler):
	'''Handles contact: contact.html'''
	def get(self):
		self.render('contact.html')

app = webapp2.WSGIApplication([('/?', MainHandler),
							   ('/about', AboutHandler),
							   ('/guides', GuidesHandler),
							   ('/contact', ContactHandler)
							   ], debug=True)
