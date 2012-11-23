from google.appengine.ext import db

WELCOME_NOTIF = """<div><span style='font-family:Junge;'>Hey %s!<br><br> We hope you love using Project Alexandria as much as we loved building it. This is a community-based site so make sure to upload or help edit study guides! Feel free to <a href='\contact'>contact us</a> if you have any questions.<br><br>-The PA Team</span>"""

def str_votes(votes):
	if votes > 0:
		return '+' + str(votes)
	else:
		return str(votes)

def make_new_guides(guides, page=0, username=''):
	table = ""
	x = 25 * int(page)

	for i in guides:
		x += 1
		if i.user_created == '[deleted]':
			user = '[deleted]'
		else:
			user = '<a href="/user/{0}">{0}</a>'.format(i.user_created)

		table += """<tr>
						<td>
							<div class="btn-group btn-group btn-group-vertical new-answer" data-toggle="buttons-radio" id="{0[key]}">
								<button class="btn btn-mini vote up {0[up]}"><i class="icon-caret-up"></i></button>
								<span rel="tooltip" id="new-tip_{0[key]}" class="tooltips" title="You already voted for this guide. <a href='#' class='tiplink' onclick=&quot;$('#new-tip_{0[key]}').tooltip('hide')&quot;>&times;</a>" data-placement="right" style="float:right;"></span>
								<button class="btn btn-mini vote down {0[down]}"><i class="icon-caret-down"></i></button>											
							</div>
						</td>
						<td>{0[x]}</td>
						<td><a href="/guides/{0[url]}">{0[title]}</a></td>
						<td>{0[subject]}</td>
						<td>{0[user_created]}</td>
						<td>{0[teacher]}</td>
						<td id="new-votes_{0[key]}">{0[votes]}</td>
					</tr>
				""".format({'key':str(i.key()), 'url':i.url, 'title':i.title, 'subject':i.subject, 'user_created':user, 'teacher':i.teacher, 'votes':str_votes(i.votes), 'x':str(x),
							'up':'active' if (username in i.up_users) else '', 'down':'active' if (username in i.down_users) else ''})
	
	pg = ''
	if page > 0:
		pg += """<li class="previous">
							<a href='guides?new_page=%s'>&larr; Previous</a>
						</li>""" % str(page - 1)
	if len(guides) == 25 and page < 2:
		pg += """<li class="next">
							<a href='guides?new_page=%s'>Next &rarr;</a>
						</li>""" % str(page + 1)

	html = """
			<table class="table-hover">
				<thead>
					<tr>
						<th>&nbsp;</th>
						<th>#</th>
						<th>Title</th>
						<th>Subject</th>
						<th>Uploader</th>
						<th>Teacher</th>					
						<th>Votes</th>
					</tr>
				</thead>
				<tbody>%s</tbody>
			</table>
			<ul class="pager">%s</ul>
	""" % (table, pg)

	script = """<script>	
		$('div.new-answer button.vote').click(function() {
		    var id = $(this).parents('div.new-answer').attr('id');
		    var vote_type = $(this).hasClass('up') ? 'up' : 'down';
		    var previous_votes = $("td.score_" + id).attr('id');
		    $.ajax({
			    type:'POST', 
			    url:'/vote', 
			    data:'id=' + id + '&type=' + vote_type + '&username=' + "%s",
			    success: function(response) {
					if (response == 'voted') {
						// if already voted
						$("#new-tip_" + id).tooltip('show');
					} else if (response == 'signin') {
						$('#login').modal('show');
					} else {
						prev = parseInt($('#new-votes_' + id).text())
						after = prev + parseInt(response)
						$('#new-votes_' + id).html(str_votes(after))
						$('#votes_' + id).html(str_votes(after))
						if (vote_type == 'up'){
							$('#new-votes_' + id).css({'color':'#14BB14'})
							$('#votes_' + id).css({'color':'#14BB14'})
						} else {
							$('#new-votes_' + id).css({'color':'red'})
							$('#votes_' + id).css({'color':'red'})
						}
					}		        
			    }
			});
		});
		</script>
	"""%username
	return html+script

def make_activation_email(username, link, ignore_link):
	html = """
	<!DOCTYPE HTML>
	<html>
	<head>
	<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
	</head>
	<body>
		Hi %s,<br/><br/>
		Thank you for visiting and joining <a href="http://projectalexa.com">Project Alexandria</a>! Together we can bring education into the 21st century and help students study more efficiently!<br/><br/><br/>
		To verify your email please click this link (or copy and paste it into your browser): <a href="%s">%s</a><br/><br/>
		If you did not make an account on Project Alexandria click this link: <a href="%s">%s</a>
		<br/><br/><br/>
		NOTE: Links will expire in 12 hours
	</body>
	</html>
	""" % (username, link, link, ignore_link, ignore_link)
	
	body = """Hi %s,
	Thank you for visiting and joining Project Alexandria (http://projectalexa.com)! Together we can bring education into the 21st century and help students study more efficiently!
	To verify your email please click this link (or copy and paste it into your browser): %s
	If you did not make an account on Project Alexandria click this link: %s
	NOTE: Links will expire in 12 hours"""% (username, link, ignore_link)

	return body, html

def make_submitted(guides, username):
	if len(guides) == 0:
		return """<center>
							<h2>You haven't submitted anything yet!</h2>
							<h3><a href="/upload">Upload</a> a study guide!</h3>
						</center>"""
	to_return = """
							<br/><br/>
							<table class="table table-hover">
							<thead>
								<th style="width: 670px;">Title</th>
								<th>Subject</th>
								<th>Teacher</th>
								<th>Date Uploaded</th>
							</thead>
							<tbody>"""
	for i in guides:
		to_return += """
								<tr>
										<td><a href="/guides/%s">%s</a></td>
										<td>%s</td>
										<td>%s</td>
										<td>%s</td>
									</tr>""" % (i['url'], i['title'], i['subject'], i['teacher'], i['date_created'].strftime("%B %d, %Y"))
	to_return += """
							</tbody>
						</table>"""
	return to_return

def make_report_email(guide):
	body = 	"""
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
	""" % (guide.title, guide.url, str(guide.votes), str(len(guide.report_users) + 1), guide.school, guide.teacher, guide.subject, guide.user_created)

	html = """
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

	return body, html

def get_notification_html(notification_list):
	html = ''
	for notif in notification_list:
		if notif.name == 'welcome':
			html += notif.notification
			html += """<a href='#' id='%s' onclick='deletenotif("%s")' style='float:right;font-size:10px;position:relative;top:1px;'>Delete</a></div>"""%(str(notif.key()),str(notif.key()))
		elif notif.name == 'comment':
			html += "<div>%s"%notif.notification
			html += """<a href='#' id='%s' onclick='deletenotif("%s")' style='float:right;font-size:10px;position:relative;top:1px;'>Delete</a></div><hr>"""%(str(notif.key()),str(notif.key()))

	return html