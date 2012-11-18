def str_votes(votes):
	if votes > 0:
		return '+' + str(votes)
	else:
		return str(votes)

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