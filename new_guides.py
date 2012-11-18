from google.appengine.ext import db

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