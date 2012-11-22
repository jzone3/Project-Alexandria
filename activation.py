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