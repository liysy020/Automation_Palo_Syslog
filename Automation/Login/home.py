from django.shortcuts import render

def home_page(request, *args, **kwargs):
	user_auth = request.user.is_authenticated
	return render (request, "welcome.html", {'user_auth': user_auth})
